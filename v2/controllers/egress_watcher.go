package controllers

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	coilv2 "github.com/cybozu-go/coil/v2/api/v2"
	"github.com/cybozu-go/coil/v2/pkg/constants"
	"github.com/cybozu-go/coil/v2/pkg/fou"
	"github.com/cybozu-go/coil/v2/pkg/nat/netfilter"
	"github.com/cybozu-go/coil/v2/pkg/nodenet"
)

type EgressWatcher struct {
	client.Client
	NodeName        string
	PodNet          nodenet.PodNetwork
	EgressPort      int
	Backend         string
	OriginatingOnly bool
	ClusterNetworks *netfilter.ClusterNetworks

	ClusterNetworksValidationFunc func(context.Context) error
}

// +kubebuilder:rbac:groups=coil.cybozu.com,resources=egresses,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

// Reconcile implements Reconciler interface.
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *EgressWatcher) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	eg := &coilv2.Egress{}
	if err := r.Get(ctx, req.NamespacedName, eg); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "failed to get egress")
		return ctrl.Result{}, err
	}

	pods := &corev1.PodList{}
	err := r.List(ctx, pods, client.MatchingFields{
		constants.PodNodeNameKey: r.NodeName,
	})
	if err != nil {
		logger.Error(err, "failed to list Pod")
		return ctrl.Result{}, err
	}

	targetPods := make(map[string]*corev1.Pod)
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Spec.HostNetwork {
			// Pods in host network cannot use egress NAT.
			// So skip it.
			continue
		}
		podIp := pod.Status.PodIP
		// The reconciliation should be triggered only for running pods.
		if pod.Status.Phase == corev1.PodRunning {
			if _, found := targetPods[podIp]; found {
				// multiple running pods have the same address.
				return ctrl.Result{}, fmt.Errorf("multiple pods have the same address: %s", podIp)
			}
			targetPods[podIp] = pod
		}
	}

	for _, targetPod := range targetPods {
		if eg.DeletionTimestamp != nil {
			continue
		}
		for k, v := range targetPod.Annotations {
			if !strings.HasPrefix(k, constants.AnnEgressPrefix) {
				continue
			}

			if k[len(constants.AnnEgressPrefix):] != eg.Namespace {
				continue
			}

			// shortcut for the most typical case
			if v == eg.Name {
				// Do reconcile
				if err := r.reconcileEgressClient(ctx, eg, targetPod, &logger); err != nil {
					if errors.Is(err, nodenet.ErrPodNetConfNotReady) {
						// Transient race with concurrent Pod setup/teardown.
						// Requeue with a small backoff instead of surfacing
						// as a hard error.
						logger.Info("transient netns lookup race; requeueing", "pod", fmt.Sprintf("%s/%s", targetPod.Namespace, targetPod.Name), "error", err.Error())
						return ctrl.Result{}, err
					}
					logger.Error(err, "failed to reconcile Egress client pod")
					return ctrl.Result{}, err
				}
				continue
			}

			for n := range strings.SplitSeq(v, ",") {
				if n == eg.Name {
					if err := r.reconcileEgressClient(ctx, eg, targetPod, &logger); err != nil {
						if errors.Is(err, nodenet.ErrPodNetConfNotReady) {
							logger.Info("transient netns lookup race; requeueing", "pod", fmt.Sprintf("%s/%s", targetPod.Namespace, targetPod.Name), "error", err.Error())
							return ctrl.Result{}, err
						}
						logger.Error(err, "failed to reconcile Egress client pod")
						return ctrl.Result{}, err
					}
					continue
				}
			}
		}
	}
	return ctrl.Result{}, nil
}

func (r *EgressWatcher) reconcileEgressClient(ctx context.Context, eg *coilv2.Egress, pod *corev1.Pod, logger *logr.Logger) error {
	logger.Info("Reconciling", "pod", fmt.Sprintf("%s/%s", pod.Namespace, pod.Name))

	gws, err := r.getGwnets(ctx, eg)
	if err != nil {
		return fmt.Errorf("failed to setup NAT hook: %w", err)
	}

	var ipv4, ipv6 net.IP
	for _, podIP := range pod.Status.PodIPs {
		ip := net.ParseIP(podIP.IP)
		if ip.To4() != nil {
			ipv4 = ip.To4()
			continue
		}
		if ip.To16() != nil {
			ipv6 = ip.To16()
		}
	}

	var active, toDelete []gwNets

	for _, gw := range gws {
		if len(gw.networks) > 0 {
			active = append(active, gw)
		} else {
			toDelete = append(toDelete, gw)
		}
	}

	deletionHooks := r.getHooks(toDelete, logger)

	for _, hook := range deletionHooks {
		if err := r.PodNet.Update(
			ipv4, ipv6, hook, pod,
		); err != nil {
			logger.Error(err, "deletion hook failed", "pod", fmt.Sprintf("%s/%s", pod.Namespace, pod.Name))
			return err
		}
	}

	if len(active) == 0 {
		return nil
	}

	// Outside PodNet.Update: no pod network lock or namespace entered.
	if r.ClusterNetworksValidationFunc != nil {
		if err := r.ClusterNetworksValidationFunc(ctx); err != nil {
			return fmt.Errorf("cluster networks validation failed: %w", err)
		}
	}

	activeHooks := r.getHooks(active, logger)

	for _, hook := range activeHooks {
		if err := r.PodNet.Update(
			ipv4, ipv6, hook, pod,
		); err != nil {
			return err
		}
	}

	return nil
}

type gwNets struct {
	gateway         net.IP
	networks        []*net.IPNet
	sportAuto       bool
	originatingOnly bool
}

// gatewayNetworks returns one gwNets per ClusterIP of svc. Each gwNets only
// contains the Egress destinations whose IP family matches the ClusterIP.
func (r *EgressWatcher) gatewayNetworks(eg *coilv2.Egress, svc *corev1.Service) ([]gwNets, error) {
	var gws []gwNets
	for _, clusterIP := range svc.Spec.ClusterIPs {
		var subnets []*net.IPNet
		svcIP := net.ParseIP(clusterIP)
		if svcIP == nil {
			return nil, fmt.Errorf("invalid ClusterIP in Service %s %s", eg.Name, svc.Spec.ClusterIP)
		}

		for _, sn := range eg.Spec.Destinations {
			_, subnet, err := net.ParseCIDR(sn)
			if err != nil {
				return nil, fmt.Errorf("invalid network in Egress %s", eg.Name)
			}
			if (svcIP.To4() != nil) == (subnet.IP.To4() != nil) {
				subnets = append(subnets, subnet)
			}
		}

		gws = append(gws, gwNets{gateway: svcIP, networks: subnets, sportAuto: eg.Spec.FouSourcePortAuto, originatingOnly: r.OriginatingOnly})
	}
	return gws, nil
}

func (r *EgressWatcher) getHooks(gws []gwNets, logger *logr.Logger) []nodenet.SetupHook {
	hooks := []nodenet.SetupHook{}
	for _, gw := range gws {
		hooks = append(hooks, r.hook(gw, logger))
	}

	return hooks
}

func (r *EgressWatcher) getGwnets(ctx context.Context, eg *coilv2.Egress) ([]gwNets, error) {
	svc := &corev1.Service{}

	if err := r.Get(ctx, client.ObjectKey{Namespace: eg.Namespace, Name: eg.Name}, svc); err != nil {
		return nil, err
	}

	gws, err := r.gatewayNetworks(eg, svc)
	if err != nil {
		return nil, err
	}

	return gws, nil
}

func (r *EgressWatcher) hook(gwn gwNets, log *logr.Logger) func(ipv4, ipv6 net.IP) error {
	return func(ipv4, ipv6 net.IP) error {
		// We assume that coild already has configured NAT for the client,
		// so we ensure that both FoUTunnel and NATClient have been initialized.
		ft := fou.NewClientFoUTunnel(r.EgressPort, ipv4, ipv6, func(message string) {
			log.Info(message)
		})

		if len(gwn.networks) == 0 {
			return ft.DelPeer(gwn.gateway)
		}

		if !ft.IsInitialized() {
			return errors.New("fouTunnel hasn't been initialized")
		}

		cl := netfilter.NewNatClient(ipv4, ipv6, r.ClusterNetworks, r.Backend, func(message string) {
			log.Info(message)
		})
		initialized, err := cl.IsInitialized()
		if !initialized {
			return fmt.Errorf("natClient hasn't been initialized: %w", err)
		}

		if err := cl.EnsureFlowBasedDevRules(); err != nil {
			return err
		}

		if err := cl.SyncInClusterRules(); err != nil {
			return fmt.Errorf("natClient was unable to sync in-cluster rules: %w", err)
		}

		inClusterInitialized, err := cl.IsInClusterInitialized()
		if !inClusterInitialized {
			return fmt.Errorf("natClient's in-cluster rules haven't been initialized: %w", err)
		}

		link, err := ft.AddPeer(gwn.gateway, gwn.sportAuto)
		if errors.Is(err, fou.ErrIPFamilyMismatch) {
			// ignore unsupported IP family link
			log.Info("ignored unsupported gateway", "gw", gwn.gateway)
			return nil
		}
		if err != nil {
			return err
		}
		if err := cl.SyncNat(link, gwn.networks, gwn.originatingOnly); err != nil {
			return err
		}

		return nil
	}
}

// SetupWithManager registers this with the manager.
func (r *EgressWatcher) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&coilv2.Egress{}).
		Complete(r)
}
