package controllers

import (
	"context"
	"errors"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	coilv2 "github.com/cybozu-go/coil/v2/api/v2"
	"github.com/cybozu-go/coil/v2/pkg/constants"
	"github.com/cybozu-go/coil/v2/pkg/indexing"
	"github.com/cybozu-go/coil/v2/pkg/nat/netfilter"
	"github.com/cybozu-go/coil/v2/pkg/nodenet"
)

type readerServiceCIDRSource struct{ reader client.Reader }

func (s readerServiceCIDRSource) Discover(ctx context.Context) ([]string, error) {
	var list networkingv1.ServiceCIDRList
	if err := s.reader.List(ctx, &list); err != nil {
		return nil, err
	}
	var cidrs []string
	for _, item := range list.Items {
		cidrs = append(cidrs, item.Spec.CIDRs...)
	}
	if len(cidrs) == 0 {
		return nil, errors.New("no ServiceCIDR objects found")
	}
	return cidrs, nil
}

var _ = Describe("Egress watcher", func() {
	ctx := context.Background()
	podNetwork := &mockPodNetwork{ips: make(map[string]int)}
	var cancel context.CancelFunc

	BeforeEach(func() {
		eg := makeEgress("egress1")
		err := k8sClient.Create(ctx, eg)
		Expect(err).ShouldNot(HaveOccurred())

		svc := &corev1.Service{}
		svc.Namespace = "default"
		svc.Name = "egress1"
		svc.Spec.Type = corev1.ServiceTypeClusterIP
		svc.Spec.Ports = []corev1.ServicePort{{
			Port:       5555,
			TargetPort: intstr.FromInt(5555),
			Protocol:   corev1.ProtocolUDP,
		}}
		err = k8sClient.Create(ctx, svc)
		Expect(err).ShouldNot(HaveOccurred())

		makePod("pod1", []string{"10.1.1.2", "fd01::2"}, map[string]string{
			"default": "egress1",
		}, corev1.PodRunning)
		makePod("pod2", []string{"10.1.1.3", "fd01::3"}, map[string]string{
			"default": "egress2",
		}, corev1.PodRunning)
		makePod("pod3", []string{"10.1.1.4", "fd01::4"}, map[string]string{
			"internet": "egress1",
		}, corev1.PodRunning)
		makePod("pod4", []string{"10.1.1.5", "fd01::5"}, map[string]string{
			"default": "egress1",
		}, corev1.PodSucceeded)

		// envtest uses 10.0.0.0/24 for Service allocation. Seed discovery
		// explicitly so these tests exercise validation with the default networks.
		serviceCIDR := &networkingv1.ServiceCIDR{
			Name: "coil-egress-test",
			Spec: networkingv1.ServiceCIDRSpec{CIDRs: []string{"10.0.0.0/24"}},
		}
		Expect(k8sClient.Create(context.Background(), serviceCIDR)).To(Succeed())

		ctx, cancel = context.WithCancel(context.TODO())
		mgr, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme:         scheme,
			LeaderElection: false,
			Metrics: metricsserver.Options{
				BindAddress: "0",
			},
		})
		Expect(err).ToNot(HaveOccurred())

		Expect(indexing.SetupIndexForPodByNodeName(ctx, mgr)).ToNot(HaveOccurred())

		watcher := EgressWatcher{
			Client:            mgr.GetClient(),
			NodeName:          "coil-worker",
			PodNet:            podNetwork,
			EgressPort:        5555,
			ServiceCIDRSource: readerServiceCIDRSource{mgr.GetAPIReader()},
		}
		err = watcher.SetupWithManager(mgr)
		Expect(err).ToNot(HaveOccurred())

		go func() {
			err := mgr.Start(ctx)
			if err != nil {
				panic(err)
			}
		}()
	})

	AfterEach(func() {
		cancel()
		Expect(k8sClient.Delete(context.Background(), &networkingv1.ServiceCIDR{
			Name: "coil-egress-test",
		})).To(Succeed())
		err := k8sClient.DeleteAllOf(context.Background(), &corev1.Pod{}, client.InNamespace("default"))
		Expect(err).ShouldNot(HaveOccurred())
		err = k8sClient.DeleteAllOf(context.Background(), &coilv2.Egress{}, client.InNamespace("default"))
		Expect(err).ShouldNot(HaveOccurred())
		time.Sleep(10 * time.Millisecond)
	})

	It("should update a NAT setup for pod1", func() {
		eg := &coilv2.Egress{}
		err := k8sClient.Get(ctx, client.ObjectKey{Namespace: "default", Name: "egress1"}, eg)
		Expect(err).ToNot(HaveOccurred())

		eg.Spec.FouSourcePortAuto = true
		err = k8sClient.Update(ctx, eg)
		Expect(err).ToNot(HaveOccurred())

		// pod1 is a client of default/egress1, but pod2 and pod3 are the clients of other egresses
		// pod4 is not the target of the reconciliation because pod4 is not running.
		Eventually(func() error {
			updated := podNetwork.getPodIPCount()
			updatedIPv4, ok := updated["10.1.1.2"]
			if !ok || updatedIPv4 != 1 {
				return errors.New("pod1's IPv4 address is not updated")
			}
			updatedIPv6, ok := updated["fd01::2"]
			if !ok || updatedIPv6 != 1 {
				return errors.New("pod1's IPv4 address is not updated")
			}
			return nil
		}).Should(Succeed())

		Consistently(func() error {
			updated := podNetwork.getPodIPCount()
			updatedIPv4, ok := updated["10.1.1.2"]
			if !ok || updatedIPv4 != 1 {
				return errors.New("pod1's IPv4 address is not updated")
			}
			updatedIPv6, ok := updated["fd01::2"]
			if !ok || updatedIPv6 != 1 {
				return errors.New("pod1's IPv4 address is not updated")
			}
			return nil
		}, 5*time.Second, 1*time.Second).Should(Succeed())

		makePod("pod5", []string{"10.1.1.3", "fd01::3"}, map[string]string{
			"default": "egress2",
		}, corev1.PodRunning)

		eg2 := makeEgress("egress2")
		err = k8sClient.Create(ctx, eg2)
		Expect(err).ShouldNot(HaveOccurred())

		svc2 := &corev1.Service{}
		svc2.Namespace = "default"
		svc2.Name = "egress2"
		svc2.Spec.Type = corev1.ServiceTypeClusterIP
		svc2.Spec.Ports = []corev1.ServicePort{{
			Port:       5555,
			TargetPort: intstr.FromInt(5555),
			Protocol:   corev1.ProtocolUDP,
		}}
		err = k8sClient.Create(ctx, svc2)
		Expect(err).ShouldNot(HaveOccurred())

		// Reconciliation should fail because of duplicate address
		Consistently(func() error {
			updated := podNetwork.getPodIPCount()
			_, ok := updated["10.1.1.3"]
			if ok {
				return errors.New("pod2 and pod5 should not be updated")
			}
			_, ok = updated["fd01::3"]
			if ok {
				return errors.New("pod2 and pod5 should not be updated")
			}
			return nil
		}, 5*time.Second, 1*time.Second).Should(Succeed())
	})
})

type mockPodNetwork struct {
	nUpdate int
	ips     map[string]int

	mu sync.Mutex
}

func (p *mockPodNetwork) Init() error {
	panic("not implemented")
}

func (p *mockPodNetwork) List() ([]*nodenet.PodNetConf, error) {
	panic("not implemented")
}

func (p *mockPodNetwork) SetupIPAM(nsPath, podName, podNS string, conf *nodenet.PodNetConf) (*current.Result, error) {
	panic("not implemented")
}

func (p *mockPodNetwork) SetupEgress(nsPath string, conf *nodenet.PodNetConf, hook nodenet.SetupHook) error {
	panic("not implemented")
}

func (p *mockPodNetwork) Update(podIPv4, podIPv6 net.IP, hook nodenet.SetupHook, pod *corev1.Pod) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.nUpdate++
	_, ok := p.ips[podIPv4.String()]
	if !ok {
		p.ips[podIPv4.String()] = 1
	}

	_, ok = p.ips[podIPv6.String()]
	if !ok {
		p.ips[podIPv6.String()] = 1
	}
	return nil
}

func (p *mockPodNetwork) getPodIPCount() map[string]int {
	m := make(map[string]int)

	p.mu.Lock()
	defer p.mu.Unlock()

	maps.Copy(m, p.ips)

	return m
}

func (p *mockPodNetwork) Check(containerId, iface string) error {
	panic("not implemented")
}

func (p *mockPodNetwork) Destroy(containerId, iface string) error {
	panic("not implemented")
}

type familyValidationPodNet struct {
	nodenet.PodNetwork
	updates int
}

func TestEgressWatcherRequeuesUnsynchronizedDiscovery(t *testing.T) {
	for _, annotation := range []string{"egress", "other,egress"} {
		t.Run(annotation, func(t *testing.T) {
			scheme := runtime.NewScheme()
			for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, coilv2.AddToScheme} {
				if err := add(scheme); err != nil {
					t.Fatal(err)
				}
			}
			eg := &coilv2.Egress{}
			eg.Namespace, eg.Name = "default", "egress"
			eg.Spec.Destinations = []string{"0.0.0.0/0"}
			svc := &corev1.Service{}
			svc.Namespace, svc.Name = eg.Namespace, eg.Name
			svc.Spec.ClusterIP = "10.96.0.10"
			svc.Spec.ClusterIPs = []string{svc.Spec.ClusterIP}
			pod := &corev1.Pod{}
			pod.Namespace, pod.Name = "default", "client"
			pod.Annotations = map[string]string{constants.AnnEgressPrefix + eg.Namespace: annotation}
			pod.Spec.NodeName = "worker"
			pod.Status.Phase = corev1.PodRunning
			pod.Status.PodIP = "10.1.2.3"
			pod.Status.PodIPs = []corev1.PodIP{{IP: pod.Status.PodIP}}
			k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(eg, svc, pod).
				WithIndex(&corev1.Pod{}, constants.PodNodeNameKey, func(obj client.Object) []string {
					return []string{obj.(*corev1.Pod).Spec.NodeName}
				}).Build()
			podNet := &familyValidationPodNet{}
			watcher := &EgressWatcher{
				Client:            k8sClient,
				NodeName:          pod.Spec.NodeName,
				PodNet:            podNet,
				ServiceCIDRSource: netfilter.NewServiceCIDRInformerSource(k8sfake.NewSimpleClientset()),
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result, err := watcher.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(eg)})
			if err != nil {
				t.Fatalf("Reconcile() error = %v, want fixed requeue without an error", err)
			}
			if result.RequeueAfter != 5*time.Second {
				t.Fatalf("Reconcile() RequeueAfter = %v, want 5s", result.RequeueAfter)
			}
			if podNet.updates != 0 {
				t.Fatalf("pod network updates = %d before discovery synchronized, want 0", podNet.updates)
			}
		})
	}
}

func (p *familyValidationPodNet) Update(net.IP, net.IP, nodenet.SetupHook, *corev1.Pod) error {
	p.updates++
	return nil
}

func TestReconcileEgressClientValidatesOnlyServiceCIDRsForActiveFamily(t *testing.T) {
	tests := []struct {
		name            string
		destinations    []string
		clusterIPs      []string
		serviceCIDRs    []string
		clusterNetworks []string
		wantErrCIDR     string
		wantDiscovery   bool
		deletionUpdates int
	}{
		{
			name:          "IPv4 egress ignores uncovered IPv6 ServiceCIDR",
			destinations:  []string{"0.0.0.0/0"},
			wantDiscovery: true,
			clusterIPs:    []string{"10.96.0.10"},
			serviceCIDRs:  []string{"10.96.0.0/16", "2001:db8:100::/112"},
		},
		{
			name:          "IPv6 egress ignores uncovered IPv4 ServiceCIDR",
			destinations:  []string{"::/0"},
			wantDiscovery: true,
			clusterIPs:    []string{"fc00:100::10"},
			serviceCIDRs:  []string{"203.0.113.0/24", "fc00:100::/64"},
		},
		{
			name:          "uncovered active IPv4 ServiceCIDR still fails",
			destinations:  []string{"0.0.0.0/0"},
			wantDiscovery: true,
			clusterIPs:    []string{"203.0.113.10"},
			serviceCIDRs:  []string{"203.0.113.0/24", "fc00:100::/64"},
			wantErrCIDR:   "203.0.113.0/24",
		},
		{
			name:          "uncovered active IPv6 ServiceCIDR still fails",
			destinations:  []string{"::/0"},
			wantDiscovery: true,
			clusterIPs:    []string{"2001:db8:100::10"},
			serviceCIDRs:  []string{"10.96.0.0/16", "2001:db8:100::/112"},
			wantErrCIDR:   "2001:db8:100::/112",
		},
		{
			name:          "dual stack egress validates both families",
			destinations:  []string{"0.0.0.0/0", "::/0"},
			clusterIPs:    []string{"10.96.0.10", "fc00:100::10"},
			serviceCIDRs:  []string{"10.96.0.0/16", "fc00:100::/64"},
			wantDiscovery: true,
		},
		{
			name:          "dual stack egress rejects uncovered IPv6",
			destinations:  []string{"0.0.0.0/0", "::/0"},
			clusterIPs:    []string{"10.96.0.10", "2001:db8:100::10"},
			serviceCIDRs:  []string{"10.96.0.0/16", "2001:db8:100::/112"},
			wantDiscovery: true,
			wantErrCIDR:   "2001:db8:100::/112",
		},
		{
			name:          "dual stack egress rejects uncovered IPv4",
			destinations:  []string{"0.0.0.0/0", "::/0"},
			clusterIPs:    []string{"203.0.113.10", "fc00:100::10"},
			serviceCIDRs:  []string{"203.0.113.0/24", "fc00:100::/64"},
			wantDiscovery: true,
			wantErrCIDR:   "203.0.113.0/24",
		},
		{
			name:            "configured networks cover nondefault ServiceCIDR",
			destinations:    []string{"0.0.0.0/0"},
			clusterIPs:      []string{"203.0.113.10"},
			serviceCIDRs:    []string{"203.0.113.0/24"},
			clusterNetworks: []string{"203.0.113.0/24"},
			wantDiscovery:   true,
		},
		{
			name:            "configured networks restrict default coverage",
			destinations:    []string{"0.0.0.0/0"},
			clusterIPs:      []string{"10.96.0.10"},
			serviceCIDRs:    []string{"10.96.0.0/16"},
			clusterNetworks: []string{"10.97.0.0/16"},
			wantDiscovery:   true,
			wantErrCIDR:     "10.96.0.0/16",
		},
		{
			name:          "nil networks still require ServiceCIDR discovery",
			destinations:  []string{"0.0.0.0/0"},
			clusterIPs:    []string{"10.96.0.10"},
			wantDiscovery: true,
			wantErrCIDR:   "no ServiceCIDR objects found",
		},
		{
			name:          "multiple gateways select IPv4 once",
			destinations:  []string{"0.0.0.0/0"},
			clusterIPs:    []string{"10.96.0.10", "10.96.0.11"},
			serviceCIDRs:  []string{"10.96.0.0/16", "2001:db8:100::/112"},
			wantDiscovery: true,
		},
		{
			name:            "gateway without matching destinations is excluded",
			deletionUpdates: 1,
			destinations:    []string{"0.0.0.0/0"},
			clusterIPs:      []string{"10.96.0.10", "2001:db8:100::10"},
			serviceCIDRs:    []string{"10.96.0.0/16", "2001:db8:100::/112"},
			wantDiscovery:   true,
		},
		{
			name:         "no matching destinations skips discovery",
			destinations: []string{"::/0"},
			clusterIPs:   []string{"10.96.0.10"},
		},
		{
			name:            "deletion runs before active validation failure",
			destinations:    []string{"0.0.0.0/0"},
			clusterIPs:      []string{"203.0.113.10", "fc00:100::10"},
			serviceCIDRs:    []string{"203.0.113.0/24", "fc00:100::/64"},
			wantDiscovery:   true,
			wantErrCIDR:     "203.0.113.0/24",
			deletionUpdates: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			for _, add := range []func(*runtime.Scheme) error{
				corev1.AddToScheme,
				coilv2.AddToScheme,
				networkingv1.AddToScheme,
			} {
				if err := add(scheme); err != nil {
					t.Fatalf("add API scheme: %v", err)
				}
			}

			podIP := "10.1.2.3"
			if slices.Contains(tt.destinations, "::/0") {
				podIP = "fc00:100::3"
			}
			eg := &coilv2.Egress{}
			eg.Namespace, eg.Name = "default", "egress"
			eg.Spec.Destinations = tt.destinations
			svc := &corev1.Service{}
			svc.Namespace, svc.Name = eg.Namespace, eg.Name
			svc.Spec.ClusterIP = tt.clusterIPs[0]
			svc.Spec.ClusterIPs = tt.clusterIPs
			objects := []runtime.Object{eg, svc}
			for i, cidr := range tt.serviceCIDRs {
				objects = append(objects, &networkingv1.ServiceCIDR{
					Name: "cidr-" + strconv.Itoa(i),
					Spec: networkingv1.ServiceCIDRSpec{CIDRs: []string{cidr}},
				})
			}
			var networks *netfilter.ClusterNetworks
			if tt.clusterNetworks != nil {
				var err error
				networks, err = netfilter.ParseClusterNetworks(tt.clusterNetworks)
				if err != nil {
					t.Fatalf("parse cluster networks: %v", err)
				}
			}
			serviceCIDRLists := 0
			podNet := &familyValidationPodNet{}
			k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).
				WithInterceptorFuncs(interceptor.Funcs{
					List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
						if _, ok := list.(*networkingv1.ServiceCIDRList); ok {
							serviceCIDRLists++
							if podNet.updates != tt.deletionUpdates {
								t.Errorf("Pod network updates before discovery = %d, want %d deletions", podNet.updates, tt.deletionUpdates)
							}
						}
						return cl.List(ctx, list, opts...)
					},
				}).Build()
			watcher := &EgressWatcher{
				Client:            k8sClient,
				PodNet:            podNet,
				EgressPort:        5555,
				ClusterNetworks:   networks,
				ServiceCIDRSource: readerServiceCIDRSource{k8sClient},
			}
			pod := &corev1.Pod{}
			pod.Namespace, pod.Name = "default", "client"
			pod.Status.PodIPs = []corev1.PodIP{{IP: podIP}}
			pod.Status.PodIP = podIP

			err := watcher.reconcileEgressClient(context.Background(), eg, pod, &logr.Logger{})
			wantLists := 0
			if tt.wantDiscovery {
				wantLists = 1
			}
			if serviceCIDRLists != wantLists {
				t.Errorf("ServiceCIDR List calls = %d, want %d", serviceCIDRLists, wantLists)
			}

			if tt.wantErrCIDR == "" {
				if err != nil {
					t.Fatalf("reconcileEgressClient() returned unexpected error: %v", err)
				}
				if podNet.updates != len(tt.clusterIPs) {
					t.Errorf("Pod network updates = %d, want %d", podNet.updates, len(tt.clusterIPs))
				}
				return
			}
			if podNet.updates != tt.deletionUpdates {
				t.Errorf("Pod network updates after validation failure = %d, want %d deletions", podNet.updates, tt.deletionUpdates)
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErrCIDR) {
				t.Fatalf("reconcileEgressClient() error = %v, want error containing %q", err, tt.wantErrCIDR)
			}
		})
	}
}
