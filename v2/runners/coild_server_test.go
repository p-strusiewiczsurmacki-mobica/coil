package runners

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	current "github.com/containernetworking/cni/pkg/types/100"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/vishvananda/netlink"
	uberzap "go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	clientgotesting "k8s.io/client-go/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	coilv2 "github.com/cybozu-go/coil/v2/api/v2"
	"github.com/cybozu-go/coil/v2/pkg/cnirpc"
	"github.com/cybozu-go/coil/v2/pkg/config"
	"github.com/cybozu-go/coil/v2/pkg/constants"
	"github.com/cybozu-go/coil/v2/pkg/nat/netfilter"
	"github.com/cybozu-go/coil/v2/pkg/nodenet"
)

const (
	testIPAMKey   = "TEST_IPAM"
	testEgressKey = "TEST_EGRESS"
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

type mockNodeIPAM struct {
	nAllocate    int
	nFree        int
	errFree      bool
	nClearRoutes atomic.Int32
}

func (n *mockNodeIPAM) Register(ctx context.Context, poolName, containerID, iface string, ipv4, ipv6 net.IP) error {
	panic("not implemented")
}

func (n *mockNodeIPAM) GC(ctx context.Context) error {
	panic("not implemented")
}

func (n *mockNodeIPAM) Notify(*coilv2.BlockRequest) {
	panic("not implemented")
}

func (n *mockNodeIPAM) NodeInternalIP(ctx context.Context) (net.IP, net.IP, error) {
	panic("not implemented")
}

func (n *mockNodeIPAM) ClearRoutes(ctx context.Context) error {
	n.nClearRoutes.Add(1)
	return nil
}

func (n *mockNodeIPAM) Allocate(ctx context.Context, poolName, containerID, iface string) (ipv4, ipv6 net.IP, err error) {
	n.nAllocate++
	if poolName == "default" {
		switch containerID {
		case "pod1":
			return net.ParseIP("10.1.2.3"), net.ParseIP("fd02::1"), nil
		case "nat-client1":
			return net.ParseIP("10.1.2.4"), net.ParseIP("fd02::2"), nil
		case "nat-client2":
			return net.ParseIP("10.1.2.5"), net.ParseIP("fd02::3"), nil
		}
	}
	if poolName == "global" && containerID == "dns1" {
		return net.ParseIP("8.8.8.8"), nil, nil
	}
	return nil, nil, errors.New("some error")
}

func (n *mockNodeIPAM) Free(ctx context.Context, containerID, iface string) error {
	n.nFree++
	if n.errFree {
		return errors.New("free failure")
	}
	return nil
}

type mockPodNetwork struct {
	nSetup   int
	nCheck   int
	nDestroy int

	errSetup   bool
	errDestroy bool

	expected string
}

func (p *mockPodNetwork) Init() error {
	panic("not implemented")
}

func (p *mockPodNetwork) List() ([]*nodenet.PodNetConf, error) {
	panic("not implemented")
}

func (p *mockPodNetwork) SetupIPAM(nsPath, podName, podNS string, conf *nodenet.PodNetConf) (*current.Result, error) {
	p.nSetup++
	if p.errSetup {
		return nil, errors.New("setup failure")
	}
	var ips []*current.IPConfig
	if conf.IPv4 != nil {
		ips = append(ips, &current.IPConfig{
			Address: *netlink.NewIPNet(conf.IPv4),
		})
	}
	if conf.IPv6 != nil {
		ips = append(ips, &current.IPConfig{
			Address: *netlink.NewIPNet(conf.IPv6),
		})
	}
	return &current.Result{IPs: ips}, nil
}

func (p *mockPodNetwork) SetupEgress(nsPath string, conf *nodenet.PodNetConf, hook nodenet.SetupHook) error {
	return nil
}

func (p *mockPodNetwork) Update(podIPv4, podIPv6 net.IP, hook nodenet.SetupHook, pod *corev1.Pod) error {
	panic("not implemented")
}

func (p *mockPodNetwork) Check(containerId, iface string) error {
	p.nCheck++
	if containerId == "pod1" || containerId == "dns1" || containerId == p.expected {
		return nil
	}
	return errors.New("check failure")
}

func (p *mockPodNetwork) Destroy(containerId, iface string) error {
	p.nDestroy++
	if p.errDestroy {
		return errors.New("destroy failure")
	}
	return nil
}

func (p *mockPodNetwork) expect(value string) {
	p.expected = value
}

func (p *mockPodNetwork) expectByPod(namespace, name string) error {
	pod := corev1.Pod{}
	if err := k8sClient.Get(context.TODO(), types.NamespacedName{Namespace: namespace, Name: name}, &pod, &client.GetOptions{}); err != nil {
		return fmt.Errorf("failed to get pod: %w", err)
	}
	p.expected = string(pod.UID)
	return nil
}

type mockNATSetup struct {
	gwnets []GWNets
}

func (ns *mockNATSetup) Hook(gwnets []GWNets, _ string, _ *uberzap.Logger) func(ipv4, ipv6 net.IP) error {
	ns.gwnets = gwnets
	return nil
}

func mockAlias(conf *nodenet.PodNetConf, ifName string) error {
	return nil
}

var _ = Describe("Coild server", func() {
	testIPAMEnv := os.Getenv(testIPAMKey)
	testIPAM := testIPAMEnv == "" || testIPAMEnv == "true"

	testEgressEnv := os.Getenv(testEgressKey)
	testEgress := testEgressEnv == "" || testEgressEnv == "true"

	tmpFile, err := os.CreateTemp("", "")
	if err != nil {
		panic(err)
	}
	coildSocket := tmpFile.Name()
	tmpFile.Close()
	os.Remove(coildSocket)

	ctx := context.Background()
	var cancel context.CancelFunc
	var nodeIPAM *mockNodeIPAM
	var podNet *mockPodNetwork
	var natsetup *mockNATSetup
	var logbuf *bytes.Buffer
	var conn *grpc.ClientConn
	var cniClient cnirpc.CNIClient
	metricPort := 13449

	BeforeEach(func() {
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
				BindAddress: fmt.Sprintf("localhost:%d", metricPort),
			},
		})
		metricPort--
		Expect(err).ToNot(HaveOccurred())

		l, err := net.Listen("unix", coildSocket)
		if err != nil {
			Expect(err).ToNot(HaveOccurred())
		}
		nodeIPAM = &mockNodeIPAM{}
		podNet = &mockPodNetwork{}
		natsetup = &mockNATSetup{}
		logbuf = &bytes.Buffer{}
		logger := zap.NewRaw(zap.WriteTo(logbuf), zap.StacktraceLevel(zapcore.DPanicLevel))
		cfg := &config.Config{
			MetricsAddr:            constants.DefautlMetricsAddr,
			HealthAddr:             constants.DefautlMetricsAddr,
			PodTableId:             constants.DefautlPodTableId,
			PodRulePrio:            constants.DefautlPodRulePrio,
			ExportTableId:          constants.DefautlExportTableId,
			ProtocolId:             constants.DefautlProtocolId,
			SocketPath:             constants.DefaultSocketPath,
			CompatCalico:           constants.DefaultCompatCalico,
			EgressPort:             constants.DefaultEgressPort,
			RegisterFromMain:       constants.DefaultRegisterFromMain,
			EnableIPAM:             testIPAM,
			EnableEgress:           testEgress,
			AddressBlockGCInterval: 10 * time.Second,
		}

		serv := NewCoildServer(l, mgr, nodeIPAM, podNet, natsetup, cfg, logger, mockAlias, "test-node", nil, readerServiceCIDRSource{mgr.GetAPIReader()})
		err = mgr.Add(serv)
		Expect(err).ToNot(HaveOccurred())

		go func() {
			err := mgr.Start(ctx)
			if err != nil {
				panic(err)
			}
		}()
		time.Sleep(100 * time.Millisecond)

		dialer := &net.Dialer{}
		dialFunc := func(ctx context.Context, a string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", a)
		}
		resolver.SetDefaultScheme("passthrough")
		conn, err = grpc.NewClient(coildSocket, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(dialFunc))
		Expect(err).ToNot(HaveOccurred())
		cniClient = cnirpc.NewCNIClient(conn)
	})

	AfterEach(func() {
		if conn != nil {
			conn.Close()
			conn = nil
		}
		cancel()
		Expect(k8sClient.Delete(context.Background(), &networkingv1.ServiceCIDR{
			Name: "coil-egress-test",
		})).To(Succeed())
		time.Sleep(10 * time.Millisecond)
		os.Remove(coildSocket)
	})

	It("should work as expected", func() {
		By("calling Add without creating the pod")
		_, err := cniClient.Add(ctx, &cnirpc.CNIArgs{
			Args:        map[string]string{"K8S_POD_NAME": "foo", "K8S_POD_NAMESPACE": "ns1"},
			ContainerId: "pod1",
			Ifname:      "eth0",
			Netns:       "/run/netns/foo",
		})
		Expect(err).To(HaveOccurred())

		pod := &corev1.Pod{}
		pod.Namespace = "ns1"
		pod.Name = "foo"
		pod.Spec.Containers = []corev1.Container{
			{Name: "foo", Image: "nginx"},
		}
		err = k8sClient.Create(ctx, pod)
		Expect(err).NotTo(HaveOccurred())

		By("calling Add w/o K8S_POD_NAMESPACE")
		_, err = cniClient.Add(ctx, &cnirpc.CNIArgs{
			Args:        map[string]string{"K8S_POD_NAME": "foo"}, // no namespace
			ContainerId: "pod1",
			Ifname:      "eth0",
			Netns:       "/run/netns/foo",
		})
		Expect(err).To(HaveOccurred())

		By("calling Add w/o K8S_POD_NAME")
		_, err = cniClient.Add(ctx, &cnirpc.CNIArgs{
			Args:        map[string]string{"K8S_POD_NAMESPACE": "ns1"}, // no name
			ContainerId: "pod1",
			Ifname:      "eth0",
			Netns:       "/run/netns/foo",
		})
		Expect(err).To(HaveOccurred())

		By("calling Add with enough parameters")
		logbuf.Reset()
		data, err := cniClient.Add(ctx, &cnirpc.CNIArgs{
			Args:        map[string]string{"K8S_POD_NAME": "foo", "K8S_POD_NAMESPACE": "ns1"},
			ContainerId: "pod1",
			Ifname:      "eth0",
			Netns:       "/run/netns/foo",
			Interfaces:  map[string]bool{"eth0": false},
		})

		if testIPAM || testEgress {
			Expect(err).NotTo(HaveOccurred())
		} else {
			Expect(err).To(HaveOccurred())
		}

		result := &current.Result{}
		if testIPAM {
			By("checking the result")
			err = json.Unmarshal(data.Result, result)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.IPs).To(HaveLen(2))
		}

		if testIPAM || testEgress {
			By("checking custom tags in gRPC log")
			// Expecting JSON output like:
			// {
			//   "grpc.code": "OK",
			//   "grpc.method": "Add",
			//   "grpc.request.pod.name": "foo",
			//   "grpc.request.pod.namespace": "ns1",
			//   "grpc.service": "pkg.cnirpc.CNI",
			//   "grpc.start_time": "2020-08-30T10:18:49Z",
			//   "grpc.time_ms": 102.34100341796875,
			//   "level": "info",
			//   "msg": "finished unary call with code OK",
			//   "peer.address": "@",
			//   "span.kind": "server",
			//   "system": "grpc",
			//   "ts": 1598782729.4605289
			// }
			logFields := struct {
				Method      string `json:"grpc.method"`
				Netns       string `json:"grpc.request.netns"`
				ContainerId string `json:"grpc.request.container_id"`
				Ifname      string `json:"grpc.request.ifname"`
				PodName     string `json:"grpc.request.pod.name"`
				PodNS       string `json:"grpc.request.pod.namespace"`
			}{}
			err = json.Unmarshal(logbuf.Bytes(), &logFields)
			Expect(err).ToNot(HaveOccurred())
			Expect(logFields.Method).To(Equal("Add"))
			Expect(logFields.Netns).To(Equal("/run/netns/foo"))
			Expect(logFields.ContainerId).To(Equal("pod1"))
			Expect(logFields.Ifname).To(Equal("eth0"))
			Expect(logFields.PodName).To(Equal("foo"))
			Expect(logFields.PodNS).To(Equal("ns1"))

			By("checking metrics for gRPC")
			resp, err := http.Get("http://localhost:13449/metrics")
			Expect(err).NotTo(HaveOccurred())
			defer resp.Body.Close()
			textParser := expfmt.NewTextParser(model.UTF8Validation)
			mfs, err := textParser.TextToMetricFamilies(resp.Body)
			Expect(err).NotTo(HaveOccurred())
			Expect(mfs).To(HaveKey("grpc_server_handled_total"))
			mf := mfs["grpc_server_handled_total"]
			metric := findMetric(mf, map[string]string{
				"grpc_method": "Add",
				"grpc_code":   "OK",
			})
			Expect(metric).NotTo(BeNil())
			// Expecting at least 1 call, because there may be other calls in BeforeEach.
			Expect(metric.GetCounter().GetValue()).To(BeNumerically(">=", 1))

			By("creating a pod in ns2")
			pod = &corev1.Pod{}
			pod.Namespace = "ns2"
			pod.Name = "bar"
			pod.Spec.Containers = []corev1.Container{
				{Name: "nginx", Image: "nginx"},
			}
			err = k8sClient.Create(ctx, pod)
			Expect(err).NotTo(HaveOccurred())

			if testIPAM {
				By("calling Add expecting a temporary failure")
				podNet.errSetup = true
				_, err = cniClient.Add(ctx, &cnirpc.CNIArgs{
					Args:        map[string]string{"K8S_POD_NAME": "bar", "K8S_POD_NAMESPACE": "ns2"},
					ContainerId: "dns1",
					Ifname:      "eth0",
					Netns:       "/run/netns/bar",
				})
				Expect(err).To(HaveOccurred())
			}

			By("calling Add for ns2/bar")
			podNet.errSetup = false
			data, err = cniClient.Add(ctx, &cnirpc.CNIArgs{
				Args:        map[string]string{"K8S_POD_NAME": "bar", "K8S_POD_NAMESPACE": "ns2"},
				ContainerId: "dns1",
				Ifname:      "eth0",
				Netns:       "/run/netns/bar",
			})
			Expect(err).NotTo(HaveOccurred())

			By("checking the result")
			result = &current.Result{}
			err = json.Unmarshal(data.Result, result)
			Expect(err).NotTo(HaveOccurred())
			if testIPAM {
				Expect(result.IPs).To(HaveLen(1))
				Expect(result.IPs[0].Address.IP.To4()).To(Equal(net.ParseIP("8.8.8.8").To4()))
			}

			By("creating another pod in ns1")
			pod = &corev1.Pod{}
			pod.Namespace = "ns1"
			pod.Name = "zot"
			pod.Spec.Containers = []corev1.Container{
				{Name: "nginx", Image: "nginx"},
			}
			err = k8sClient.Create(ctx, pod)
			Expect(err).NotTo(HaveOccurred())

			if testIPAM {
				By("calling Add to fail for Allocation failure")
				_, err = cniClient.Add(ctx, &cnirpc.CNIArgs{
					Args:        map[string]string{"K8S_POD_NAME": "zot", "K8S_POD_NAMESPACE": "ns1"},
					ContainerId: "hoge",
					Ifname:      "eth0",
					Netns:       "/run/netns/zot",
				})
				Expect(err).To(HaveOccurred())
			}

			By("calling Check")
			if !testIPAM {
				err := podNet.expectByPod("ns2", "bar")
				Expect(err).NotTo(HaveOccurred())
			}
			_, err = cniClient.Check(ctx, &cnirpc.CNIArgs{
				Args:        map[string]string{"K8S_POD_NAME": "bar", "K8S_POD_NAMESPACE": "ns2"},
				ContainerId: "dns1",
				Ifname:      "eth0",
				Netns:       "/run/netns/bar",
			})
			Expect(err).NotTo(HaveOccurred())

			if !testIPAM {
				podNet.expect("forced error")
			}
			_, err = cniClient.Check(ctx, &cnirpc.CNIArgs{
				Args:        map[string]string{"K8S_POD_NAME": "zot", "K8S_POD_NAMESPACE": "ns1"},
				ContainerId: "hoge",
				Ifname:      "eth0",
				Netns:       "/run/netns/zot",
			})
			Expect(err).To(HaveOccurred())

			By("calling Del")
			_, err = cniClient.Del(ctx, &cnirpc.CNIArgs{
				Args:        map[string]string{"K8S_POD_NAME": "bar", "K8S_POD_NAMESPACE": "ns2"},
				ContainerId: "dns1",
				Ifname:      "eth0",
				Netns:       "/run/netns/bar",
			})
			Expect(err).NotTo(HaveOccurred())

			if testIPAM {
				nodeIPAM.errFree = true
				_, err = cniClient.Del(ctx, &cnirpc.CNIArgs{
					Args:        map[string]string{"K8S_POD_NAME": "bar", "K8S_POD_NAMESPACE": "ns2"},
					ContainerId: "dns1",
					Ifname:      "eth0",
					Netns:       "/run/netns/bar",
				})
				Expect(err).To(HaveOccurred())

				nodeIPAM.errFree = false
				podNet.errDestroy = true
				_, err = cniClient.Del(ctx, &cnirpc.CNIArgs{
					Args:        map[string]string{"K8S_POD_NAME": "bar", "K8S_POD_NAMESPACE": "ns2"},
					ContainerId: "dns1",
					Ifname:      "eth0",
					Netns:       "/run/netns/bar",
				})
				Expect(err).To(HaveOccurred())
			}
		}
	})

	if testEgress {
		It("should setup Foo-over-UDP NAT", func() {
			By("creating pod declaring itself as a NAT client")
			pod := &corev1.Pod{}
			pod.Namespace = "ns1"
			pod.Name = "nat-client1"
			pod.Spec.Containers = []corev1.Container{
				{Name: "foo", Image: "nginx"},
			}
			pod.Annotations = map[string]string{
				"egress.coil.cybozu.com/ns2": "egress",
			}
			err = k8sClient.Create(ctx, pod)
			Expect(err).NotTo(HaveOccurred())

			By("calling Add without Egress/Service")
			_, err := cniClient.Add(ctx, &cnirpc.CNIArgs{
				Args:        map[string]string{"K8S_POD_NAME": "nat-client1", "K8S_POD_NAMESPACE": "ns1"},
				ContainerId: "nat-client1",
				Ifname:      "eth0",
				Netns:       "/run/netns/nat-client1",
			})
			Expect(err).To(HaveOccurred())

			eg := &coilv2.Egress{}
			eg.Namespace = "ns2"
			eg.Name = "egress"
			eg.Spec.Destinations = []string{"192.168.0.0/16", "fd20::/112"}
			eg.Spec.Replicas = 1
			err = k8sClient.Create(ctx, eg)
			Expect(err).NotTo(HaveOccurred())

			By("calling Add without Service")
			_, err = cniClient.Add(ctx, &cnirpc.CNIArgs{
				Args:        map[string]string{"K8S_POD_NAME": "nat-client1", "K8S_POD_NAMESPACE": "ns1"},
				ContainerId: "nat-client1",
				Ifname:      "eth0",
				Netns:       "/run/netns/nat-client1",
			})
			Expect(err).To(HaveOccurred())

			svc := &corev1.Service{}
			svc.Namespace = "ns2"
			svc.Name = "egress"
			// currently, ClusterIP must be picked from 10.0.0.0/24
			// see https://github.com/kubernetes/kubernetes/pull/51249
			svc.Spec.ClusterIP = "10.0.0.5"
			svc.Spec.ClusterIPs = []string{"10.0.0.5"}
			svc.Spec.Ports = []corev1.ServicePort{{Port: 8080}}
			err = k8sClient.Create(ctx, svc)
			Expect(err).NotTo(HaveOccurred())
			time.Sleep(100 * time.Millisecond)

			By("calling Add with IPv4 Service")
			_, err = cniClient.Add(ctx, &cnirpc.CNIArgs{
				Args:        map[string]string{"K8S_POD_NAME": "nat-client1", "K8S_POD_NAMESPACE": "ns1"},
				ContainerId: "nat-client1",
				Ifname:      "eth0",
				Netns:       "/run/netns/nat-client1",
				Interfaces:  map[string]bool{"eth0": false},
			})
			Expect(err).NotTo(HaveOccurred())

			By("checking NAT configurations")
			Expect(natsetup.gwnets).To(HaveLen(1))
			gwnets := natsetup.gwnets[0]
			Expect(gwnets.Gateway.Equal(net.ParseIP("10.0.0.5"))).To(BeTrue())
			Expect(gwnets.Networks).To(HaveLen(1))
			subnet := gwnets.Networks[0]
			Expect(subnet.IP.Equal(net.ParseIP("192.168.0.0"))).To(BeTrue())
		})
	}
})

var _ = Describe("shutdown route cleanup", func() {
	var nodeIPAM *mockNodeIPAM
	var mgrDone chan struct{}
	var cancel context.CancelFunc
	var socketPath string

	BeforeEach(func() {
		// Initialize with safe defaults so AfterEach does not crash if startServer is never called.
		cancel = func() {}
		mgrDone = make(chan struct{})
		close(mgrDone)
	})

	AfterEach(func() {
		cancel()
		Eventually(mgrDone, "15s").Should(BeClosed())
		os.Remove(socketPath)
	})

	startServer := func(nodeName string, clearRoutes bool) {
		tmpFile, err := os.CreateTemp("", "")
		Expect(err).ToNot(HaveOccurred())
		socketPath = tmpFile.Name()
		tmpFile.Close()
		os.Remove(socketPath)

		var ctx context.Context
		ctx, cancel = context.WithCancel(context.Background())

		mgr, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme:         scheme,
			LeaderElection: false,
			Metrics: metricsserver.Options{
				BindAddress: "0",
			},
		})
		Expect(err).ToNot(HaveOccurred())

		l, err := net.Listen("unix", socketPath)
		Expect(err).ToNot(HaveOccurred())

		nodeIPAM = &mockNodeIPAM{}
		logger := zap.NewRaw(zap.StacktraceLevel(zapcore.DPanicLevel))
		servCfg := &config.Config{
			AddressBlockGCInterval: 1 * time.Hour,
			ClearRoutesOnShutdown:  clearRoutes,
		}

		serv := NewCoildServer(l, mgr, nodeIPAM, &mockPodNetwork{}, &mockNATSetup{}, servCfg, logger, mockAlias, nodeName, nil, nil)
		err = mgr.Add(serv)
		Expect(err).ToNot(HaveOccurred())

		mgrDone = make(chan struct{})
		go func() {
			defer close(mgrDone)
			_ = mgr.Start(ctx)
		}()
		time.Sleep(100 * time.Millisecond)
	}

	It("clears routes when node does not exist and flag is enabled", func() {
		startServer("nonexistent-node", true)
		cancel()
		Eventually(func() int32 { return nodeIPAM.nClearRoutes.Load() }, "5s").Should(Equal(int32(1)))
	})

	It("does not clear routes when node exists and flag is enabled", func() {
		startServer("node1", true)
		cancel()
		Eventually(mgrDone, "5s").Should(BeClosed())
		Consistently(func() int32 { return nodeIPAM.nClearRoutes.Load() }, "200ms").Should(Equal(int32(0)))
	})

	It("does not clear routes when flag is disabled", func() {
		startServer("nonexistent-node", false)
		cancel()
		Eventually(mgrDone, "5s").Should(BeClosed())
		Consistently(func() int32 { return nodeIPAM.nClearRoutes.Load() }, "200ms").Should(Equal(int32(0)))
	})
})

func TestGetHookValidatesOnlyServiceCIDRsForActiveFamily(t *testing.T) {
	tests := []struct {
		name            string
		destinations    []string
		clusterIPs      []string
		serviceCIDRs    []string
		clusterNetworks []string
		// podIPs are the client pod addresses; nil means a dual-stack pod.
		podIPs        []string
		wantErrCIDR   string
		wantDiscovery bool
		// wantHook expects a NAT hook even when no discovery happens.
		wantHook bool
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
			podIPs:        []string{"10.1.2.3", "fc00:200::3"},
			wantDiscovery: true,
		},
		{
			name:          "dual stack egress rejects uncovered IPv6",
			destinations:  []string{"0.0.0.0/0", "::/0"},
			clusterIPs:    []string{"10.96.0.10", "2001:db8:100::10"},
			serviceCIDRs:  []string{"10.96.0.0/16", "2001:db8:100::/112"},
			podIPs:        []string{"10.1.2.3", "fc00:200::3"},
			wantDiscovery: true,
			wantErrCIDR:   "2001:db8:100::/112",
		},
		{
			name:          "dual stack egress rejects uncovered IPv4",
			destinations:  []string{"0.0.0.0/0", "::/0"},
			clusterIPs:    []string{"203.0.113.10", "fc00:100::10"},
			serviceCIDRs:  []string{"203.0.113.0/24", "fc00:100::/64"},
			podIPs:        []string{"10.1.2.3", "fc00:200::3"},
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
			name:          "gateway without matching destinations is excluded",
			destinations:  []string{"0.0.0.0/0"},
			clusterIPs:    []string{"10.96.0.10", "2001:db8:100::10"},
			serviceCIDRs:  []string{"10.96.0.0/16", "2001:db8:100::/112"},
			wantDiscovery: true,
		},
		{
			name:         "no matching destinations skips discovery",
			destinations: []string{"::/0"},
			clusterIPs:   []string{"10.96.0.10"},
		},
		{
			name:          "IPv4-only pod on dual stack egress ignores uncovered IPv6 ServiceCIDR",
			destinations:  []string{"0.0.0.0/0", "::/0"},
			clusterIPs:    []string{"10.96.0.10", "2001:db8:100::10"},
			serviceCIDRs:  []string{"10.96.0.0/16", "2001:db8:100::/112"},
			podIPs:        []string{"10.1.2.3"},
			wantDiscovery: true,
		},
		{
			name:          "IPv4-only pod on dual stack egress rejects uncovered IPv4 ServiceCIDR",
			destinations:  []string{"0.0.0.0/0", "::/0"},
			clusterIPs:    []string{"203.0.113.10", "fc00:100::10"},
			serviceCIDRs:  []string{"203.0.113.0/24", "fc00:100::/64"},
			podIPs:        []string{"10.1.2.3"},
			wantDiscovery: true,
			wantErrCIDR:   "203.0.113.0/24",
		},
		{
			name:          "IPv6-only pod on dual stack egress ignores uncovered IPv4 ServiceCIDR",
			destinations:  []string{"0.0.0.0/0", "::/0"},
			clusterIPs:    []string{"203.0.113.10", "fc00:100::10"},
			serviceCIDRs:  []string{"203.0.113.0/24", "fc00:100::/64"},
			podIPs:        []string{"fc00:200::3"},
			wantDiscovery: true,
		},
		{
			name:          "IPv6-only pod on dual stack egress rejects uncovered IPv6 ServiceCIDR",
			destinations:  []string{"0.0.0.0/0", "::/0"},
			clusterIPs:    []string{"10.96.0.10", "2001:db8:100::10"},
			serviceCIDRs:  []string{"10.96.0.0/16", "2001:db8:100::/112"},
			podIPs:        []string{"fc00:200::3"},
			wantDiscovery: true,
			wantErrCIDR:   "2001:db8:100::/112",
		},
		{
			name:         "IPv6-only pod on IPv4 egress skips discovery",
			destinations: []string{"0.0.0.0/0"},
			clusterIPs:   []string{"203.0.113.10"},
			serviceCIDRs: []string{"203.0.113.0/24"},
			podIPs:       []string{"fc00:200::3"},
			wantHook:     true,
		},
		{
			name:         "pod without addresses skips discovery",
			destinations: []string{"0.0.0.0/0", "::/0"},
			clusterIPs:   []string{"203.0.113.10", "2001:db8:100::10"},
			serviceCIDRs: []string{"203.0.113.0/24", "2001:db8:100::/112"},
			podIPs:       []string{},
			wantHook:     true,
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

			podIPs := tt.podIPs
			if podIPs == nil {
				podIPs = []string{"10.0.0.1", "2001:db8::1"}
			}
			var ipv4, ipv6 net.IP
			for _, s := range podIPs {
				ip := net.ParseIP(s)
				if ip.To4() != nil {
					ipv4 = ip.To4()
				} else {
					ipv6 = ip
				}
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
			natSetup := &mockNATSetup{}
			k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).
				WithInterceptorFuncs(interceptor.Funcs{
					List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
						if _, ok := list.(*networkingv1.ServiceCIDRList); ok {
							serviceCIDRLists++
							if len(natSetup.gwnets) != 0 {
								t.Error("NAT hook was configured before ServiceCIDR discovery")
							}
						}
						return cl.List(ctx, list, opts...)
					},
				}).Build()
			server := &coildServer{
				client:            k8sClient,
				cfg:               &config.Config{},
				natSetup:          natSetup,
				logger:            uberzap.NewNop(),
				clusterNetworks:   networks,
				serviceCIDRSource: readerServiceCIDRSource{k8sClient},
			}
			pod := &corev1.Pod{}
			pod.Namespace = "default"
			pod.Name = "client"
			pod.Annotations = map[string]string{constants.AnnEgressPrefix + "default": "egress"}

			_, err := server.getHook(context.Background(), pod, ipv4, ipv6)
			wantLists := 0
			if tt.wantDiscovery {
				wantLists = 1
			}
			if serviceCIDRLists != wantLists {
				t.Errorf("ServiceCIDR List calls = %d, want %d", serviceCIDRLists, wantLists)
			}

			if tt.wantErrCIDR != "" && len(natSetup.gwnets) != 0 {
				t.Error("NAT hook was configured after validation failed")
			}
			if tt.wantErrCIDR == "" {
				if wantHook := tt.wantDiscovery || tt.wantHook; (len(natSetup.gwnets) > 0) != wantHook {
					t.Errorf("NAT gateways = %v, want active hook: %v", natSetup.gwnets, wantHook)
				}
				if err != nil {
					t.Fatalf("getHook() returned unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("getHook() error = nil, want error containing %q", tt.wantErrCIDR)
			}
			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("getHook() error is not a gRPC status: %v", err)
			}
			for _, detail := range st.Details() {
				if cniErr, ok := detail.(*cnirpc.CNIError); ok && strings.Contains(cniErr.Details, tt.wantErrCIDR) {
					return
				}
			}
			t.Fatalf("getHook() error details do not contain %q: %v", tt.wantErrCIDR, st.Details())
		})
	}
}

func TestCNIStartsWhileServiceCIDRListIsForbidden(t *testing.T) {
	var listAttempts atomic.Int32
	kubeClient := k8sfake.NewSimpleClientset()
	kubeClient.PrependReactor("list", "servicecidrs", func(clientgotesting.Action) (bool, runtime.Object, error) {
		listAttempts.Add(1)
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "networking.k8s.io", Resource: "servicecidrs"}, "", errors.New("denied"))
	})
	source := netfilter.NewServiceCIDRInformerSource(kubeClient)

	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, coilv2.AddToScheme, networkingv1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatalf("add API scheme: %v", err)
		}
	}
	pod := &corev1.Pod{
		Namespace: "default",
		Name:      "client",
		UID:       "pod-uid",
	}
	egress := &coilv2.Egress{
		Namespace: "default",
		Name:      "egress",
		Spec:      coilv2.EgressSpec{Destinations: []string{"0.0.0.0/0"}},
	}
	svc := &corev1.Service{
		Namespace: "default",
		Name:      "egress",
		Spec: corev1.ServiceSpec{
			ClusterIP:  "10.0.0.10",
			ClusterIPs: []string{"10.0.0.10"},
		},
	}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, egress, svc).Build()

	mgr, err := ctrl.NewManager(&rest.Config{Host: "http://127.0.0.1:1"}, ctrl.Options{
		Scheme: scheme,
		MapperProvider: func(*rest.Config, *http.Client) (meta.RESTMapper, error) {
			return meta.NewDefaultRESTMapper([]schema.GroupVersion{}), nil
		},
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		LeaderElection:         false,
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cfg := &config.Config{EnableEgress: true}
	podNet := &mockPodNetwork{}
	serverRunnable := &coildServer{
		listener:          listener,
		apiReader:         reader,
		client:            reader,
		podNet:            podNet,
		natSetup:          &mockNATSetup{},
		logger:            uberzap.NewNop(),
		cfg:               cfg,
		aliasFunc:         mockAlias,
		serviceCIDRSource: source,
	}
	if err := mgr.Add(source); err != nil {
		t.Fatalf("add ServiceCIDR informer to manager: %v", err)
	}
	if err := mgr.Add(serverRunnable); err != nil {
		t.Fatalf("add CNI server to manager: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	managerDone := make(chan error, 1)
	go func() { managerDone <- mgr.Start(ctx) }()
	defer func() {
		cancel()
		select {
		case err := <-managerDone:
			if err != nil {
				t.Errorf("manager stopped with error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("manager did not stop after cancellation")
		}
	}()

	deadline := time.Now().Add(5 * time.Second)
	for listAttempts.Load() == 0 && time.Now().Before(deadline) {
		select {
		case err := <-managerDone:
			t.Fatalf("manager exited before forbidden ServiceCIDR list was observed: %v", err)
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	if listAttempts.Load() == 0 {
		t.Fatal("ServiceCIDR informer did not issue its forbidden initial list")
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
	defer dialCancel()
	c, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("unable to create grpc client: %v", err)
	}
	defer c.Close()

	cni := cnirpc.NewCNIClient(c)
	args := &cnirpc.CNIArgs{
		Args:        map[string]string{constants.PodNameKey: "client", constants.PodNamespaceKey: "default"},
		ContainerId: "sandbox",
		Ifname:      "eth0",
		// Egress validation only covers families the pod has an address for.
		Ips:        []string{"10.1.2.3"},
		Interfaces: map[string]bool{"eth0": false},
	}
	if _, err := cni.Add(dialCtx, args); err != nil {
		t.Fatalf("CNI Add without egress annotation should succeed while discovery is unavailable: %v", err)
	}

	pod.Annotations = map[string]string{constants.AnnEgressPrefix + "default": "egress"}
	if err := reader.Update(ctx, pod); err != nil {
		t.Fatalf("add egress annotation to pod: %v", err)
	}
	_, err = cni.Add(dialCtx, args)
	if err == nil {
		t.Fatal("CNI Add with egress annotation succeeded despite unavailable ServiceCIDR discovery")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("CNI Add error is not a gRPC status: %v", err)
	}
	if st.Code() != codes.Internal {
		t.Fatalf("CNI Add status code = %s, want Internal", st.Code())
	}
	for _, detail := range st.Details() {
		if cniErr, ok := detail.(*cnirpc.CNIError); ok && strings.Contains(cniErr.Details, "egress validation failed for cluster networks") {
			return
		}
	}
	t.Fatalf("CNI Add error details do not identify egress validation failure: %v", st.Details())
}
