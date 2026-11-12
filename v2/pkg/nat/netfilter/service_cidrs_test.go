package netfilter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	listersnetworkingv1 "k8s.io/client-go/listers/networking/v1"
	clientgotesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestValidateServiceCIDRs(t *testing.T) {
	tests := []struct {
		name            string
		services        []string
		clusters        []string
		nilReceiver     bool
		wantErrContains []string
		wantWrappedErr  bool
	}{
		{name: "broader", services: []string{"10.96.0.0/16"}, clusters: []string{"10.0.0.0/8"}},
		{name: "exact", services: []string{"10.96.0.0/16"}, clusters: []string{"10.96.0.0/16"}},
		{name: "two halves", services: []string{"10.96.0.0/16"}, clusters: []string{"10.96.128.0/17", "10.96.0.0/17"}},
		{name: "four quarters", services: []string{"10.96.0.0/16"}, clusters: []string{"10.96.192.0/18", "10.96.0.0/18", "10.96.128.0/18", "10.96.64.0/18"}},
		{name: "overlap duplicate shuffled", services: []string{"10.96.0.0/16"}, clusters: []string{"10.96.64.0/18", "10.96.0.0/17", "10.96.0.0/17", "10.96.128.0/17"}},
		{name: "missing half", services: []string{"10.96.0.0/16"}, clusters: []string{"10.96.0.0/17"}, wantErrContains: []string{"10.96.0.0/16", "--cluster-networks"}},
		{name: "interior gap", services: []string{"10.96.0.0/16"}, clusters: []string{"10.96.0.0/18", "10.96.64.0/19", "10.96.128.0/18", "10.96.192.0/18"}, wantErrContains: []string{"10.96.0.0/16", "--cluster-networks"}},
		{name: "unrelated", services: []string{"10.96.0.0/16"}, clusters: []string{"10.97.0.0/16"}, wantErrContains: []string{"10.96.0.0/16", "--cluster-networks"}},
		{name: "family mismatch", services: []string{"192.0.2.0/24"}, clusters: []string{"fd00::/8"}, wantErrContains: []string{"192.0.2.0/24", "--cluster-networks"}},
		{name: "IPv6 halves", services: []string{"fd00:1::/64"}, clusters: []string{"fd00:1:0:0:8000::/65", "fd00:1::/65"}},
		{name: "v4 /32 exact", services: []string{"192.0.2.1/32"}, clusters: []string{"192.0.2.1/32"}},
		{name: "v4 /32 adjacent", services: []string{"192.0.2.1/32"}, clusters: []string{"192.0.2.0/32"}, wantErrContains: []string{"192.0.2.1/32", "--cluster-networks"}},
		{name: "v6 /128 exact", services: []string{"2001:db8::1/128"}, clusters: []string{"2001:db8::1/128"}},
		{name: "v6 /128 adjacent", services: []string{"2001:db8::1/128"}, clusters: []string{"2001:db8::2/128"}, wantErrContains: []string{"2001:db8::1/128", "--cluster-networks"}},
		{name: "host bits masked", services: []string{"10.96.3.4/16"}, clusters: []string{"10.96.0.0/16"}},
		{name: "v4 max endpoint", services: []string{"255.255.255.255/32"}, clusters: []string{"255.255.255.254/31"}},
		{name: "v6 max endpoint", services: []string{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"}, clusters: []string{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127"}},
		{name: "mapped rejected", services: []string{"::ffff:10.96.0.0/120"}, clusters: []string{"10.0.0.0/8"}, wantErrContains: []string{"::ffff:10.96.0.0/120", "IPv4-mapped IPv6"}},
		{name: "nil receiver private dual stack", services: []string{"10.96.0.0/16", "fc00:1::/64"}, nilReceiver: true},
		{name: "empty config private dual stack", services: []string{"10.96.0.0/16", "fc00:1::/64"}},
		{name: "nil receiver public range", services: []string{"8.8.8.0/24"}, nilReceiver: true, wantErrContains: []string{"8.8.8.0/24", "--cluster-networks"}},
		{name: "empty config public range", services: []string{"8.8.8.0/24"}, wantErrContains: []string{"8.8.8.0/24", "--cluster-networks"}},
		{name: "custom IPv4 retains IPv6 default", services: []string{"10.96.0.0/16", "fc00:1::/64"}, clusters: []string{"10.96.0.0/16"}},
		{name: "custom IPv4 replaces default", services: []string{"10.97.0.0/16"}, clusters: []string{"10.96.0.0/16"}, wantErrContains: []string{"10.97.0.0/16", "--cluster-networks"}},
		{name: "uncovered second dual-stack CIDR", services: []string{"10.96.0.0/16", "2001:db8::/64"}, clusters: []string{"10.96.0.0/16"}, wantErrContains: []string{"2001:db8::/64", "--cluster-networks"}},
		{name: "custom IPv6 retains IPv4 fallback", services: []string{"10.96.0.0/16", "fd00:1::/64"}, clusters: []string{"fd00:1::/64"}},
		{name: "custom IPv6 replaces fallback", services: []string{"10.96.0.0/16", "fc00:1::/64"}, clusters: []string{"fd00:1::/64"}, wantErrContains: []string{"fc00:1::/64", "--cluster-networks"}},
		{name: "IPv4 /0 covered by two halves", services: []string{"0.0.0.0/0"}, clusters: []string{"128.0.0.0/1", "0.0.0.0/1"}},
		{name: "IPv4 /0 missing half", services: []string{"0.0.0.0/0"}, clusters: []string{"128.0.0.0/1"}, wantErrContains: []string{"0.0.0.0/0", "--cluster-networks"}},
		{name: "IPv6 /0 covered by two halves", services: []string{"::/0"}, clusters: []string{"8000::/1", "::/1"}},
		{name: "IPv6 /0 missing half", services: []string{"::/0"}, clusters: []string{"8000::/1"}, wantErrContains: []string{"::/0", "--cluster-networks"}},
		{name: "IPv6 /0 single address", services: []string{"::/0"}, clusters: []string{"::1/128"}, wantErrContains: []string{"::/0", "--cluster-networks"}},
		{name: "nil service CIDRs", services: nil, clusters: []string{"10.0.0.0/8"}, wantErrContains: []string{"no Service CIDRs"}},
		{name: "empty service CIDRs", services: []string{}, clusters: []string{"10.0.0.0/8"}, wantErrContains: []string{"no Service CIDRs"}},
		{name: "empty CIDR string", services: []string{""}, clusters: []string{"10.0.0.0/8"}, wantErrContains: []string{"\"\""}, wantWrappedErr: true},
		{name: "malformed CIDR", services: []string{"not-a-cidr"}, clusters: []string{"10.0.0.0/8"}, wantErrContains: []string{"not-a-cidr"}, wantWrappedErr: true},
		{name: "valid then malformed CIDR", services: []string{"10.1.0.0/16", "not-a-cidr"}, clusters: []string{"10.0.0.0/8"}, wantErrContains: []string{"not-a-cidr"}, wantWrappedErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cn *ClusterNetworks
			if !tt.nilReceiver {
				var err error
				cn, err = ParseClusterNetworks(tt.clusters)
				if err != nil {
					t.Fatalf("parse cluster networks: %v", err)
				}
			}
			err := cn.ValidateServiceCIDRs(tt.services, []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol})
			if len(tt.wantErrContains) == 0 {
				if err != nil {
					t.Fatalf("ValidateServiceCIDRs() error = %v, want success", err)
				}
				return
			}
			if err == nil {
				t.Fatal("ValidateServiceCIDRs() succeeded, want error")
			}
			for _, want := range tt.wantErrContains {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
			if tt.wantWrappedErr && errors.Unwrap(err) == nil {
				t.Errorf("error %q does not wrap a parse cause", err)
			}
		})
	}
}

func TestValidateServiceCIDRsDoesNotMutateInputs(t *testing.T) {
	cn, err := ParseClusterNetworks([]string{"10.96.128.0/17", "10.96.0.0/17"})
	if err != nil {
		t.Fatal(err)
	}
	before := []string{cn.v4[0].String(), cn.v4[1].String()}
	cidrs := []string{"10.96.3.4/16"}
	if err := cn.ValidateServiceCIDRs(cidrs, []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol}); err != nil {
		t.Fatal(err)
	}
	if cn.v4[0].String() != before[0] || cn.v4[1].String() != before[1] || cidrs[0] != "10.96.3.4/16" {
		t.Fatal("validation mutated input networks or CIDR strings")
	}
}

type serviceCIDRReader struct {
	client.Reader
	list func(context.Context, client.ObjectList) error
}

// readerServiceCIDRSource adapts controller-runtime fixtures for validator
// tests. Discovery behavior itself is exercised against the production
// informer source below.
type readerServiceCIDRSource struct{ reader client.Reader }

func (s readerServiceCIDRSource) Discover(ctx context.Context) ([]string, error) {
	var list networkingv1.ServiceCIDRList
	if err := s.reader.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list ServiceCIDRs: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(list.Items) == 0 {
		return nil, errors.New("no ServiceCIDR objects found")
	}
	var cidrs []string
	for _, item := range list.Items {
		if len(item.Spec.CIDRs) == 0 {
			return nil, fmt.Errorf("ServiceCIDR %q has no CIDRs", item.Name)
		}
		cidrs = append(cidrs, item.Spec.CIDRs...)
	}
	return cidrs, nil
}

func (r serviceCIDRReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if r.list != nil {
		return r.list(ctx, list)
	}
	return r.Reader.List(ctx, list, opts...)
}

func serviceCIDRScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := networkingv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func startedServiceCIDRInformerSource(t *testing.T, objects ...runtime.Object) *ServiceCIDRInformerSource {
	t.Helper()
	kubeClient := kubernetesfake.NewSimpleClientset(objects...)
	source := NewServiceCIDRInformerSource(kubeClient)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		<-done
	})
	go func() {
		defer close(done)
		_ = source.Start(ctx)
	}()
	if !cache.WaitForCacheSync(ctx.Done(), source.informer.HasSynced) {
		t.Fatal("ServiceCIDR informer did not synchronize")
	}
	return source
}

func TestDiscoverServiceCIDRs(t *testing.T) {
	objects := []runtime.Object{
		&networkingv1.ServiceCIDR{Name: "second", Spec: networkingv1.ServiceCIDRSpec{CIDRs: []string{"10.97.0.0/16", "fd00:5678::/108"}}},
		&networkingv1.ServiceCIDR{Name: "first", Spec: networkingv1.ServiceCIDRSpec{CIDRs: []string{"10.96.0.0/16"}}},
	}
	source := startedServiceCIDRInformerSource(t, objects...)
	got, err := source.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	want := []string{"10.96.0.0/16", "10.97.0.0/16", "fd00:5678::/108"}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Discover() = %v, want %v", got, want)
	}
}

func TestDiscoverServiceCIDRsRejectsEmptyResults(t *testing.T) {
	t.Run("empty list", func(t *testing.T) {
		source := startedServiceCIDRInformerSource(t)
		if _, err := source.Discover(context.Background()); err == nil {
			t.Fatal("expected error for empty ServiceCIDR list")
		}
	})

	t.Run("empty object CIDRs", func(t *testing.T) {
		source := startedServiceCIDRInformerSource(t, &networkingv1.ServiceCIDR{Name: "empty"})
		if _, err := source.Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "empty") {
			t.Fatalf("expected error naming empty ServiceCIDR, got %v", err)
		}
	})
}

func TestDiscoverServiceCIDRsContext(t *testing.T) {
	source := startedServiceCIDRInformerSource(t, &networkingv1.ServiceCIDR{
		Name: "ok",
		Spec: networkingv1.ServiceCIDRSpec{CIDRs: []string{"10.96.0.0/16"}},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Discover(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

type countingServiceCIDRLister struct {
	calls int
	err   error
}

func (l *countingServiceCIDRLister) List(labels.Selector) ([]*networkingv1.ServiceCIDR, error) {
	l.calls++
	return nil, l.err
}

func (l *countingServiceCIDRLister) Get(string) (*networkingv1.ServiceCIDR, error) {
	panic("unexpected Get")
}

var _ listersnetworkingv1.ServiceCIDRLister = (*countingServiceCIDRLister)(nil)

func TestDiscoverServiceCIDRsBeforeSyncReturnsPromptlyWithoutListing(t *testing.T) {
	source := NewServiceCIDRInformerSource(kubernetesfake.NewSimpleClientset())
	lister := &countingServiceCIDRLister{}
	source.lister = lister

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := time.Now()
	_, err := source.Discover(ctx)
	if !errors.Is(err, ErrServiceCIDRNotReady) {
		t.Fatalf("Discover() error = %v, want ErrServiceCIDRNotReady", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Discover() took %s before sync, want prompt return", elapsed)
	}
	if lister.calls != 0 {
		t.Fatalf("lister List called %d times before sync, want 0", lister.calls)
	}
}

func TestServiceCIDRInformerRecoversAfterForbiddenAndReflectsUpdates(t *testing.T) {
	service := &networkingv1.ServiceCIDR{
		Name: "services",
		Spec: networkingv1.ServiceCIDRSpec{CIDRs: []string{"10.96.0.0/16"}},
	}
	var allowList atomic.Bool
	var listAttempts atomic.Int32
	kubeClient := kubernetesfake.NewSimpleClientset(service)
	kubeClient.PrependReactor("list", "servicecidrs", func(clientgotesting.Action) (bool, runtime.Object, error) {
		listAttempts.Add(1)
		if !allowList.Load() {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "networking.k8s.io", Resource: "servicecidrs"}, "", errors.New("denied"))
		}
		return false, nil, nil
	})
	source := NewServiceCIDRInformerSource(kubeClient)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = source.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("ServiceCIDR informer did not stop after cancellation")
		}
	})

	deadline := time.Now().Add(3 * time.Second)
	for listAttempts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if listAttempts.Load() == 0 {
		t.Fatal("ServiceCIDR informer did not issue its initial list")
	}
	networks, err := ParseClusterNetworks([]string{"10.96.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateEgressClusterNetworks(ctx, source, networks, []corev1.IPFamily{corev1.IPv4Protocol})
	if !errors.Is(err, ErrServiceCIDRNotReady) {
		t.Fatalf("validation error = %v, want wrapped ErrServiceCIDRNotReady", err)
	}

	allowList.Store(true)
	syncCtx, syncCancel := context.WithTimeout(ctx, 5*time.Second)
	defer syncCancel()
	if !cache.WaitForCacheSync(syncCtx.Done(), source.informer.HasSynced) {
		t.Fatal("informer did not synchronize after forbidden responses stopped")
	}
	if err := ValidateEgressClusterNetworks(ctx, source, networks, []corev1.IPFamily{corev1.IPv4Protocol}); err != nil {
		t.Fatalf("validation did not recover after informer sync: %v", err)
	}

	updated := service.DeepCopy()
	updated.Spec.CIDRs = []string{"10.97.0.0/16"}
	if _, err := kubeClient.NetworkingV1().ServiceCIDRs().Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update ServiceCIDR: %v", err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		err = ValidateEgressClusterNetworks(ctx, source, networks, []corev1.IPFamily{corev1.IPv4Protocol})
		if err != nil && strings.Contains(err.Error(), "10.97.0.0/16") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("validation did not observe updated ServiceCIDR; last error = %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ServiceCIDR informer did not stop after cancellation")
	}
}

func TestValidateEgressClusterNetworksSkipsDiscoveryForEmptyFamilies(t *testing.T) {
	if err := ValidateEgressClusterNetworks(context.Background(), nil, nil, nil); err != nil {
		t.Fatalf("empty family selection should not require discovery: %v", err)
	}
}

func TestValidateEgressClusterNetworksHelper(t *testing.T) {
	service := func(name string, cidrs ...string) client.Object {
		return &networkingv1.ServiceCIDR{
			Name: name,
			Spec: networkingv1.ServiceCIDRSpec{CIDRs: cidrs},
		}
	}
	tests := []struct {
		name      string
		networks  []string
		objects   []client.Object
		wantErr   []string
		wantParse bool
	}{
		{
			name:     "split IPv4 prefixes cover ServiceCIDR",
			networks: []string{"10.96.0.0/17", "10.96.128.0/17"},
			objects:  []client.Object{service("services-v4", "10.96.0.0/16")},
		},
		{
			name:     "split prefixes cover dual stack object",
			networks: []string{"10.96.0.0/17", "10.96.128.0/17", "fd00:1234::/65", "fd00:1234:0:0:8000::/65"},
			objects:  []client.Object{service("services-dual", "10.96.0.0/16", "fd00:1234::/64")},
		},
		{
			name:     "all ranges across multiple objects are covered",
			networks: []string{"10.96.0.0/16", "10.97.0.0/16", "fd10::/64"},
			objects: []client.Object{
				service("primary", "10.96.0.0/16"),
				service("extra-v4", "10.97.0.0/16"),
				service("extra-v6", "fd10::/64"),
			},
		},
		{
			name:     "uncovered extra object range is reported",
			networks: []string{"10.96.0.0/16", "fd10::/64"},
			objects: []client.Object{
				service("a-primary", "10.96.0.0/16"),
				service("z-extra", "10.97.0.0/16"),
			},
			wantErr: []string{"egress validation", "10.97.0.0/16", "--cluster-networks"},
		},
		{
			name:     "uncovered IPv6 range in dual stack object is reported",
			networks: []string{"10.96.0.0/16", "fd20::/64"},
			objects:  []client.Object{service("services-dual", "10.96.0.0/16", "fd10::/64")},
			wantErr:  []string{"egress validation", "fd10::/64", "--cluster-networks"},
		},
		{
			name:    "empty config uses private dual stack defaults",
			objects: []client.Object{service("services-dual", "10.96.0.0/16", "fc00:1::/64")},
		},
		{
			name:     "IPv4 override retains IPv6 default",
			networks: []string{"10.96.0.0/16"},
			objects:  []client.Object{service("services-dual", "10.96.0.0/16", "fc00:1::/64")},
		},
		{
			name:     "IPv6 override retains IPv4 default",
			networks: []string{"fd10::/64"},
			objects:  []client.Object{service("services-dual", "10.96.0.0/16", "fd10::/64")},
		},
		{
			name:     "custom IPv4 replaces private default",
			networks: []string{"10.96.0.0/16"},
			objects:  []client.Object{service("private-v4", "10.97.0.0/16")},
			wantErr:  []string{"10.97.0.0/16", "--cluster-networks"},
		},
		{
			name:      "malformed discovered CIDR preserves parse error",
			networks:  []string{"10.96.0.0/16"},
			objects:   []client.Object{service("malformed", "not-a-cidr")},
			wantErr:   []string{"egress validation", "not-a-cidr"},
			wantParse: true,
		},
		{
			name:     "empty object fails despite another valid object",
			networks: []string{"10.96.0.0/16"},
			objects: []client.Object{
				service("a-valid", "10.96.0.0/16"),
				&networkingv1.ServiceCIDR{Name: "z-empty-object"},
			},
			wantErr: []string{"egress validation", "z-empty-object", "no CIDRs"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			networks, err := ParseClusterNetworks(tt.networks)
			if err != nil {
				t.Fatalf("ParseClusterNetworks() error = %v", err)
			}
			reader := fake.NewClientBuilder().WithScheme(serviceCIDRScheme(t)).WithObjects(tt.objects...).Build()
			err = ValidateEgressClusterNetworks(context.Background(), readerServiceCIDRSource{reader}, networks, []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol})
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("ValidateEgressClusterNetworks() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected validation error")
			}
			for _, part := range tt.wantErr {
				if !strings.Contains(err.Error(), part) {
					t.Errorf("error %q does not contain %q", err, part)
				}
			}
			if tt.wantParse {
				if errors.Unwrap(errors.Unwrap(err)) == nil {
					t.Fatalf("expected parse error to remain wrapped through validation, got %v", err)
				}
			}
		})
	}

	t.Run("empty list fails", func(t *testing.T) {
		reader := fake.NewClientBuilder().WithScheme(serviceCIDRScheme(t)).Build()
		err := ValidateEgressClusterNetworks(context.Background(), readerServiceCIDRSource{reader}, nil, []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol})
		if err == nil || !strings.Contains(err.Error(), "no ServiceCIDR objects found") {
			t.Fatalf("expected empty-list error, got %v", err)
		}
	})

	for _, tc := range []struct {
		name          string
		cause         error
		cancelContext bool
		wantAPICheck  func(error) bool
	}{
		{
			name:         "forbidden list error preserves cause",
			cause:        apierrors.NewForbidden(schema.GroupResource{Group: "networking.k8s.io", Resource: "servicecidrs"}, "", errors.New("denied")),
			wantAPICheck: apierrors.IsForbidden,
		},
		{
			name:         "unavailable API error preserves cause",
			cause:        apierrors.NewNotFound(schema.GroupResource{Group: "networking.k8s.io", Resource: "servicecidrs"}, ""),
			wantAPICheck: apierrors.IsNotFound,
		},
		{
			name:          "cancelled context preserves cause",
			cause:         context.Canceled,
			cancelContext: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			reader := serviceCIDRReader{list: func(context.Context, client.ObjectList) error {
				calls++
				return tc.cause
			}}
			ctx := context.Background()
			cancel := func() {}
			if tc.cancelContext {
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			defer cancel()
			err := ValidateEgressClusterNetworks(ctx, readerServiceCIDRSource{reader}, nil, []corev1.IPFamily{corev1.IPv4Protocol})
			if err == nil || !strings.Contains(err.Error(), "egress validation") || !errors.Is(err, tc.cause) {
				t.Fatalf("expected wrapped cause %v, got %v", tc.cause, err)
			}
			if calls != 1 {
				t.Fatalf("List called %d times, want 1", calls)
			}
			if tc.wantAPICheck != nil && !tc.wantAPICheck(err) {
				t.Fatalf("expected API error classification to survive wrapping, got %v", err)
			}
		})
	}
}

func TestValidateEgressClusterNetworksReadsUpdatedCIDRs(t *testing.T) {
	ctx := context.Background()
	service := &networkingv1.ServiceCIDR{
		Name: "services",
		Spec: networkingv1.ServiceCIDRSpec{CIDRs: []string{"10.96.0.0/16"}},
	}
	cached := fake.NewClientBuilder().WithScheme(serviceCIDRScheme(t)).WithObjects(service).Build()
	calls := 0
	reader := serviceCIDRReader{list: func(ctx context.Context, list client.ObjectList) error {
		calls++
		return cached.List(ctx, list)
	}}
	networks, err := ParseClusterNetworks([]string{"10.96.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateEgressClusterNetworks(ctx, readerServiceCIDRSource{reader}, networks, []corev1.IPFamily{corev1.IPv4Protocol}); err != nil {
		t.Fatalf("initial validation: %v", err)
	}
	service.Spec.CIDRs = []string{"10.96.0.0/16", "2001:db8::/64"}
	if err := cached.Update(ctx, service); err != nil {
		t.Fatal(err)
	}
	if err := ValidateEgressClusterNetworks(ctx, readerServiceCIDRSource{reader}, networks, []corev1.IPFamily{corev1.IPv4Protocol}); err != nil {
		t.Fatalf("validation after unrelated family update: %v", err)
	}
	if err := ValidateEgressClusterNetworks(ctx, readerServiceCIDRSource{reader}, networks, []corev1.IPFamily{corev1.IPv6Protocol}); err == nil || !strings.Contains(err.Error(), "2001:db8::/64") {
		t.Fatalf("expected uncovered IPv6 with changed selection, got %v", err)
	}

	service.Spec.CIDRs = []string{"10.97.0.0/16"}
	if err := cached.Update(ctx, service); err != nil {
		t.Fatal(err)
	}
	if err := ValidateEgressClusterNetworks(ctx, readerServiceCIDRSource{reader}, networks, []corev1.IPFamily{corev1.IPv4Protocol}); err == nil || !strings.Contains(err.Error(), "10.97.0.0/16") {
		t.Fatalf("expected updated uncovered ServiceCIDR error, got %v", err)
	}

	service.Spec.CIDRs = []string{"10.96.0.0/16"}
	if err := cached.Update(ctx, service); err != nil {
		t.Fatal(err)
	}
	if err := ValidateEgressClusterNetworks(ctx, readerServiceCIDRSource{reader}, networks, []corev1.IPFamily{corev1.IPv4Protocol}); err != nil {
		t.Fatalf("validation after restoring covered CIDR: %v", err)
	}
	if calls != 5 {
		t.Fatalf("List called %d times, want one per validation (5)", calls)
	}
}

func TestServiceCIDRCoverageSelectedFamilies(t *testing.T) {
	tests := []struct {
		name     string
		families []corev1.IPFamily
		cidrs    []string
		wantErr  string
	}{
		{name: "IPv4 ignores uncovered IPv6", families: []corev1.IPFamily{corev1.IPv4Protocol}, cidrs: []string{"10.96.0.0/16", "2001:db8::/64"}},
		{name: "IPv6 ignores uncovered IPv4", families: []corev1.IPFamily{corev1.IPv6Protocol}, cidrs: []string{"203.0.113.0/24", "fd00::/64"}},
		{name: "both families covered", families: []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol}, cidrs: []string{"10.96.0.0/16", "fd00::/64"}},
		{name: "both families require IPv4 coverage", families: []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol}, cidrs: []string{"203.0.113.0/24", "fd00::/64"}, wantErr: "203.0.113.0/24"},
		{name: "both families require IPv6 coverage", families: []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol}, cidrs: []string{"10.96.0.0/16", "2001:db8::/64"}, wantErr: "2001:db8::/64"},
		{name: "duplicate families", families: []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv4Protocol}, cidrs: []string{"10.96.0.0/16", "2001:db8::/64"}},
		{name: "nil selection needs no coverage", cidrs: []string{"203.0.113.0/24", "2001:db8::/64"}},
		{name: "empty selection skips empty discovery", families: []corev1.IPFamily{}},
		{name: "active family retains empty discovery safeguard", families: []corev1.IPFamily{corev1.IPv4Protocol}, wantErr: "no Service CIDR"},
		{name: "active family retains malformed discovery safeguard", families: []corev1.IPFamily{corev1.IPv4Protocol}, cidrs: []string{"10.96.0.0/16", "bad-prefix"}, wantErr: "bad-prefix"},
		{name: "active family retains mapped IPv6 safeguard", families: []corev1.IPFamily{corev1.IPv4Protocol}, cidrs: []string{"::ffff:192.0.2.0/120"}, wantErr: "IPv4-mapped"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var networks *ClusterNetworks
			err := networks.ValidateServiceCIDRs(tt.cidrs, tt.families)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("coverage validation: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("coverage validation error = %v, want %q", err, tt.wantErr)
			}
			calls := 0
			reader := serviceCIDRReader{list: func(_ context.Context, list client.ObjectList) error {
				calls++
				list.(*networkingv1.ServiceCIDRList).Items = []networkingv1.ServiceCIDR{{Spec: networkingv1.ServiceCIDRSpec{CIDRs: tt.cidrs}}}
				return nil
			}}
			err = ValidateEgressClusterNetworks(context.Background(), readerServiceCIDRSource{reader}, nil, tt.families)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("egress validation: %v", err)
				}
			} else if err == nil {
				t.Fatal("egress validation succeeded, want error")
			}
			wantCalls := 1
			if len(tt.families) == 0 {
				wantCalls = 0
			}
			if calls != wantCalls {
				t.Errorf("List calls = %d, want %d", calls, wantCalls)
			}
		})
	}
}

func TestGatewayFamilies(t *testing.T) {
	v4 := net.ParseIP("10.0.0.1")
	v4b := net.ParseIP("10.0.0.2")
	v6 := net.ParseIP("fd00::1")
	v6b := net.ParseIP("fd00::2")
	pod4 := net.ParseIP("10.1.0.5")
	pod6 := net.ParseIP("fd01::5")
	both := []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol}
	only4 := []corev1.IPFamily{corev1.IPv4Protocol}
	only6 := []corev1.IPFamily{corev1.IPv6Protocol}

	tests := []struct {
		name     string
		gateways []net.IP
		podV4    net.IP
		podV6    net.IP
		want     []corev1.IPFamily
	}{
		{"dual gateways dual pod", []net.IP{v6, v4, v4b, v6b}, pod4, pod6, both},
		{"dual gateways ipv4 pod", []net.IP{v4, v6}, pod4, nil, only4},
		{"dual gateways ipv6 pod", []net.IP{v6, v4}, nil, pod6, only6},
		{"ipv4 gateways ipv6 pod", []net.IP{v4, v4b}, nil, pod6, nil},
		{"ipv6 gateways ipv4 pod", []net.IP{v6, v6b}, pod4, nil, nil},
		{"dual gateways no pod addresses", []net.IP{v4, v6}, nil, nil, nil},
		{"nil gateways", nil, pod4, pod6, nil},
		{"empty gateways", []net.IP{}, pod4, pod6, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GatewayFamilies(tt.gateways, tt.podV4, tt.podV6)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GatewayFamilies() = %v, want %v", got, tt.want)
			}
		})
	}
}
