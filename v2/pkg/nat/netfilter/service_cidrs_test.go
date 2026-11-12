package netfilter

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
			err := cn.ValidateServiceCIDRs(tt.services)
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
	if err := cn.ValidateServiceCIDRs(cidrs); err != nil {
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

func (r serviceCIDRReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if r.list != nil {
		return r.list(ctx, list)
	}
	return r.Reader.List(ctx, list, opts...)
}

// shortenServiceCIDRPolling makes the retry budget small so error-path tests
// finish quickly. It changes package variables, so tests that call it must not
// run in parallel.
func shortenServiceCIDRPolling(t *testing.T) {
	t.Helper()
	interval, timeout := serviceCIDRPollInterval, serviceCIDRPollTimeout
	serviceCIDRPollInterval = time.Millisecond
	serviceCIDRPollTimeout = 50 * time.Millisecond
	t.Cleanup(func() {
		serviceCIDRPollInterval, serviceCIDRPollTimeout = interval, timeout
	})
}

func serviceCIDRScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := networkingv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDiscoverServiceCIDRs(t *testing.T) {
	tests := []struct {
		name    string
		objects []client.Object
		want    []string
	}{
		{
			name: "dual stack object",
			//nolint:modernize
			objects: []client.Object{&networkingv1.ServiceCIDR{
				ObjectMeta: metav1.ObjectMeta{Name: "dual"},
				Spec:       networkingv1.ServiceCIDRSpec{CIDRs: []string{"10.96.0.0/16", "fd00:1234::/108"}},
			}},
			want: []string{"10.96.0.0/16", "fd00:1234::/108"},
		},
		{
			name: "multiple objects and CIDRs",
			//nolint:modernize
			objects: []client.Object{
				&networkingv1.ServiceCIDR{ObjectMeta: metav1.ObjectMeta{Name: "second"}, Spec: networkingv1.ServiceCIDRSpec{CIDRs: []string{"10.97.0.0/16", "fd00:5678::/108"}}},
				&networkingv1.ServiceCIDR{ObjectMeta: metav1.ObjectMeta{Name: "first"}, Spec: networkingv1.ServiceCIDRSpec{CIDRs: []string{"10.96.0.0/16"}}},
			},
			want: []string{"10.96.0.0/16", "10.97.0.0/16", "fd00:5678::/108"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(serviceCIDRScheme(t)).WithObjects(tt.objects...).Build()
			got, err := discoverServiceCIDRs(context.Background(), c)
			if err != nil {
				t.Fatal(err)
			}
			sort.Strings(got)
			sort.Strings(tt.want)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("discoverServiceCIDRs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDiscoverServiceCIDRsRejectsEmptyResults(t *testing.T) {
	t.Run("empty list", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(serviceCIDRScheme(t)).Build()
		if _, err := discoverServiceCIDRs(context.Background(), c); err == nil {
			t.Fatal("expected error for empty ServiceCIDR list")
		}
	})

	t.Run("empty object CIDRs", func(t *testing.T) {
		//nolint:modernize
		obj := &networkingv1.ServiceCIDR{ObjectMeta: metav1.ObjectMeta{Name: "empty"}}
		c := fake.NewClientBuilder().WithScheme(serviceCIDRScheme(t)).WithObjects(obj).Build()
		if _, err := discoverServiceCIDRs(context.Background(), c); err == nil || !strings.Contains(err.Error(), "empty") {
			t.Fatalf("expected error naming empty ServiceCIDR, got %v", err)
		}
	})
}

func TestDiscoverServiceCIDRsWrapsListErrors(t *testing.T) {
	shortenServiceCIDRPolling(t)

	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "forbidden", err: apierrors.NewForbidden(schema.GroupResource{Group: "networking.k8s.io", Resource: "servicecidrs"}, "", errors.New("denied"))},
		{name: "unavailable API", err: apierrors.NewNotFound(schema.GroupResource{Group: "networking.k8s.io", Resource: "servicecidrs"}, "")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := serviceCIDRReader{list: func(context.Context, client.ObjectList) error { return tc.err }}
			_, err := discoverServiceCIDRs(context.Background(), reader)
			if err == nil || !errors.Is(err, tc.err) {
				t.Fatalf("expected wrapped %v, got %v", tc.err, err)
			}
		})
	}
}

func TestDiscoverServiceCIDRsRetries(t *testing.T) {
	shortenServiceCIDRPolling(t)

	resetList := func(_ context.Context, list client.ObjectList) {
		//nolint:modernize
		list.(*networkingv1.ServiceCIDRList).Items = []networkingv1.ServiceCIDR{{
			ObjectMeta: metav1.ObjectMeta{Name: "ok"},
			Spec:       networkingv1.ServiceCIDRSpec{CIDRs: []string{"10.96.0.0/16"}},
		}}
	}
	forbidden := apierrors.NewForbidden(schema.GroupResource{Group: "networking.k8s.io", Resource: "servicecidrs"}, "", errors.New("denied"))

	t.Run("transient errors are retried until success", func(t *testing.T) {
		calls := 0
		reader := serviceCIDRReader{list: func(ctx context.Context, list client.ObjectList) error {
			calls++
			if calls <= 2 {
				return apierrors.NewServiceUnavailable("busy")
			}
			resetList(ctx, list)
			return nil
		}}
		got, err := discoverServiceCIDRs(context.Background(), reader)
		if err != nil {
			t.Fatal(err)
		}
		if calls != 3 {
			t.Fatalf("List called %d times, want 3", calls)
		}
		if want := []string{"10.96.0.0/16"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("discoverServiceCIDRs() = %v, want %v", got, want)
		}
	})

	// Forbidden is retried too: RBAC can lag behind a DaemonSet rollout.
	t.Run("forbidden is retried until the budget runs out", func(t *testing.T) {
		calls := 0
		reader := serviceCIDRReader{list: func(context.Context, client.ObjectList) error {
			calls++
			return forbidden
		}}
		_, err := discoverServiceCIDRs(context.Background(), reader)
		if !errors.Is(err, forbidden) {
			t.Fatalf("expected wrapped forbidden error, got %v", err)
		}
		if calls < 2 {
			t.Fatalf("List called %d times, want retries before giving up", calls)
		}
	})
}

func TestDiscoverServiceCIDRsContext(t *testing.T) {
	t.Run("bounded timeout", func(t *testing.T) {
		reader := serviceCIDRReader{list: func(ctx context.Context, list client.ObjectList) error {
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Fatal("List context has no deadline")
			}
			remaining := time.Until(deadline)
			if remaining <= 0 || remaining > serviceCIDRDiscoveryTimeout {
				t.Fatalf("List deadline has unexpected remaining duration %v", remaining)
			}
			//nolint:modernize
			list.(*networkingv1.ServiceCIDRList).Items = []networkingv1.ServiceCIDR{{ObjectMeta: metav1.ObjectMeta{Name: "ok"}, Spec: networkingv1.ServiceCIDRSpec{CIDRs: []string{"10.96.0.0/16"}}}}
			return nil
		}}
		_, err := discoverServiceCIDRs(context.Background(), reader)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("earlier parent deadline", func(t *testing.T) {
		parentDeadline := time.Now().Add(2 * time.Second)
		parent, cancel := context.WithDeadline(context.Background(), parentDeadline)
		defer cancel()
		reader := serviceCIDRReader{list: func(ctx context.Context, list client.ObjectList) error {
			deadline, ok := ctx.Deadline()
			if !ok || !deadline.Equal(parentDeadline) {
				t.Fatalf("List deadline = %v, %v; want parent deadline %v", deadline, ok, parentDeadline)
			}
			//nolint:modernize
			list.(*networkingv1.ServiceCIDRList).Items = []networkingv1.ServiceCIDR{{ObjectMeta: metav1.ObjectMeta{Name: "ok"}, Spec: networkingv1.ServiceCIDRSpec{CIDRs: []string{"10.96.0.0/16"}}}}
			return nil
		}}
		if _, err := discoverServiceCIDRs(parent, reader); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("pre-cancelled parent", func(t *testing.T) {
		parent, cancel := context.WithCancel(context.Background())
		cancel()
		reader := serviceCIDRReader{list: func(ctx context.Context, _ client.ObjectList) error { return ctx.Err() }}
		_, err := discoverServiceCIDRs(parent, reader)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected wrapped context.Canceled, got %v", err)
		}
	})

	t.Run("expired parent deadline", func(t *testing.T) {
		parent, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		reader := serviceCIDRReader{list: func(ctx context.Context, _ client.ObjectList) error { return ctx.Err() }}
		_, err := discoverServiceCIDRs(parent, reader)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected wrapped context.DeadlineExceeded, got %v", err)
		}
	})
}

func TestValidateEgressClusterNetworks(t *testing.T) {
	shortenServiceCIDRPolling(t)

	service := func(name string, cidrs ...string) client.Object {
		//nolint:modernize
		return &networkingv1.ServiceCIDR{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       networkingv1.ServiceCIDRSpec{CIDRs: cidrs},
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
				//nolint:modernize
				&networkingv1.ServiceCIDR{ObjectMeta: metav1.ObjectMeta{Name: "z-empty-object"}},
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
			f := ValidateEgressClusterNetworks(reader, networks)
			err = f(context.Background())
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
		f := ValidateEgressClusterNetworks(reader, nil)
		err := f(context.Background())
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
			reader := serviceCIDRReader{list: func(ctx context.Context, _ client.ObjectList) error {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return tc.cause
			}}
			ctx := context.Background()
			cancel := func() {}
			if tc.cancelContext {
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			defer cancel()
			f := ValidateEgressClusterNetworks(reader, nil)
			err := f(ctx)
			if err == nil || !strings.Contains(err.Error(), "egress validation") || !errors.Is(err, tc.cause) {
				t.Fatalf("expected wrapped cause %v, got %v", tc.cause, err)
			}
			if tc.wantAPICheck != nil && !tc.wantAPICheck(err) {
				t.Fatalf("expected API error classification to survive wrapping, got %v", err)
			}
		})
	}
}
