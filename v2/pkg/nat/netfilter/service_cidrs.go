package netfilter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	informersv1 "k8s.io/client-go/informers/networking/v1"
	"k8s.io/client-go/kubernetes"
	listersnetworkingv1 "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"
)

// ValidateServiceCIDRs checks that the effective cluster networks cover every
// Service CIDR in the selected families. An empty family selection requires no
// coverage. A nil ClusterNetworks receiver uses the configured defaults.
func (cn *ClusterNetworks) ValidateServiceCIDRs(cidrs []string, families []corev1.IPFamily) error {
	if len(families) == 0 {
		return nil
	}
	var checkV4, checkV6 bool
	for _, family := range families {
		if family == corev1.IPv4Protocol {
			checkV4 = true
		}
		if family == corev1.IPv6Protocol {
			checkV6 = true
		}
	}
	if len(cidrs) == 0 {
		return errors.New("no Service CIDRs were discovered")
	}
	effective := effectiveClusterNetworks(cn)
	v4, err := prefixesFromIPNets(effective.v4)
	if err != nil {
		return fmt.Errorf("invalid IPv4 cluster network: %w", err)
	}
	v6, err := prefixesFromIPNets(effective.v6)
	if err != nil {
		return fmt.Errorf("invalid IPv6 cluster network: %w", err)
	}
	for _, original := range cidrs {
		p, err := netip.ParsePrefix(original)
		if err != nil {
			return fmt.Errorf("invalid Service CIDR %q: %w", original, err)
		}
		if p.Addr().Is4In6() {
			return fmt.Errorf("invalid Service CIDR %q: IPv4-mapped IPv6 prefixes are unsupported", original)
		}
		if (p.Addr().Is4() && !checkV4) || (p.Addr().Is6() && !checkV6) {
			continue
		}
		p = p.Masked()
		candidates := v6
		if p.Addr().Is4() {
			candidates = v4
		}
		if !prefixUnionCovers(p, candidates) {
			return fmt.Errorf("service CIDR %q is not covered by --cluster-networks", original)
		}
	}
	return nil
}

// +kubebuilder:rbac:groups=networking.k8s.io,resources=servicecidrs,verbs=list;watch

// ValidateEgressClusterNetworks checks that the ServiceCIDRs in the selected
// families are covered by the configured cluster networks before configuring
// Egress NAT. An empty selection needs no validation; nil networks uses defaults.
func ValidateEgressClusterNetworks(ctx context.Context, source ServiceCIDRSource, networks *ClusterNetworks, families []corev1.IPFamily) error {
	if len(families) == 0 {
		return nil
	}
	if source == nil {
		return errors.New("egress validation: ServiceCIDR source is not configured")
	}
	cidrs, err := source.Discover(ctx)
	if err != nil {
		return fmt.Errorf("egress validation: discover ServiceCIDRs: %w", err)
	}

	if err := networks.ValidateServiceCIDRs(cidrs, families); err != nil {
		return fmt.Errorf("egress validation: check ServiceCIDR coverage: %w", err)
	}
	return nil
}

func prefixesFromIPNets(nets []*net.IPNet) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(nets))
	for _, n := range nets {
		if n == nil {
			return nil, errors.New("nil network")
		}
		p, err := netip.ParsePrefix(n.String())
		if err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// prefixUnionCovers determines whether the union of prefixes contains target.
// It recursively splits only branches intersected by a candidate, so even /0
// inputs cost at most the address width times the number of relevant prefixes.
func prefixUnionCovers(target netip.Prefix, candidates []netip.Prefix) bool {
	relevant := make([]netip.Prefix, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Addr().Is4() != target.Addr().Is4() {
			continue
		}
		candidate = candidate.Masked()
		if candidate.Bits() <= target.Bits() && candidate.Contains(target.Addr()) {
			return true
		}
		if target.Contains(candidate.Addr()) {
			relevant = append(relevant, candidate)
		}
	}
	return prefixUnionCoversRelevant(target, relevant)
}

func prefixUnionCoversRelevant(target netip.Prefix, candidates []netip.Prefix) bool {
	if len(candidates) == 0 {
		return false
	}
	for _, candidate := range candidates {
		if candidate.Bits() <= target.Bits() && candidate.Contains(target.Addr()) {
			return true
		}
	}
	width := 128
	if target.Addr().Is4() {
		width = 32
	}
	if target.Bits() >= width {
		return false
	}
	left, right := splitPrefix(target)
	var leftCandidates, rightCandidates []netip.Prefix
	for _, candidate := range candidates {
		if left.Contains(candidate.Addr()) {
			leftCandidates = append(leftCandidates, candidate)
		}
		if right.Contains(candidate.Addr()) {
			rightCandidates = append(rightCandidates, candidate)
		}
	}
	return prefixUnionCoversRelevant(left, leftCandidates) && prefixUnionCoversRelevant(right, rightCandidates)
}

func splitPrefix(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	childBits := p.Bits() + 1
	left := netip.PrefixFrom(p.Masked().Addr(), childBits)
	addr := p.Masked().Addr()
	if addr.Is4() {
		b := addr.As4()
		b[p.Bits()/8] |= byte(1 << (7 - uint(p.Bits()%8)))
		addr = netip.AddrFrom4(b)
	} else {
		b := addr.As16()
		b[p.Bits()/8] |= byte(1 << (7 - uint(p.Bits()%8)))
		addr = netip.AddrFrom16(b)
	}
	return left, netip.PrefixFrom(addr, childBits)
}

var (
	// ErrServiceCIDRNotReady is returned by Discover before the ServiceCIDR
	// informer has completed its initial synchronization.
	ErrServiceCIDRNotReady = errors.New("ServiceCIDR informer has not synchronized (check that the networking.k8s.io/v1 ServiceCIDR API is served and RBAC allows list/watch on servicecidrs; see coild logs)")
	// ErrNoServiceCIDRs is returned by Discover if no service CIDRs were found in the cluster
	ErrNoServiceCIDRs = errors.New("no ServiceCIDR objects are available")
)

// ServiceCIDRSource provides the Service CIDRs used for egress validation.
// Discover returns promptly with an error before the source's initial data
// is synchronized; it must not wait for synchronization. Once synchronized,
// it returns all CIDRs from all ServiceCIDR objects and reports errors for an
// empty ServiceCIDR set, an object without CIDRs, or a discovery failure.
// Discover should honor context cancellation.
type ServiceCIDRSource interface {
	Discover(ctx context.Context) ([]string, error)
}

// ServiceCIDRInformerSource discovers Service CIDRs using its own client-go
// informer. It is deliberately independent of the controller-runtime manager's
// cache, so it can read ServiceCIDRs without API resource discovery.
type ServiceCIDRInformerSource struct {
	informer cache.SharedIndexInformer
	lister   listersnetworkingv1.ServiceCIDRLister
}

// NewServiceCIDRInformerSource creates an independent typed ServiceCIDR
// informer and its lister. The informer is started by the manager through
// Start; callers must not start it separately. Client-go's default error
// handler logs list/watch failures.
func NewServiceCIDRInformerSource(client kubernetes.Interface) *ServiceCIDRInformerSource {
	informer := informersv1.NewServiceCIDRInformer(client, 0, cache.Indexers{})
	return &ServiceCIDRInformerSource{
		informer: informer,
		lister:   listersnetworkingv1.NewServiceCIDRLister(informer.GetIndexer()),
	}
}

// Start runs the informer until the manager cancels ctx. It intentionally does
// not wait for initial synchronization: the manager can become ready while
// Discover reports that the informer is not ready yet.
func (s *ServiceCIDRInformerSource) Start(ctx context.Context) error {
	s.informer.RunWithContext(ctx)
	return nil
}

// NeedLeaderElection allows this read-only informer to run on every replica.
func (s *ServiceCIDRInformerSource) NeedLeaderElection() bool { return false }

// Discover returns a snapshot of all ServiceCIDR CIDRs currently in the
// informer cache. It returns ErrServiceCIDRNotReady immediately before initial
// synchronization and reports an error if the snapshot is invalid.
func (s *ServiceCIDRInformerSource) Discover(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !s.informer.HasSynced() {
		return nil, ErrServiceCIDRNotReady
	}

	objects, err := s.lister.List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("list ServiceCIDRs from informer cache: %w", err)
	}

	if len(objects) == 0 {
		return nil, ErrNoServiceCIDRs
	}

	var cidrs []string
	for _, object := range objects {
		if len(object.Spec.CIDRs) == 0 {
			return nil, fmt.Errorf("ServiceCIDR %q has no CIDRs", object.Name)
		}
		cidrs = append(cidrs, object.Spec.CIDRs...)
	}

	return cidrs, nil
}
