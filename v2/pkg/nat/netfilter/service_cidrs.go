package netfilter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ValidateServiceCIDRs checks that the effective cluster networks cover every
// Service CIDR. A nil ClusterNetworks receiver uses the configured defaults.
func (cn *ClusterNetworks) ValidateServiceCIDRs(cidrs []string) error {
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

const serviceCIDRDiscoveryTimeout = 10 * time.Second

var (
	serviceCIDRPollInterval = 2 * time.Second
	serviceCIDRPollTimeout  = 60 * time.Second
)

// +kubebuilder:rbac:groups=networking.k8s.io,resources=servicecidrs,verbs=list;watch

// discoverServiceCIDRs reads every ServiceCIDR from the manager's cached client.
// The first read starts a cluster-wide informer, which needs list and watch
// permissions on ServiceCIDR.
func discoverServiceCIDRs(ctx context.Context, reader client.Reader) ([]string, error) {
	var list networkingv1.ServiceCIDRList
	var lastErr error
	err := wait.PollUntilContextTimeout(ctx, serviceCIDRPollInterval, serviceCIDRPollTimeout, true,
		func(ctx context.Context) (bool, error) {
			reqCtx, cancel := context.WithTimeout(ctx, serviceCIDRDiscoveryTimeout)
			defer cancel()
			lastErr = reader.List(reqCtx, &list)
			return lastErr == nil, nil
		})
	if err != nil {
		if lastErr != nil {
			return nil, fmt.Errorf("list networking.k8s.io/v1 ServiceCIDRs: %w; last API error: %w", err, lastErr)
		}
		return nil, fmt.Errorf("list networking.k8s.io/v1 ServiceCIDRs: %w", err)
	}

	if ctx.Err() != nil {
		return nil, fmt.Errorf("list networking.k8s.io/v1 ServiceCIDRs: context error: %w", ctx.Err())
	}

	if len(list.Items) == 0 {
		return nil, errors.New("list networking.k8s.io/v1 ServiceCIDRs: no ServiceCIDR objects found")
	}

	cidrs := make([]string, 0, len(list.Items))
	for _, item := range list.Items {
		if len(item.Spec.CIDRs) == 0 {
			return nil, fmt.Errorf("ServiceCIDR %q has no CIDRs", item.Name)
		}
		cidrs = append(cidrs, item.Spec.CIDRs...)
	}
	return cidrs, nil
}

// ValidateEgressClusterNetworks returns a function that checks the ServiceCIDRs
// are covered by the configured cluster networks. Discovery runs each time the
// returned function is called, and the callers invoke it before configuring
// Egress NAT, not at startup.
func ValidateEgressClusterNetworks(reader client.Reader, networks *ClusterNetworks) func(context.Context) error {
	return func(ctx context.Context) error {
		cidrs, err := discoverServiceCIDRs(ctx, reader)
		if err != nil {
			return fmt.Errorf("egress validation: discover ServiceCIDRs: %w", err)
		}

		if err := networks.ValidateServiceCIDRs(cidrs); err != nil {
			return fmt.Errorf("egress validation: check ServiceCIDR coverage: %w", err)
		}
		return nil
	}
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
