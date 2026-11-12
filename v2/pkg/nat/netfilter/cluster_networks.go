package netfilter

import (
	"fmt"
	"net"
)

type ClusterNetworks struct {
	v4 []*net.IPNet
	v6 []*net.IPNet
}

var (
	v4PrivateList = []*net.IPNet{
		{IP: net.ParseIP("10.0.0.0").To4(), Mask: net.CIDRMask(8, 32)},
		{IP: net.ParseIP("172.16.0.0").To4(), Mask: net.CIDRMask(12, 32)},
		{IP: net.ParseIP("192.168.0.0").To4(), Mask: net.CIDRMask(16, 32)},
	}
	v6PrivateList = []*net.IPNet{
		{IP: net.ParseIP("fc00::"), Mask: net.CIDRMask(7, 128)},
	}
)

// effectiveClusterNetworks returns the configured networks with defaults for
// any family that has no configured networks.
func effectiveClusterNetworks(cn *ClusterNetworks) *ClusterNetworks {
	effective := &ClusterNetworks{v4: v4PrivateList, v6: v6PrivateList}
	if cn != nil {
		if len(cn.v4) > 0 {
			effective.v4 = cn.v4
		}
		if len(cn.v6) > 0 {
			effective.v6 = cn.v6
		}
	}
	return effective
}

func (cn *ClusterNetworks) IsEmpty() bool {
	return len(cn.v4) == 0 && len(cn.v6) == 0
}

// ParseClusterNetworks parses --cluster-networks CIDR strings into net.IPNet values.
func ParseClusterNetworks(cidrs []string) (*ClusterNetworks, error) {
	var v4, v6 []*net.IPNet
	for _, s := range cidrs {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		if n.IP.To4() != nil {
			v4 = append(v4, n)
		} else {
			v6 = append(v6, n)
		}
	}

	cn := &ClusterNetworks{
		v4: v4,
		v6: v6,
	}

	if err := cn.validate(); err != nil {
		return nil, fmt.Errorf("cluster networks validation failed: %w", err)
	}

	return cn, nil
}

// validate checks that clusterNetworks does not exceed
// MaxInClusterNetworks entries per IP family.
func (cn *ClusterNetworks) validate() error {
	if len(cn.v4) > MaxInClusterNetworks {
		return fmt.Errorf("too many IPv4 cluster networks: %d (max %d)", len(cn.v4), MaxInClusterNetworks)
	}
	if len(cn.v6) > MaxInClusterNetworks {
		return fmt.Errorf("too many IPv6 cluster networks: %d (max %d)", len(cn.v6), MaxInClusterNetworks)
	}
	return nil
}
