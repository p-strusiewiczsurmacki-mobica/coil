package netfilter

import (
	"fmt"
	"net"
)

type ClusterNetworks struct {
	v4 []*net.IPNet
	v6 []*net.IPNet
}

func (cn *ClusterNetworks) IsEmpty() bool {
	return len(cn.v4) == 0 && len(cn.v6) == 0
}

func (cn *ClusterNetworks) Add(toAdd *ClusterNetworks) {
	if toAdd == nil {
		return
	}

	if cn.v4 == nil {
		cn.v4 = make([]*net.IPNet, 0)
	}
	if cn.v6 == nil {
		cn.v6 = make([]*net.IPNet, 0)
	}

	if len(toAdd.v4) > 0 {
		cn.v4 = append(cn.v4, toAdd.v4...)
	}
	if len(toAdd.v6) > 0 {
		cn.v6 = append(cn.v6, toAdd.v6...)
	}
}

// parseClusterNetworks parses --cluster-networks CIDR strings into net.IPNet values.
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
	return &ClusterNetworks{v4, v6}, nil
}

// ValidateClusterNetworks checks that clusterNetworks does not exceed
// MaxInClusterNetworks entries per IP family. Each in-cluster network consumes
// one rule priority starting at ncLocalPrioBase; exceeding the limit would
// collide with the ncWidePrio rule and silently break the wide (default route)
// NAT path.
func ValidateClusterNetworks(clusterNetworks *ClusterNetworks) error {
	var v4Count, v6Count int

	if len(clusterNetworks.v4) > MaxInClusterNetworks {
		return fmt.Errorf("too many IPv4 cluster networks: %d (max %d)", v4Count, MaxInClusterNetworks)
	}
	if len(clusterNetworks.v6) > MaxInClusterNetworks {
		return fmt.Errorf("too many IPv6 cluster networks: %d (max %d)", v6Count, MaxInClusterNetworks)
	}
	return nil
}
