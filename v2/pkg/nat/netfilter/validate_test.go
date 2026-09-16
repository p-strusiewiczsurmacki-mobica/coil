package netfilter

import (
	"net"
	"testing"
)

func cidrs(t *testing.T, ss ...string) []*net.IPNet {
	t.Helper()
	var nets []*net.IPNet
	for _, s := range ss {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatalf("invalid CIDR %q: %v", s, err)
		}
		nets = append(nets, n)
	}
	return nets
}

func TestValidateClusterNetworks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		nets    []*net.IPNet
		wantErr bool
	}{
		{
			name:    "empty",
			nets:    nil,
			wantErr: false,
		},
		{
			name:    "a few networks of each family",
			nets:    cidrs(t, "10.0.0.0/8", "172.16.0.0/12", "fd00::/8", "2001:db8::/32"),
			wantErr: false,
		},
		{
			name:    "exactly at the IPv4 limit",
			nets:    make([]*net.IPNet, MaxInClusterNetworks),
			wantErr: false,
		},
		{
			name:    "exceeds the IPv4 limit",
			nets:    make([]*net.IPNet, MaxInClusterNetworks+1),
			wantErr: true,
		},
	}

	// make([]*net.IPNet, n) above yields nil entries; fill with distinct
	// IPv4 /32 networks so the per-family counting logic under test is exercised.
	fillV4 := func(nets []*net.IPNet) []*net.IPNet {
		for i := range nets {
			ip := net.IPv4(10, 0, byte(i>>8), byte(i))
			nets[i] = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		}
		return nets
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			nets := tt.nets
			if tt.name == "exactly at the IPv4 limit" || tt.name == "exceeds the IPv4 limit" {
				nets = fillV4(nets)
			}
			err := ValidateClusterNetworks(nets)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateClusterNetworks() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateClusterNetworksIPv6Limit(t *testing.T) {
	t.Parallel()

	var nets []*net.IPNet
	for i := range MaxInClusterNetworks {
		ip := net.ParseIP("2001:db8::")
		ip[14] = byte(i >> 8)
		ip[15] = byte(i)
		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
	}
	if err := ValidateClusterNetworks(nets); err != nil {
		t.Errorf("ValidateClusterNetworks() at limit should succeed, got error = %v", err)
	}

	ip := net.ParseIP("2001:db8::ffff")
	nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
	if err := ValidateClusterNetworks(nets); err == nil {
		t.Errorf("ValidateClusterNetworks() exceeding IPv6 limit should fail, got nil")
	}
}
