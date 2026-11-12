package netfilter

import (
	"net"
	"slices"
	"testing"
)

func TestParseClusterNetworks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		nets    []string
		wantErr bool
		v4Size  int
		v6Size  int
	}{
		{
			name:    "empty",
			nets:    []string{},
			wantErr: false,
			v4Size:  0,
			v6Size:  0,
		},
		{
			name:    "a few networks of each family",
			nets:    []string{"10.0.0.0/8", "fd00::/8", "172.16.0.0/12", "2001:db8::/32"},
			wantErr: false,
			v4Size:  2,
			v6Size:  2,
		},
		{
			name:    "only IPv4",
			nets:    []string{"10.0.0.0/8", "172.16.0.0/12"},
			wantErr: false,
			v4Size:  2,
			v6Size:  0,
		},
		{
			name:    "only IPv6",
			nets:    []string{"fd00::/8", "2001:db8::/32"},
			wantErr: false,
			v4Size:  0,
			v6Size:  2,
		},
		{
			name:    "invalid value",
			nets:    []string{"fd00::/8", "not a CIDR"},
			wantErr: true,
			v4Size:  0,
			v6Size:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			nets := tt.nets

			cn, err := ParseClusterNetworks(nets)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseClusterNetworks() error = %v, wantErr %v", err, tt.wantErr)
			}

			if cn != nil {
				if len(cn.v4) != tt.v4Size {
					t.Errorf("ParseClusterNetworks() invalid size of V4 slice, want %d, got %d", tt.v4Size, len(cn.v4))
				}

				if len(cn.v6) != tt.v6Size {
					t.Errorf("ParseClusterNetworks() invalid size of V6 slice, want %d, got %d", tt.v6Size, len(cn.v6))
				}
			}
		})
	}
}

func TestEffectiveClusterNetworks(t *testing.T) {
	t.Parallel()

	parse := func(t *testing.T, cidrs ...string) *ClusterNetworks {
		t.Helper()
		cn, err := ParseClusterNetworks(cidrs)
		if err != nil {
			t.Fatal(err)
		}
		return cn
	}

	tests := []struct {
		name string
		cn   *ClusterNetworks
		v4   []string
		v6   []string
	}{
		{
			name: "nil uses defaults",
			v4:   []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			v6:   []string{"fc00::/7"},
		},
		{
			name: "zero config uses defaults and stays empty",
			cn:   &ClusterNetworks{},
			v4:   []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			v6:   []string{"fc00::/7"},
		},
		{
			name: "IPv4 override preserves IPv6 defaults",
			cn:   parse(t, "100.64.0.0/10"),
			v4:   []string{"100.64.0.0/10"},
			v6:   []string{"fc00::/7"},
		},
		{
			name: "IPv6 override preserves IPv4 defaults",
			cn:   parse(t, "2001:db8::/32"),
			v4:   []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			v6:   []string{"2001:db8::/32"},
		},
		{
			name: "both families overridden",
			cn:   parse(t, "100.64.0.0/10", "2001:db8::/32"),
			v4:   []string{"100.64.0.0/10"},
			v6:   []string{"2001:db8::/32"},
		},
		{
			name: "custom order and duplicates are preserved",
			cn:   parse(t, "100.64.0.0/10", "100.64.0.0/10", "198.18.0.0/15", "2001:db8:1::/48", "2001:db8::/32"),
			v4:   []string{"100.64.0.0/10", "100.64.0.0/10", "198.18.0.0/15"},
			v6:   []string{"2001:db8:1::/48", "2001:db8::/32"},
		},
		{
			name: "explicit empty slices use defaults",
			cn:   &ClusterNetworks{v4: []*net.IPNet{}, v6: []*net.IPNet{}},
			v4:   []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			v6:   []string{"fc00::/7"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var rawV4, rawV6 []string
			var rawEmpty bool
			if tt.cn != nil {
				rawV4 = ipNetStrings(tt.cn.v4)
				rawV6 = ipNetStrings(tt.cn.v6)
				rawEmpty = tt.cn.IsEmpty()
			}
			effective := effectiveClusterNetworks(tt.cn)
			if effective == tt.cn {
				t.Fatal("effectiveClusterNetworks returned the input wrapper")
			}
			if got := ipNetStrings(effective.v4); !slices.Equal(got, tt.v4) {
				t.Errorf("IPv4 networks = %v, want %v", got, tt.v4)
			}
			if got := ipNetStrings(effective.v6); !slices.Equal(got, tt.v6) {
				t.Errorf("IPv6 networks = %v, want %v", got, tt.v6)
			}
			if tt.cn != nil {
				if got := ipNetStrings(tt.cn.v4); !slices.Equal(got, rawV4) {
					t.Errorf("raw IPv4 networks changed to %v, want %v", got, rawV4)
				}
				if got := ipNetStrings(tt.cn.v6); !slices.Equal(got, rawV6) {
					t.Errorf("raw IPv6 networks changed to %v, want %v", got, rawV6)
				}
				if got := tt.cn.IsEmpty(); got != rawEmpty {
					t.Errorf("raw IsEmpty() = %v, want %v", got, rawEmpty)
				}
			}
		})
	}
}

func ipNetStrings(nets []*net.IPNet) []string {
	result := make([]string, 0, len(nets))
	for _, n := range nets {
		result = append(result, n.String())
	}
	return result
}

func TestClusterNetworksValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cn      *ClusterNetworks
		wantErr bool
	}{
		{
			name:    "empty",
			cn:      &ClusterNetworks{},
			wantErr: false,
		},
		{
			name: "a few networks of each family",
			cn: &ClusterNetworks{
				v4: make([]*net.IPNet, 2),
				v6: make([]*net.IPNet, 2),
			},
			wantErr: false,
		},
		{
			name: "exactly at the IPv4 limit",
			cn: &ClusterNetworks{
				v4: make([]*net.IPNet, MaxInClusterNetworks),
				v6: make([]*net.IPNet, 0),
			},
			wantErr: false,
		},
		{
			name: "exactly at the IPv6 limit",
			cn: &ClusterNetworks{
				v4: make([]*net.IPNet, 0),
				v6: make([]*net.IPNet, MaxInClusterNetworks),
			},
			wantErr: false,
		},
		{
			name: "exceeds the IPv4 limit",
			cn: &ClusterNetworks{
				v4: make([]*net.IPNet, MaxInClusterNetworks+1),
				v6: make([]*net.IPNet, 0),
			},
			wantErr: true,
		},
		{
			name: "exceeds the IPv6 limit",
			cn: &ClusterNetworks{
				v4: make([]*net.IPNet, 0),
				v6: make([]*net.IPNet, MaxInClusterNetworks+1),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cn := tt.cn
			err := cn.validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateClusterNetworks() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
