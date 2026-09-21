package netfilter

import (
	"net"
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
					t.Errorf("ParseClusterNetworks() invalid size of V4 slice, want %d, got %d", tt.v6Size, len(cn.v6))
				}
			}
		})
	}
}

func TestAddClusterNetworks(t *testing.T) {
	t.Parallel()

	type testCNet struct {
		cNet *ClusterNetworks
		size int
	}

	newTestCNet := func(s int) *testCNet {
		return &testCNet{
			cNet: &ClusterNetworks{
				v4: make([]*net.IPNet, s),
				v6: make([]*net.IPNet, s),
			},
			size: s,
		}
	}

	cNets := []*testCNet{}
	for i := range 3 {
		cNets = append(cNets, newTestCNet(i+1))
	}

	tests := []struct {
		name  string
		cNets []*testCNet
	}{
		{
			name:  "Simple ClusterNetwork concatenation",
			cNets: cNets,
		},
	}

	expected := 0

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			for i := range tt.cNets {
				if i > 0 {
					tt.cNets[0].cNet.Add(tt.cNets[i].cNet)
				}
				expected += tt.cNets[i].size

				if len(tt.cNets[0].cNet.v4) != expected {
					t.Errorf("cNets[0].v4 size, expected %d, got %d", expected, len(tt.cNets[0].cNet.v4))
				}
				if len(tt.cNets[0].cNet.v6) != expected {
					t.Errorf("cNets[0].v6 size, expected %d, got %d", expected, len(tt.cNets[0].cNet.v6))
				}
			}
		})
	}
}

func TestValidateClusterNetworks(t *testing.T) {
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
			err := ValidateClusterNetworks(cn)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateClusterNetworks() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
