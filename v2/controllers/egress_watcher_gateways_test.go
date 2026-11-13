package controllers

import (
	"net"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	coilv2 "github.com/cybozu-go/coil/v2/api/v2"
)

type wantGateway struct {
	gateway  string
	networks []string
}

func networkStrings(nets []*net.IPNet) []string {
	var out []string
	for _, n := range nets {
		out = append(out, n.String())
	}
	return out
}

func TestGatewayNetworks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		destinations    []string
		clusterIPs      []string
		fouSportAuto    bool
		originatingOnly bool
		wantErr         string
		want            []wantGateway
	}{
		{
			// Guards that IPv6 destinations are not attached to an IPv4 gateway.
			name:         "IPv4-only Service",
			destinations: []string{"10.0.0.0/8", "2001:db8::/32"},
			clusterIPs:   []string{"10.96.0.10"},
			want: []wantGateway{
				{gateway: "10.96.0.10", networks: []string{"10.0.0.0/8"}},
			},
		},
		{
			// Guards that IPv4 destinations are not attached to an IPv6 gateway.
			name:         "IPv6-only Service",
			destinations: []string{"10.0.0.0/8", "2001:db8::/32"},
			clusterIPs:   []string{"fd00::10"},
			want: []wantGateway{
				{gateway: "fd00::10", networks: []string{"2001:db8::/32"}},
			},
		},
		{
			// Regression guard: a dual-stack Service whose destinations are IPv4 only
			// must still produce an IPv6 gateway (with no networks), so that a stale
			// IPv6 FoU tunnel can be removed by the hook.
			name:         "dual-stack Service with IPv4-only destinations",
			destinations: []string{"10.0.0.0/8"},
			clusterIPs:   []string{"10.96.0.10", "fd00::10"},
			want: []wantGateway{
				{gateway: "10.96.0.10", networks: []string{"10.0.0.0/8"}},
				{gateway: "fd00::10", networks: nil},
			},
		},
		{
			// Each gateway only receives destinations of its own IP family.
			name:         "dual-stack Service with IPv4 and IPv6 destinations",
			destinations: []string{"10.0.0.0/8", "2001:db8::/32", "172.16.0.0/12", "fd00::/8"},
			clusterIPs:   []string{"10.96.0.10", "fd00::10"},
			want: []wantGateway{
				{gateway: "10.96.0.10", networks: []string{"10.0.0.0/8", "172.16.0.0/12"}},
				{gateway: "fd00::10", networks: []string{"2001:db8::/32", "fd00::/8"}},
			},
		},
		{
			// Regression guard: with no destinations, both gateways must still be
			// returned so that the hook can tear down any existing tunnels.
			name:       "dual-stack Service without destinations",
			clusterIPs: []string{"10.96.0.10", "fd00::10"},
			want: []wantGateway{
				{gateway: "10.96.0.10", networks: nil},
				{gateway: "fd00::10", networks: nil},
			},
		},
		{
			// Guards that the default routes 0.0.0.0/0 and ::/0 are classified by family.
			name:         "default routes land in the matching family",
			destinations: []string{"0.0.0.0/0", "::/0"},
			clusterIPs:   []string{"10.96.0.10", "fd00::10"},
			want: []wantGateway{
				{gateway: "10.96.0.10", networks: []string{"0.0.0.0/0"}},
				{gateway: "fd00::10", networks: []string{"::/0"}},
			},
		},
		{
			// Guards that an unparsable destination aborts the computation with the
			// documented error message.
			name:         "invalid destination CIDR",
			destinations: []string{"10.0.0.0/8", "not-a-cidr"},
			clusterIPs:   []string{"10.96.0.10"},
			wantErr:      "invalid network in Egress",
		},
		{
			// Guards that an unparsable ClusterIP aborts the computation with the
			// documented error message.
			name:       "invalid ClusterIP",
			clusterIPs: []string{"not-an-ip"},
			wantErr:    "invalid ClusterIP",
		},
		{
			// Guards that FouSourcePortAuto from the Egress reaches every gateway.
			name:         "sportAuto is copied from the Egress",
			destinations: []string{"10.0.0.0/8"},
			clusterIPs:   []string{"10.96.0.10"},
			fouSportAuto: true,
			want: []wantGateway{
				{gateway: "10.96.0.10", networks: []string{"10.0.0.0/8"}},
			},
		},
		{
			// Guards that the controller's OriginatingOnly setting reaches every gateway.
			name:            "originatingOnly is copied from the watcher",
			destinations:    []string{"10.0.0.0/8"},
			clusterIPs:      []string{"10.96.0.10"},
			originatingOnly: true,
			want: []wantGateway{
				{gateway: "10.96.0.10", networks: []string{"10.0.0.0/8"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			eg := &coilv2.Egress{
				Spec: coilv2.EgressSpec{
					Destinations:      tt.destinations,
					FouSourcePortAuto: tt.fouSportAuto,
				},
			}
			svc := &corev1.Service{
				Spec: corev1.ServiceSpec{
					ClusterIPs: tt.clusterIPs,
				},
			}
			if len(tt.clusterIPs) > 0 {
				svc.Spec.ClusterIP = tt.clusterIPs[0]
			}
			r := &EgressWatcher{OriginatingOnly: tt.originatingOnly}

			gws, err := r.gatewayNetworks(eg, svc)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(gws) != len(tt.want) {
				t.Fatalf("got %d gateways, want %d", len(gws), len(tt.want))
			}
			for i, w := range tt.want {
				gw := gws[i]
				if gw.gateway.String() != w.gateway {
					t.Errorf("gateway[%d] = %s, want %s", i, gw.gateway, w.gateway)
				}
				if got := networkStrings(gw.networks); !slices.Equal(got, w.networks) {
					t.Errorf("gateway[%d] networks = %v, want %v", i, got, w.networks)
				}
				if gw.sportAuto != tt.fouSportAuto {
					t.Errorf("gateway[%d] sportAuto = %v, want %v", i, gw.sportAuto, tt.fouSportAuto)
				}
				if gw.originatingOnly != tt.originatingOnly {
					t.Errorf("gateway[%d] originatingOnly = %v, want %v", i, gw.originatingOnly, tt.originatingOnly)
				}
			}
		})
	}
}
