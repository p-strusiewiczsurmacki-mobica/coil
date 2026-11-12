//go:build privileged

package controllers

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/go-logr/logr"
	"github.com/vishvananda/netlink"

	"github.com/cybozu-go/coil/v2/pkg/constants"
	"github.com/cybozu-go/coil/v2/pkg/fou"
	"github.com/cybozu-go/coil/v2/pkg/nat/netfilter"
)

const hookTestEgressPort = 5555

// newHookNS creates a throw-away network namespace prepared the way coild
// prepares a client Pod namespace: FoU tunnel and NAT client are initialized.
// The test is skipped if the kernel lacks the required modules.
func newHookNS(t *testing.T, ipv4, ipv6 net.IP) ns.NetNS {
	t.Helper()

	netNS, err := testutils.NewNS()
	if err != nil {
		t.Skipf("cannot create network namespace: %v", err)
	}
	t.Cleanup(func() {
		_ = netNS.Close()
		_ = testutils.UnmountNS(netNS)
	})

	err = netNS.Do(func(ns.NetNS) error {
		ft := fou.NewFoUTunnel(hookTestEgressPort, ipv4, ipv6, nil)
		if err := ft.Init(); err != nil {
			return fmt.Errorf("fou Init failed: %w", err)
		}
		nc := netfilter.NewNatClient(ipv4, ipv6, nil, constants.EgressBackendIPTables, nil)
		if err := nc.Init(); err != nil {
			return fmt.Errorf("nat Init failed: %w", err)
		}
		return nil
	})
	if err != nil {
		if strings.Contains(err.Error(), "modprobe") {
			t.Skipf("kernel modules unavailable: %v", err)
		}
		t.Fatal(err)
	}
	return netNS
}

// applyHook runs EgressWatcher.hook for gw inside netNS.
func applyHook(netNS ns.NetNS, ipv4, ipv6 net.IP, cn *netfilter.ClusterNetworks, gw gwNets) error {
	return netNS.Do(func(ns.NetNS) error {
		r := &EgressWatcher{
			EgressPort:      hookTestEgressPort,
			Backend:         constants.EgressBackendIPTables,
			ClusterNetworks: cn,
		}
		logger := logr.Discard()
		return r.hook(context.Background(), gw, &logger)(ipv4, ipv6)
	})
}

// inNS runs fn inside netNS and fails the test on error.
func inNS(t *testing.T, netNS ns.NetNS, fn func() error) {
	t.Helper()
	if err := netNS.Do(func(ns.NetNS) error { return fn() }); err != nil {
		t.Fatal(err)
	}
}

// linkExists reports whether a link with the given name exists. Must run in netNS.
func linkExists(name string) (int, bool, error) {
	link, err := netlink.LinkByName(name)
	if err == nil {
		return link.Attrs().Index, true, nil
	}
	if _, ok := errors.AsType[netlink.LinkNotFoundError](err); ok {
		return 0, false, nil
	}
	return 0, false, err
}

type tableRoute struct {
	table int
	dst   string
	link  int
}

// tableRoutes lists routes in the NatClient tables for family. Must run in netNS.
func tableRoutes(family int) ([]tableRoute, error) {
	var out []tableRoute
	for _, table := range []int{netfilter.NcNarrowTableID, netfilter.NcWideTableID} {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return nil, err
		}
		for _, r := range routes {
			if r.Dst == nil {
				continue
			}
			out = append(out, tableRoute{table: table, dst: r.Dst.String(), link: r.LinkIndex})
		}
	}
	return out, nil
}

// routesOn returns "table dst" strings for routes that use linkIndex.
func routesOn(routes []tableRoute, linkIndex int) []string {
	var out []string
	for _, r := range routes {
		if r.link == linkIndex {
			out = append(out, fmt.Sprintf("%d %s", r.table, r.dst))
		}
	}
	slices.Sort(out)
	return out
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestEgressWatcherHook(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	ipv4 := net.ParseIP("10.1.1.2")
	ipv6 := net.ParseIP("fd01::102")
	gw4 := net.ParseIP("10.96.0.10")
	gw6 := net.ParseIP("fd00::10")

	// 10.1.3.0/24 and fd01::/64 are in-cluster (narrow table 117);
	// 8.8.8.0/24 and 2001:db8::/32 are not (wide table 118).
	v4Networks := []*net.IPNet{mustCIDR(t, "10.1.3.0/24"), mustCIDR(t, "8.8.8.0/24")}
	v6Networks := []*net.IPNet{mustCIDR(t, "fd01::/64"), mustCIDR(t, "2001:db8::/32")}
	v4Want := []string{"117 10.1.3.0/24", "118 8.8.8.0/24"}
	v6Want := []string{"117 fd01::/64", "118 2001:db8::/32"}

	// Regression guard: a gateway with networks must get a FoU tunnel and its routes.
	t.Run("networks create tunnel and routes", func(t *testing.T) {
		netNS := newHookNS(t, ipv4, ipv6)
		gw := gwNets{gateway: gw4, networks: v4Networks, originatingOnly: false}
		if err := applyHook(netNS, ipv4, ipv6, nil, gw); err != nil {
			t.Fatalf("hook failed: %v", err)
		}
		inNS(t, netNS, func() error {
			idx, ok, err := linkExists(fou.FouName(gw4))
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("link %s does not exist", fou.FouName(gw4))
			}
			routes, err := tableRoutes(netlink.FAMILY_V4)
			if err != nil {
				return err
			}
			if got := routesOn(routes, idx); !slices.Equal(got, v4Want) {
				return fmt.Errorf("routes = %v, want %v", got, v4Want)
			}
			return nil
		})
	})

	// Regression guard: an empty network list must remove a stale tunnel and its
	// routes instead of leaving them behind.
	t.Run("empty networks remove tunnel and routes", func(t *testing.T) {
		netNS := newHookNS(t, ipv4, ipv6)
		if err := applyHook(netNS, ipv4, ipv6, nil, gwNets{gateway: gw4, networks: v4Networks}); err != nil {
			t.Fatalf("setup hook failed: %v", err)
		}
		if err := applyHook(netNS, ipv4, ipv6, nil, gwNets{gateway: gw4}); err != nil {
			t.Fatalf("hook with empty networks failed: %v", err)
		}
		inNS(t, netNS, func() error {
			_, ok, err := linkExists(fou.FouName(gw4))
			if err != nil {
				return err
			}
			if ok {
				return fmt.Errorf("link %s still exists", fou.FouName(gw4))
			}
			routes, err := tableRoutes(netlink.FAMILY_V4)
			if err != nil {
				return err
			}
			if len(routes) != 0 {
				return fmt.Errorf("routes remain in NAT tables: %v", routes)
			}
			return nil
		})
	})

	// Regression guard: an empty network list for a gateway that never had a
	// tunnel must be a no-op, not an error.
	t.Run("empty networks for unknown gateway is a no-op", func(t *testing.T) {
		netNS := newHookNS(t, ipv4, ipv6)
		if err := applyHook(netNS, ipv4, ipv6, nil, gwNets{gateway: gw4}); err != nil {
			t.Fatalf("hook with empty networks failed: %v", err)
		}
		inNS(t, netNS, func() error {
			_, ok, err := linkExists(fou.FouName(gw4))
			if err != nil {
				return err
			}
			if ok {
				return fmt.Errorf("link %s was created", fou.FouName(gw4))
			}
			return nil
		})
	})

	// Guards that the hook is idempotent when reconciled repeatedly.
	t.Run("repeated hook is idempotent", func(t *testing.T) {
		netNS := newHookNS(t, ipv4, ipv6)
		gw := gwNets{gateway: gw4, networks: v4Networks}
		if err := applyHook(netNS, ipv4, ipv6, nil, gw); err != nil {
			t.Fatalf("first hook failed: %v", err)
		}
		if err := applyHook(netNS, ipv4, ipv6, nil, gw); err != nil {
			t.Fatalf("second hook failed: %v", err)
		}
		inNS(t, netNS, func() error {
			idx, ok, err := linkExists(fou.FouName(gw4))
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("link %s does not exist", fou.FouName(gw4))
			}
			routes, err := tableRoutes(netlink.FAMILY_V4)
			if err != nil {
				return err
			}
			if got := routesOn(routes, idx); !slices.Equal(got, v4Want) {
				return fmt.Errorf("routes = %v, want %v", got, v4Want)
			}
			return nil
		})
	})

	// Regression guard for the dual-stack case: clearing the IPv6 networks must
	// remove only the IPv6 tunnel and leave the IPv4 tunnel and its routes intact.
	t.Run("dual-stack: clearing IPv6 networks keeps IPv4", func(t *testing.T) {
		netNS := newHookNS(t, ipv4, ipv6)
		if err := applyHook(netNS, ipv4, ipv6, nil, gwNets{gateway: gw4, networks: v4Networks}); err != nil {
			t.Fatalf("setup IPv4 hook failed: %v", err)
		}
		if err := applyHook(netNS, ipv4, ipv6, nil, gwNets{gateway: gw6, networks: v6Networks}); err != nil {
			t.Fatalf("setup IPv6 hook failed: %v", err)
		}
		// Ensure the setup really produced IPv6 routes, so the removal below is meaningful.
		inNS(t, netNS, func() error {
			idx6, ok6, err := linkExists(fou.FouName(gw6))
			if err != nil {
				return err
			}
			if !ok6 {
				return fmt.Errorf("IPv6 link %s was not created", fou.FouName(gw6))
			}
			routes6, err := tableRoutes(netlink.FAMILY_V6)
			if err != nil {
				return err
			}
			if got := routesOn(routes6, idx6); !slices.Equal(got, v6Want) {
				return fmt.Errorf("IPv6 routes after setup = %v, want %v", got, v6Want)
			}
			return nil
		})
		if err := applyHook(netNS, ipv4, ipv6, nil, gwNets{gateway: gw6}); err != nil {
			t.Fatalf("IPv6 hook with empty networks failed: %v", err)
		}
		inNS(t, netNS, func() error {
			_, ok6, err := linkExists(fou.FouName(gw6))
			if err != nil {
				return err
			}
			if ok6 {
				return fmt.Errorf("IPv6 link %s still exists", fou.FouName(gw6))
			}
			idx4, ok4, err := linkExists(fou.FouName(gw4))
			if err != nil {
				return err
			}
			if !ok4 {
				return fmt.Errorf("IPv4 link %s was removed", fou.FouName(gw4))
			}
			routes, err := tableRoutes(netlink.FAMILY_V4)
			if err != nil {
				return err
			}
			if got := routesOn(routes, idx4); !slices.Equal(got, v4Want) {
				return fmt.Errorf("IPv4 routes = %v, want %v", got, v4Want)
			}
			routes6, err := tableRoutes(netlink.FAMILY_V6)
			if err != nil {
				return err
			}
			if len(routes6) != 0 {
				return fmt.Errorf("IPv6 routes remain in NAT tables: %v", routes6)
			}
			return nil
		})
	})

	// Guards that the hook installs in-cluster rules for the configured cluster
	// networks and removes the defaults (the NAT client was prepared with defaults).
	t.Run("in-cluster rules follow configured cluster networks", func(t *testing.T) {
		netNS := newHookNS(t, ipv4, ipv6)
		cn, err := netfilter.ParseClusterNetworks([]string{"100.64.0.0/10"})
		if err != nil {
			t.Fatal(err)
		}
		if err := applyHook(netNS, ipv4, ipv6, cn, gwNets{gateway: gw4, networks: v4Networks}); err != nil {
			t.Fatalf("hook failed: %v", err)
		}
		inNS(t, netNS, func() error {
			rules, err := netlink.RuleListFiltered(netlink.FAMILY_V4, &netlink.Rule{Table: netfilter.MainTableID}, netlink.RT_FILTER_TABLE)
			if err != nil {
				return err
			}
			var got []string
			for _, r := range rules {
				if r.Priority < netfilter.NcLocalPrioBase || r.Priority >= netfilter.NcWidePrio || r.Dst == nil {
					continue
				}
				got = append(got, r.Dst.String())
			}
			if want := []string{"100.64.0.0/10"}; !slices.Equal(got, want) {
				return fmt.Errorf("in-cluster IPv4 rules = %v, want %v", got, want)
			}
			return nil
		})
	})
}
