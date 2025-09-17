package ipam

import (
	"fmt"
	"net"
	"sync"

	"github.com/bits-and-blooms/bitset"
	"github.com/cybozu-go/netutil"
)

type allocator struct {
	ipv4         *net.IPNet
	ipv6         *net.IPNet
	usage        *bitset.BitSet
	lastAllocIdx int64
	mtx          sync.Mutex
}

func newAllocator(ipv4, ipv6 *string) *allocator {
	a := &allocator{
		lastAllocIdx: -1,
	}
	if ipv4 != nil {
		ip, n, _ := net.ParseCIDR(*ipv4)
		if ip.To4() == nil {
			panic("ipv4 must be an IPv4 subnet")
		}
		a.ipv4 = n
		ones, bits := n.Mask.Size()
		a.usage = bitset.New(uint(1) << (bits - ones))
	}
	if ipv6 != nil {
		_, n, _ := net.ParseCIDR(*ipv6)
		a.ipv6 = n
		if a.usage == nil {
			ones, bits := n.Mask.Size()
			a.usage = bitset.New(uint(1) << (bits - ones))
		}
	}
	return a
}

func (a *allocator) isFull() bool {
	return a.usage.All()
}

func (a *allocator) isEmpty() bool {
	return a.usage.None()
}

func (a *allocator) fill() {
	for i := uint(0); i < a.usage.Len(); i++ {
		a.usage.Set(i)
	}
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.lastAllocIdx = int64(a.usage.Len() - 1)
}

func (a *allocator) register(ipv4, ipv6 net.IP) (uint, bool) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	if a.ipv4 != nil && a.ipv4.Contains(ipv4) {
		offset := netutil.IPDiff(a.ipv4.IP, ipv4)
		if offset < 0 {
			panic(fmt.Sprintf("ip: %v, base: %v, offset: %v", ipv4, a.ipv4.IP, offset))
		}
		a.usage.Set(uint(offset))
		a.lastAllocIdx = int64(offset)
		return uint(offset), true
	}
	if a.ipv6 != nil && a.ipv6.Contains(ipv6) {
		offset := netutil.IPDiff(a.ipv6.IP, ipv6)
		if offset < 0 {
			panic(fmt.Sprintf("ip: %v, base: %v, offset: %v", ipv6, a.ipv6.IP, offset))
		}
		a.usage.Set(uint(offset))
		a.lastAllocIdx = int64(offset)
		return uint(offset), true
	}
	return 0, false
}

func (a *allocator) allocate() (ipv4, ipv6 net.IP, idx uint, ok bool) {
	// try to get an usable index from the last allocated index
	a.mtx.Lock()
	defer a.mtx.Unlock()
	idx, ok = a.usage.NextClear(uint(a.lastAllocIdx + 1))
	if !ok {
		// if an usable index is not found, try to get from index 0
		if idx, ok = a.usage.NextClear(0); !ok {
			return nil, nil, 0, false
		}
	}

	if a.ipv4 != nil {
		ipv4 = netutil.IPAdd(a.ipv4.IP, int64(idx))
	}
	if a.ipv6 != nil {
		ipv6 = netutil.IPAdd(a.ipv6.IP, int64(idx))
	}
	a.usage.Set(idx)
	a.lastAllocIdx = int64(idx)
	return
}

func (a *allocator) free(idx uint) {
	a.usage.Clear(idx)
}
