package tunnel

import (
	"net/netip"
	"sort"
)

// LocalPeer names the peer that is this machine: the helper, on loopback. A
// tunnel's capturing half may run elsewhere, so every flow says its peer.
const LocalPeer = "local"

// peer is one WireGuard peer the engine takes packets from.
type peer struct {
	// id names the peer to the router and the proxy.
	id        string
	publicKey string
	// sources are the addresses WireGuard takes its packets from.
	sources []netip.Prefix
}

// everySource is what the helper sends from: a connection opened before the
// routes changed keeps its old address.
var everySource = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}

// peerSource is a range of source addresses and the peer they are taken from.
type peerSource struct {
	prefix netip.Prefix
	peer   string
}

// sourcesOf lists the peers' ranges, the narrowest first: the order WireGuard
// itself picks a peer in, so both always name the same one.
func sourcesOf(peers []peer) []peerSource {
	var sources []peerSource
	for _, peer := range peers {
		for _, prefix := range peer.sources {
			sources = append(sources, peerSource{prefix: prefix.Masked(), peer: peer.id})
		}
	}
	sort.SliceStable(sources, func(i, j int) bool { return sources[i].prefix.Bits() > sources[j].prefix.Bits() })
	return sources
}

// peerOf names the peer a source address belongs to. WireGuard drops a packet
// whose source isn't its sender's, so the address alone says who sent it.
func peerOf(sources []peerSource, source netip.Addr) (string, bool) {
	source = source.Unmap()
	for _, held := range sources {
		if held.prefix.Contains(source) {
			return held.peer, true
		}
	}
	return "", false
}
