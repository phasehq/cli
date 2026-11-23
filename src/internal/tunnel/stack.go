// Package tunnel carries a machine's traffic into Phase without proxy settings.
//
// Everything is a WireGuard peer. On a laptop, a small privileged helper owns the
// operating system's tunnel device and routes; it holds no credentials. Its packets
// arrive here over WireGuard on loopback, where a user-space network stack turns them
// back into connections. Traffic for a Connection host goes to the credential proxy's
// existing front doors, exactly as a program with proxy settings would; everything
// else passes through unread.
package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Flow is one captured connection. Source is the program's side, and Dest is the
// address it dialled.
type Flow struct {
	Source netip.AddrPort
	Dest   netip.AddrPort
	// Peer is the WireGuard peer the flow's packets came from, by the range its
	// source address is in. Empty is LocalPeer.
	Peer string
	// Prepared is whatever Hooks.Prepare returned for this flow.
	Prepared any
}

// peer is the flow's peer with the zero value read as LocalPeer.
func (f Flow) peer() string {
	if f.Peer == "" {
		return LocalPeer
	}
	return f.Peer
}

// Hooks is where captured traffic goes.
type Hooks struct {
	// Prepare runs before a TCP connection completes, so a destination that refuses
	// looks refused to the program. Returning false resets the connection.
	Prepare func(Flow) (prepared any, ok bool)
	// TCP owns the program's connection for its whole life.
	TCP func(client net.Conn, flow Flow)
	// UDP owns one UDP conversation.
	UDP func(client net.Conn, flow Flow)
	// RefuseUDP is asked about each datagram that belongs to no conversation yet.
	// When it says yes the datagram starts none, and its sender is told at once that
	// the port can't be reached. Without it nothing is refused.
	RefuseUDP func(Flow) bool
	// DNS answers queries sent to DNSAddr on port 53. A nil reply sends nothing.
	DNSAddr netip.Addr
	DNS     func(query []byte) []byte
	// Echo sends one ping and reports whether the destination answered. Without it,
	// pings get no reply, rather than a reply the destination never sent.
	Echo func(dest netip.Addr, sequence uint16, payload []byte) bool
}

// Stack is the user-space network stack in front of Hooks.
type Stack struct {
	hooks Hooks
	stack *stack.Stack
	ep    *channel.Endpoint
	// sources says which peer each source address is taken from. Until peers
	// are set every address is the local peer's, as it is behind the helper.
	sources atomic.Pointer[[]peerSource]
}

// NewStack starts a stack for packets of up to mtu bytes.
func NewStack(hooks Hooks, mtu int) (*Stack, error) {
	if hooks.TCP == nil || hooks.UDP == nil || hooks.DNS == nil {
		return nil, errors.New("tunnel stack needs TCP, UDP and DNS hooks")
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	// The defaults suit a small embedded stack. Larger windows and selective
	// acknowledgements let a bulk transfer keep up with the links on either side.
	sack := tcpip.TCPSACKEnabled(true)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	moderate := tcpip.TCPModerateReceiveBufferOption(true)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &moderate)
	receive := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 1 << 20, Max: 8 << 20}
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &receive)
	send := tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 1 << 20, Max: 8 << 20}
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &send)
	ep := channel.New(4096, uint32(mtu), "")
	// Packets come straight from the local kernel, which may leave checksums for the
	// hardware to fill in.
	ep.LinkEPCapabilities |= stack.CapabilityRXChecksumOffload
	const nic = tcpip.NICID(1)
	if err := s.CreateNIC(nic, ep); err != nil {
		return nil, errors.New("create the tunnel's network interface: " + err.String())
	}
	if err := s.SetPromiscuousMode(nic, true); err != nil {
		return nil, errors.New("accept every destination: " + err.String())
	}
	if err := s.SetSpoofing(nic, true); err != nil {
		return nil, errors.New("answer as every destination: " + err.String())
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nic},
		{Destination: header.IPv6EmptySubnet, NIC: nic},
	})
	c := &Stack{hooks: hooks, stack: s, ep: ep}
	c.setPeers([]peer{{id: LocalPeer, sources: everySource}})
	tcpForwarder := tcp.NewForwarder(s, 0, 4096, func(r *tcp.ForwarderRequest) {
		flow, known := c.flowOf(r.ID())
		if !known {
			r.Complete(true)
			return
		}
		if hooks.Prepare != nil {
			prepared, ok := hooks.Prepare(flow)
			if !ok {
				r.Complete(true)
				return
			}
			flow.Prepared = prepared
		}
		var wq waiter.Queue
		endpoint, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			if closer, ok := flow.Prepared.(io.Closer); ok {
				_ = closer.Close()
			}
			return
		}
		r.Complete(false)
		enableKeepAlive(endpoint)
		conn := gonet.NewTCPConn(&wq, endpoint)
		go func() {
			defer conn.Close()
			hooks.TCP(conn, flow)
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	udpForwarder := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
		flow, known := c.flowOf(r.ID())
		if !known {
			return
		}
		var wq waiter.Queue
		endpoint, err := r.CreateEndpoint(&wq)
		if err != nil {
			return
		}
		conn := gonet.NewUDPConn(&wq, endpoint)
		if flow.Dest.Port() == 53 && flow.Dest.Addr() == hooks.DNSAddr {
			go c.serveDNS(conn)
			return
		}
		go hooks.UDP(conn, flow)
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, packet *stack.PacketBuffer) bool {
		if hooks.RefuseUDP != nil {
			if flow, known := c.flowOf(id); known && hooks.RefuseUDP(flow) {
				// A datagram nobody took is answered by the stack itself, as any
				// host answers one for a port nothing listens on.
				return false
			}
		}
		return udpForwarder.HandlePacket(id, packet)
	})
	return c, nil
}

// Close stops the stack and every flow in it.
func (c *Stack) Close() {
	c.ep.Close()
	c.stack.Close()
}

// enableKeepAlive notices a program that went away without saying so, which would
// otherwise hold its flow open for ever.
func enableKeepAlive(endpoint tcpip.Endpoint) {
	endpoint.SocketOptions().SetKeepAlive(true)
	idle := tcpip.KeepaliveIdleOption(45 * time.Second)
	_ = endpoint.SetSockOpt(&idle)
	interval := tcpip.KeepaliveIntervalOption(15 * time.Second)
	_ = endpoint.SetSockOpt(&interval)
	_ = endpoint.SetSockOptInt(tcpip.KeepaliveCountOption, 4)
}

// setPeers replaces the peers whose packets reach the stack.
func (c *Stack) setPeers(peers []peer) {
	sources := sourcesOf(peers)
	c.sources.Store(&sources)
}

// flowOf describes a flow, and names the peer it came from. known is false
// for a source no peer sends from: such a flow is nobody's, and is refused.
func (c *Stack) flowOf(id stack.TransportEndpointID) (flow Flow, known bool) {
	source, _ := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	dest, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	flow = Flow{Source: netip.AddrPortFrom(source, id.RemotePort), Dest: netip.AddrPortFrom(dest, id.LocalPort)}
	flow.Peer, known = peerOf(*c.sources.Load(), source)
	return flow, known
}

// serveDNS answers until the socket goes quiet. Resolvers commonly send A and AAAA
// queries together from one socket, so answering only the first would leave the other
// to time out, which costs the program several seconds on every lookup.
func (c *Stack) serveDNS(conn *gonet.UDPConn) {
	defer conn.Close()
	query := make([]byte, 1500)
	for {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(query)
		if err != nil {
			return
		}
		if reply := c.hooks.DNS(query[:n]); reply != nil {
			_, _ = conn.Write(reply)
		}
	}
}

// Inject hands the stack one raw IP packet from the tunnel.
func (c *Stack) Inject(packet []byte) {
	if len(packet) == 0 || c.interceptEcho(packet) {
		return
	}
	var protocol tcpip.NetworkProtocolNumber
	switch packet[0] >> 4 {
	case 4:
		protocol = ipv4.ProtocolNumber
	case 6:
		protocol = ipv6.ProtocolNumber
	default:
		return
	}
	buf := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), packet...))})
	defer buf.DecRef()
	c.ep.InjectInbound(protocol, buf)
}

// Next blocks for the next raw IP packet the stack sends towards the tunnel.
func (c *Stack) Next(ctx context.Context) []byte {
	buf := c.ep.ReadContext(ctx)
	if buf == nil {
		return nil
	}
	defer buf.DecRef()
	view := buf.ToView()
	defer view.Release()
	return append([]byte(nil), view.AsSlice()...)
}

// interceptEcho answers pings from the real destination. Left alone, the stack would
// reply for every address itself, and a dead host would look alive.
func (c *Stack) interceptEcho(packet []byte) bool {
	var source, dest netip.Addr
	var message []byte
	switch packet[0] >> 4 {
	case 4:
		headerLength := int(packet[0]&0x0f) * 4
		if len(packet) < headerLength+8 || packet[9] != 1 || packet[headerLength] != 8 {
			return false
		}
		source, _ = netip.AddrFromSlice(packet[12:16])
		dest, _ = netip.AddrFromSlice(packet[16:20])
		message = packet[headerLength:]
	case 6:
		if len(packet) < 48 || packet[6] != 58 || packet[40] != 128 {
			return false
		}
		source, _ = netip.AddrFromSlice(packet[8:24])
		dest, _ = netip.AddrFromSlice(packet[24:40])
		message = packet[40:]
	default:
		return false
	}
	if c.hooks.Echo == nil {
		return true
	}
	id := binary.BigEndian.Uint16(message[4:])
	sequence := binary.BigEndian.Uint16(message[6:])
	payload := append([]byte(nil), message[8:]...)
	go func() {
		if c.hooks.Echo(dest, sequence, payload) {
			c.emit(EchoReply(dest, source, id, sequence, payload))
		}
	}()
	return true
}

// emit queues a raw IP packet towards the tunnel, as if the stack had built it.
func (c *Stack) emit(packet []byte) {
	buf := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
	defer buf.DecRef()
	var list stack.PacketBufferList
	list.PushBack(buf)
	_, _ = c.ep.WritePackets(list)
}

// EchoReply builds the packet a destination would have sent in reply to a ping.
func EchoReply(from, to netip.Addr, id, sequence uint16, payload []byte) []byte {
	message := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(message[4:], id)
	binary.BigEndian.PutUint16(message[6:], sequence)
	copy(message[8:], payload)
	if from.Is4() {
		binary.BigEndian.PutUint16(message[2:], InternetChecksum(message))
		packet := make([]byte, 20+len(message))
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
		packet[8] = 64
		packet[9] = 1
		source, target := from.As4(), to.As4()
		copy(packet[12:], source[:])
		copy(packet[16:], target[:])
		binary.BigEndian.PutUint16(packet[10:], InternetChecksum(packet[:20]))
		copy(packet[20:], message)
		return packet
	}
	message[0] = 129
	source, target := from.As16(), to.As16()
	pseudo := make([]byte, 40, 40+len(message))
	copy(pseudo, source[:])
	copy(pseudo[16:], target[:])
	binary.BigEndian.PutUint32(pseudo[32:], uint32(len(message)))
	pseudo[39] = 58
	binary.BigEndian.PutUint16(message[2:], InternetChecksum(append(pseudo, message...)))
	packet := make([]byte, 40+len(message))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:], uint16(len(message)))
	packet[6] = 58
	packet[7] = 64
	copy(packet[8:], source[:])
	copy(packet[24:], target[:])
	copy(packet[40:], message)
	return packet
}

// InternetChecksum is the checksum IP and ICMP use.
func InternetChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) > 1 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
