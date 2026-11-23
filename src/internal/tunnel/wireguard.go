package tunnel

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"

	wgconn "golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// NewKeyPair makes a WireGuard key pair, hex encoded the way wireguard-go's
// configuration takes it.
func NewKeyPair() (private, public string, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(key.Bytes()), hex.EncodeToString(key.PublicKey().Bytes()), nil
}

// ValidKey reports whether a hex key has the right shape.
func ValidKey(key string) bool {
	raw, err := hex.DecodeString(key)
	return err == nil && len(raw) == 32
}

// stackDevice lets WireGuard read and write the stack's packets, with no operating
// system tunnel and no privileges.
type stackDevice struct {
	stack  *Stack
	events chan tun.Event
	ctx    context.Context
}

func (d *stackDevice) File() *os.File           { return nil }
func (d *stackDevice) MTU() (int, error)        { return MTU, nil }
func (d *stackDevice) Name() (string, error)    { return "phase", nil }
func (d *stackDevice) Events() <-chan tun.Event { return d.events }
func (d *stackDevice) Close() error             { return nil }
func (d *stackDevice) BatchSize() int           { return 1 }

func (d *stackDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		packet := d.stack.Next(d.ctx)
		if packet != nil {
			sizes[0] = copy(bufs[0][offset:], packet)
			return 1, nil
		}
		if err := d.ctx.Err(); err != nil {
			return 0, os.ErrClosed
		}
	}
}

func (d *stackDevice) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		d.stack.Inject(buf[offset:])
	}
	return len(bufs), nil
}

// LoopbackBind keeps WireGuard's socket on loopback, so a laptop's engine is never
// reachable from the network and raises no firewall prompt.
type LoopbackBind struct {
	mu   sync.Mutex
	conn *net.UDPConn
}

func (b *LoopbackBind) Open(port uint16) ([]wgconn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		return nil, 0, wgconn.ErrBindAlreadyOpen
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	b.conn = conn
	receive := func(packets [][]byte, sizes []int, endpoints []wgconn.Endpoint) (int, error) {
		n, addr, err := conn.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		endpoints[0] = &wgconn.StdNetEndpoint{AddrPort: netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())}
		return 1, nil
	}
	return []wgconn.ReceiveFunc{receive}, uint16(conn.LocalAddr().(*net.UDPAddr).Port), nil
}

func (b *LoopbackBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn == nil {
		return nil
	}
	err := b.conn.Close()
	b.conn = nil
	return err
}

func (b *LoopbackBind) SetMark(uint32) error { return nil }

func (b *LoopbackBind) Send(bufs [][]byte, endpoint wgconn.Endpoint) error {
	b.mu.Lock()
	conn := b.conn
	b.mu.Unlock()
	if conn == nil {
		return net.ErrClosed
	}
	target, ok := endpoint.(*wgconn.StdNetEndpoint)
	if !ok {
		return wgconn.ErrWrongEndpointType
	}
	for _, buf := range bufs {
		if _, err := conn.WriteToUDPAddrPort(buf, target.AddrPort); err != nil {
			return err
		}
	}
	return nil
}

func (b *LoopbackBind) ParseEndpoint(text string) (wgconn.Endpoint, error) {
	addr, err := netip.ParseAddrPort(text)
	if err != nil {
		return nil, err
	}
	if !addr.Addr().IsLoopback() {
		return nil, fmt.Errorf("%s isn't a loopback endpoint", text)
	}
	return &wgconn.StdNetEndpoint{AddrPort: addr}, nil
}

func (b *LoopbackBind) BatchSize() int { return 1 }

// EngineDevice is the engine's end of the tunnel: WireGuard into the stack.
type EngineDevice struct {
	device *device.Device
	// stack is told which source addresses are whose whenever the peers change.
	stack      *Stack
	cancel     context.CancelFunc
	privateKey string
	PublicKey  string
	Port       int
}

// StartEngineDevice listens for the helper on 127.0.0.1:port.
func StartEngineDevice(stack *Stack, port int) (*EngineDevice, error) {
	private, public, err := NewKeyPair()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	tunDevice := &stackDevice{stack: stack, events: make(chan tun.Event, 1), ctx: ctx}
	tunDevice.events <- tun.EventUp
	wg := device.NewDevice(tunDevice, &LoopbackBind{}, device.NewLogger(device.LogLevelError, "phase tunnel: "))
	if err := wg.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", private, port)); err != nil {
		cancel()
		wg.Close()
		return nil, err
	}
	if err := wg.Up(); err != nil {
		cancel()
		wg.Close()
		return nil, err
	}
	return &EngineDevice{device: wg, stack: stack, cancel: cancel, privateKey: private, PublicKey: public, Port: port}, nil
}

// SetPeer accepts the helper's key. Any source address is allowed, because a
// connection opened before the routes changed keeps its old address.
func (d *EngineDevice) SetPeer(peerPublicKey string) error {
	if !ValidKey(peerPublicKey) {
		return fmt.Errorf("the helper's key is malformed")
	}
	return d.setPeers([]peer{{id: LocalPeer, publicKey: peerPublicKey, sources: everySource}})
}

// setPeers replaces the peers WireGuard takes packets from. The stack is told
// the same ranges, so a flow is named after the peer WireGuard took it from.
func (d *EngineDevice) setPeers(peers []peer) error {
	var config strings.Builder
	config.WriteString("replace_peers=true\n")
	for _, peer := range peers {
		// A key is written into WireGuard's configuration as it is.
		if !ValidKey(peer.publicKey) {
			return fmt.Errorf("a peer's key is malformed")
		}
		fmt.Fprintf(&config, "public_key=%s\n", peer.publicKey)
		for _, source := range peer.sources {
			fmt.Fprintf(&config, "allowed_ip=%s\n", source)
		}
	}
	if err := d.device.IpcSet(config.String()); err != nil {
		return err
	}
	d.stack.setPeers(peers)
	return nil
}

// Close stops the device.
func (d *EngineDevice) Close() {
	d.cancel()
	d.device.Close()
}
