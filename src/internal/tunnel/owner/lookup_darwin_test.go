//go:build darwin

package owner

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// connectFromAnotherProgram starts nc, a program that isn't this one, and returns the
// port its connection to a listener here left from.
func connectFromAnotherProgram(t *testing.T, network string) (child *exec.Cmd, clientPort int, listener netip.AddrPort) {
	t.Helper()
	host := "127.0.0.1"
	if network == "tcp6" {
		host = "::1"
	}
	socket, err := net.Listen(network, net.JoinHostPort(host, "0"))
	if err != nil {
		t.Skipf("no %s loopback here: %v", network, err)
	}
	t.Cleanup(func() { socket.Close() })
	listener = socket.Addr().(*net.TCPAddr).AddrPort()
	child = exec.Command("/usr/bin/nc", host, strconv.Itoa(int(listener.Port())))
	// An open pipe on its input keeps nc connected until the test is over.
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = input.Close()
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
	})
	_ = socket.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
	conn, err := socket.Accept()
	if err != nil {
		t.Fatalf("nc never connected: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return child, conn.RemoteAddr().(*net.TCPAddr).Port, listener
}

func TestLookupFindsTheProgramBehindAPort(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			child, port, listener := connectFromAnotherProgram(t, network)
			start := time.Now()
			process, err := Lookup(context.Background(), port, listener)
			elapsed := time.Since(start)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("found in %s", elapsed.Round(time.Millisecond))
			if process.PID != child.Process.Pid {
				t.Errorf("pid %d, and nc is %d", process.PID, child.Process.Pid)
			}
			if process.Executable != "/usr/bin/nc" {
				t.Errorf("executable %q", process.Executable)
			}
			want := []string{"/usr/bin/nc", listener.Addr().String(), strconv.Itoa(int(listener.Port()))}
			if !reflect.DeepEqual(process.Args, want) {
				t.Errorf("arguments %q, want %q", process.Args, want)
			}
			if process.UID != os.Getuid() {
				t.Errorf("runs as user %d, and nc was started as %d", process.UID, os.Getuid())
			}
			if got := Identify(process); got != "" {
				t.Errorf("nc was taken for %q", got)
			}
			if elapsed > Wait {
				t.Errorf("took %s, longer than a lookup may", elapsed)
			}
		})
	}
}

// Which user a process runs as is read from the kernel, for another user's process
// too, so a flow can be told apart from this user's own.
func TestUIDOfNamesTheUserAProcessRunsAs(t *testing.T) {
	if uid, err := uidOf(os.Getpid()); err != nil || uid != os.Getuid() {
		t.Fatalf("this process runs as %d (%v), want %d", uid, err, os.Getuid())
	}
	// launchd is root's.
	if uid, err := uidOf(1); err != nil || uid != 0 {
		t.Fatalf("launchd runs as %d (%v)", uid, err)
	}
	if _, err := uidOf(1 << 30); err == nil {
		t.Fatal("a process that doesn't exist was given a user")
	}
}

// The same port number is some other socket's when it leads somewhere else.
func TestLookupNeedsTheFarEndToMatch(t *testing.T) {
	_, port, listener := connectFromAnotherProgram(t, "tcp4")
	elsewhere := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), listener.Port())
	if process, err := Lookup(context.Background(), port, elsewhere); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a connection to somewhere else was found: %+v, %v", process.PID, err)
	}
	// With no far end to go by, the port alone has to do.
	if _, err := Lookup(context.Background(), port, netip.AddrPort{}); err != nil {
		t.Fatalf("by port alone: %v", err)
	}
}

// The listener's end of the same connection belongs to this process, which is never
// the answer: the engine's own sockets must not be taken for a program's.
func TestLookupNeverAnswersWithThisProcess(t *testing.T) {
	_, port, listener := connectFromAnotherProgram(t, "tcp4")
	client := netip.AddrPortFrom(listener.Addr(), uint16(port))
	if process, err := Lookup(context.Background(), int(listener.Port()), client); !errors.Is(err, ErrNotFound) {
		t.Fatalf("this process's own socket was found: pid %d (this is %d), %v", process.PID, os.Getpid(), err)
	}
}

func TestLookupOfAPortNobodyHasIsNotFound(t *testing.T) {
	socket, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := socket.Addr().(*net.TCPAddr).Port
	socket.Close()
	if _, err := Lookup(context.Background(), port, netip.MustParseAddrPort("192.0.2.1:443")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	for _, port := range []int{0, -1, 65536} {
		if _, err := Lookup(context.Background(), port, netip.AddrPort{}); err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("port %d: err = %v", port, err)
		}
	}
}

// slowLsof stands in for an lsof that hangs, as it would on a machine in trouble. It
// leaves a child holding its output open, which is the harder case to give up on.
func slowLsof(t *testing.T) {
	t.Helper()
	script := filepath.Join(t.TempDir(), "lsof")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n/bin/sleep 3\necho p1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	original := lsofPath
	lsofPath = script
	t.Cleanup(func() { lsofPath = original })
}

func TestLookupGivesUpAtItsDeadline(t *testing.T) {
	slowLsof(t)
	t.Run("the caller's", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := Lookup(ctx, 40000, netip.MustParseAddrPort("192.0.2.1:443"))
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v", err)
		}
		if elapsed := time.Since(start); elapsed > 400*time.Millisecond {
			t.Fatalf("took %s to give up after 100ms", elapsed)
		}
	})
	t.Run("its own", func(t *testing.T) {
		start := time.Now()
		_, err := Lookup(context.Background(), 40000, netip.MustParseAddrPort("192.0.2.1:443"))
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v", err)
		}
		if elapsed := time.Since(start); elapsed < Wait || elapsed > Wait+300*time.Millisecond {
			t.Fatalf("took %s, and a lookup may take %s", elapsed, Wait)
		}
	})
	t.Run("a caller that has already left", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		start := time.Now()
		if _, err := Lookup(ctx, 40000, netip.AddrPort{}); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
		if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
			t.Fatalf("took %s", elapsed)
		}
	})
}

func TestLookupFailsWhenLsofCannotRun(t *testing.T) {
	original := lsofPath
	lsofPath = filepath.Join(t.TempDir(), "missing")
	t.Cleanup(func() { lsofPath = original })
	if _, err := Lookup(context.Background(), 40000, netip.AddrPort{}); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestLookupStopsReadingARunawayListing(t *testing.T) {
	script := filepath.Join(t.TempDir(), "lsof")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexec /usr/bin/yes n127.0.0.1:40000-\\>192.0.2.1:443\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	original := lsofPath
	lsofPath = script
	t.Cleanup(func() { lsofPath = original })
	stopped := 0
	listing := &capped{limit: 16, full: func() { stopped++ }}
	for range 4 {
		if n, err := listing.Write([]byte("0123456789")); n != 10 || err != nil {
			t.Fatalf("wrote %d, %v", n, err)
		}
	}
	if !listing.over || stopped != 1 || listing.kept.String() != "0123456789012345" {
		t.Fatalf("kept %q, over %v, stopped %d times", listing.kept.String(), listing.over, stopped)
	}
	// The writer is stopped as soon as there's too much, not left to run to the deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	kept, err := listSockets(ctx, 40000)
	if err == nil || ctx.Err() != nil || kept != nil {
		t.Fatalf("%d bytes, err = %v", len(kept), err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("took %s", elapsed)
	}
	if _, err := Lookup(context.Background(), 40000, netip.MustParseAddrPort("192.0.2.1:443")); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestParseListing(t *testing.T) {
	listing := strings.Join([]string{
		"p501", "f3", "n127.0.0.1:8080", // a listener
		"f5", "n127.0.0.1:8080->127.0.0.1:50000",
		"p777", "f3", "n198.19.248.1:50000->203.0.113.7:443",
		"f9", "n[fd70:7068:6173::1]:50001->[2001:db8::7]:443",
		"f10", "n[::ffff:198.19.248.1]:50002->[::ffff:203.0.113.7]:443",
		"f11", "n*:9000",
		"f12", "nnot an address->203.0.113.7:443",
		"pnot-a-number", "f3", "n198.19.248.1:50003->203.0.113.7:443",
		"p888", "f4", "n198.19.248.1:50004->203.0.113.8:443",
		"", "x", "p",
	}, "\n")
	want := []socket{
		{501, netip.MustParseAddrPort("127.0.0.1:8080"), netip.MustParseAddrPort("127.0.0.1:50000")},
		{777, netip.MustParseAddrPort("198.19.248.1:50000"), netip.MustParseAddrPort("203.0.113.7:443")},
		{777, netip.MustParseAddrPort("[fd70:7068:6173::1]:50001"), netip.MustParseAddrPort("[2001:db8::7]:443")},
		{777, netip.MustParseAddrPort("198.19.248.1:50002"), netip.MustParseAddrPort("203.0.113.7:443")},
		{888, netip.MustParseAddrPort("198.19.248.1:50004"), netip.MustParseAddrPort("203.0.113.8:443")},
	}
	if got := parseListing([]byte(listing)); !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

func TestHolders(t *testing.T) {
	address := netip.MustParseAddrPort
	const self = 100
	sockets := []socket{
		// The engine's own socket, which happens to leave from the same port.
		{self, address("192.168.1.5:50000"), address("203.0.113.7:443")},
		// The program's.
		{200, address("198.19.248.1:50000"), address("203.0.113.7:443")},
		// The same port number reused for another destination, by another program.
		{300, address("192.168.1.5:50000"), address("203.0.113.9:443")},
		// A local server on that port number: its clients have it at the far end.
		{400, address("127.0.0.1:61000"), address("127.0.0.1:50000")},
		// One connection held by a program and the child it started.
		{500, address("198.19.248.1:50001"), address("203.0.113.7:443")},
		{501, address("198.19.248.1:50001"), address("203.0.113.7:443")},
		{500, address("198.19.248.1:50001"), address("203.0.113.7:443")},
	}
	for _, test := range []struct {
		name   string
		port   int
		remote string
		want   []int
	}{
		{"the program, not the engine and not the port's other user", 50000, "203.0.113.7:443", []int{200}},
		{"the port's other user", 50000, "203.0.113.9:443", []int{300}},
		{"written as an IPv4 address inside IPv6", 50000, "[::ffff:203.0.113.7]:443", []int{200}},
		{"nobody goes there from that port", 50000, "203.0.113.10:443", nil},
		{"the right address on another port", 50000, "203.0.113.7:8443", nil},
		{"the server a local client reaches on that port number", 50000, "127.0.0.1:61000", nil},
		{"everyone holding the connection, once each", 50001, "203.0.113.7:443", []int{500, 501}},
	} {
		if got := holders(sockets, test.port, address(test.remote), self); !reflect.DeepEqual(got, test.want) {
			t.Errorf("%s: got %v, want %v", test.name, got, test.want)
		}
	}
	if got := holders(sockets, 50000, netip.AddrPort{}, self); !reflect.DeepEqual(got, []int{200, 300}) {
		t.Errorf("with no far end to go by: %v", got)
	}
}

// record lays a start record out the way the kernel does.
func record(count int32, executable string, strings ...string) []byte {
	raw := binary.NativeEndian.AppendUint32(nil, uint32(count))
	raw = append(raw, executable...)
	raw = append(raw, 0)
	for (len(raw)-4)%8 != 0 {
		raw = append(raw, 0)
	}
	for _, value := range strings {
		raw = append(raw, value...)
		raw = append(raw, 0)
	}
	return raw
}

func TestParseStartReadsTheArgumentsAndNeverTheEnvironment(t *testing.T) {
	const environment = "SECRET_TOKEN=do-not-read"
	for _, test := range []struct {
		name       string
		raw        []byte
		executable string
		args       []string
	}{
		{"a program and its arguments", record(3, "/usr/bin/nc", "nc", "127.0.0.1", "443", environment), "/usr/bin/nc", []string{"nc", "127.0.0.1", "443"}},
		{"a path that fills its eight bytes exactly", record(1, "/bin/ab", "ab", environment), "/bin/ab", []string{"ab"}},
		{"a path one byte over", record(1, "/bin/abc", "abc", environment), "/bin/abc", []string{"abc"}},
		{"no arguments", record(0, "/usr/bin/true", environment), "/usr/bin/true", nil},
		// node, after the script it runs changed its title: the arguments are blanked.
		{"a rewritten title", record(3, "/opt/homebrew/bin/node", "claude", "", "", environment), "/opt/homebrew/bin/node", []string{"claude", "", ""}},
		// Skipping blanks to find the first argument would read the environment as the last.
		{"an empty first argument", record(2, "/usr/bin/nc", "", "443", environment), "/usr/bin/nc", []string{"", "443"}},
		{"empty arguments only", record(2, "/usr/bin/nc", "", "", environment), "/usr/bin/nc", []string{"", ""}},
		{"a count that isn't one", record(-1, "/usr/bin/nc", "nc", environment), "/usr/bin/nc", nil},
		{"cut off inside an argument", record(2, "/usr/bin/nc", "nc", "443")[:4+16+3+2], "/usr/bin/nc", []string{"nc"}},
		{"cut off after the path", record(2, "/usr/bin/nc")[:4+12], "/usr/bin/nc", nil},
	} {
		executable, args, err := parseStart(test.raw)
		if err != nil || executable != test.executable || !reflect.DeepEqual(args, test.args) {
			t.Errorf("%s: %q %q, %v", test.name, executable, args, err)
		}
		for _, arg := range args {
			if strings.Contains(arg, "SECRET") {
				t.Errorf("%s: the environment was read as an argument", test.name)
			}
		}
	}
	for name, raw := range map[string][]byte{
		"nothing":                  nil,
		"a count and nothing":      {1, 0, 0, 0},
		"no path":                  append([]byte{1, 0, 0, 0}, 0, 0, 0, 0),
		"a path with no end":       append([]byte{1, 0, 0, 0}, "/usr/bin/nc"...),
		"something in the padding": append(append([]byte{1, 0, 0, 0}, "/usr/bin/nc\x00x\x00\x00\x00"...), "nc\x00"...),
	} {
		if executable, args, err := parseStart(raw); err == nil {
			t.Errorf("%s: read as %q %q", name, executable, args)
		}
	}
}

// The layout parseStart relies on, checked against the kernel for every length of
// path: where the arguments start depends on it.
func TestProcessOfReadsARunningProgram(t *testing.T) {
	directory := t.TempDir()
	for length := 1; length <= 9; length++ {
		link := filepath.Join(directory, strings.Repeat("s", length))
		if err := os.Symlink("/bin/sleep", link); err != nil {
			t.Fatal(err)
		}
		child := exec.Command(link, "30")
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		process, err := processOf(child.Process.Pid)
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
		if err != nil {
			t.Fatal(err)
		}
		if process.Executable != link || !reflect.DeepEqual(process.Args, []string{link, "30"}) {
			t.Fatalf("a %d-byte path: started as %q %q, read as %q %q", len(link), link, []string{link, "30"}, process.Executable, process.Args)
		}
	}
	if _, err := processOf(1); err == nil {
		t.Error("another user's process could be read")
	}
}
