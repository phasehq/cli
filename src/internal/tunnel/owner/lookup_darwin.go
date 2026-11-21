//go:build darwin

package owner

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// lsofPath is the system's own lsof, by its full path, so nothing on PATH can stand
// in for it. The kernel's socket table would be cheaper, but without privileges it
// lists only the caller's own sockets, and lsof sees every process of this user.
var lsofPath = "/usr/sbin/lsof"

// maxListing bounds what is read from lsof. One port's sockets fit in a few hundred
// bytes.
const maxListing = 64 << 10

// Lookup finds the program whose TCP socket has localPort as its own port and remote
// as its far end. A port number is reused for other destinations, so the far end is
// part of the question; only a remote that isn't valid is left out of it. It takes
// about 50 ms, and never longer than Wait or ctx allows. The calling process is never
// the answer.
func Lookup(ctx context.Context, localPort int, remote netip.AddrPort) (Process, error) {
	if localPort < 1 || localPort > 65535 {
		return Process{}, fmt.Errorf("port %d is out of range", localPort)
	}
	ctx, cancel := context.WithTimeout(ctx, Wait)
	defer cancel()
	listing, err := listSockets(ctx, localPort)
	if err != nil {
		return Process{}, err
	}
	var found *Process
	failure := ErrNotFound
	for _, pid := range holders(parseListing(listing), localPort, remote, os.Getpid()) {
		process, err := processOf(pid)
		if err != nil {
			// It may have gone since it was listed, and then it holds nothing.
			failure = err
			continue
		}
		if found != nil && found.Executable != process.Executable {
			return Process{}, ErrShared
		}
		if found == nil {
			found = &process
		}
	}
	if found == nil {
		return Process{}, failure
	}
	return *found, nil
}

// listSockets asks lsof for the TCP sockets that have port at either end.
func listSockets(ctx context.Context, port int) ([]byte, error) {
	// -n and -P stop it resolving names. -b keeps it off the calls that can block on a
	// dead network mount, and -w drops the warnings that causes. -F prints one field a
	// line: the process, then each of its sockets.
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	command := exec.CommandContext(ctx, lsofPath, "-nP", "-b", "-w", "-iTCP:"+strconv.Itoa(port), "-Fpn")
	command.Env = []string{"LC_ALL=C"}
	listing := &capped{limit: maxListing, full: stop}
	command.Stdout = listing
	// Once it has been killed, nothing it left behind is waited for.
	command.WaitDelay = 50 * time.Millisecond
	err := command.Run()
	if listing.over {
		return nil, errors.New("lsof listed more sockets than one port has")
	}
	if stopped := ctx.Err(); stopped != nil {
		return nil, stopped
	}
	// It exits with 1 when nothing matches, and prints nothing.
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		return nil, fmt.Errorf("run lsof: %w", err)
	}
	return listing.kept.Bytes(), nil
}

// capped keeps the first limit bytes written to it. Anything more is dropped, and
// full is called to stop whatever is writing.
type capped struct {
	kept  bytes.Buffer
	limit int
	over  bool
	full  func()
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.limit - c.kept.Len(); len(p) > room {
		c.kept.Write(p[:max(room, 0)])
		if !c.over && c.full != nil {
			c.full()
		}
		c.over = true
		return len(p), nil
	}
	return c.kept.Write(p)
}

// socket is one connected TCP socket, and the process that holds it.
type socket struct {
	pid           int
	local, remote netip.AddrPort
}

// parseListing reads lsof's field output. A "p" line starts a process, and each "n"
// line under it is one of its sockets, written local->remote once it's connected.
func parseListing(listing []byte) []socket {
	var sockets []socket
	pid := 0
	for _, line := range strings.Split(string(listing), "\n") {
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			// A line that can't be read leaves the sockets under it with no owner, rather
			// than with the process before.
			if pid, _ = strconv.Atoi(line[1:]); pid < 0 {
				pid = 0
			}
		case 'n':
			near, far, connected := strings.Cut(line[1:], "->")
			if pid == 0 || !connected {
				continue
			}
			local, localErr := netip.ParseAddrPort(near)
			remote, remoteErr := netip.ParseAddrPort(far)
			if localErr != nil || remoteErr != nil {
				continue
			}
			sockets = append(sockets, socket{pid: pid, local: plain(local), remote: plain(remote)})
		}
	}
	return sockets
}

// plain writes an address one way, however the socket was opened.
func plain(address netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(address.Addr().Unmap().WithZone(""), address.Port())
}

// holders picks the processes, other than self, behind the sockets from localPort to
// remote. lsof also lists sockets with the port at their far end, which belong to
// whatever the program is talking to.
func holders(sockets []socket, localPort int, remote netip.AddrPort, self int) []int {
	remote = plain(remote)
	seen := map[int]bool{}
	var pids []int
	for _, candidate := range sockets {
		if candidate.pid == self || int(candidate.local.Port()) != localPort || seen[candidate.pid] {
			continue
		}
		if remote.IsValid() && candidate.remote != remote {
			continue
		}
		seen[candidate.pid] = true
		pids = append(pids, candidate.pid)
	}
	sort.Ints(pids)
	return pids
}

// processOf reads what a process was started with. The kernel answers for this
// user's own processes, with no privileges.
func processOf(pid int) (Process, error) {
	uid, err := uidOf(pid)
	if err != nil {
		return Process{}, err
	}
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return Process{}, fmt.Errorf("read what process %d was started with: %w", pid, err)
	}
	// The process's environment follows its arguments. It is never read, and it
	// doesn't outlive this call.
	defer clear(raw)
	executable, args, err := parseStart(raw)
	if err != nil {
		return Process{}, fmt.Errorf("read what process %d was started with: %w", pid, err)
	}
	return Process{PID: pid, Executable: executable, Args: args, UID: uid}, nil
}

// uidOf is the user a process runs as, by its effective ID: the one its privileges
// come from. The kernel answers for any process.
func uidOf(pid int) (int, error) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, fmt.Errorf("read which user process %d runs as: %w", pid, err)
	}
	if int(info.Proc.P_pid) != pid {
		return 0, fmt.Errorf("read which user process %d runs as: no such process", pid)
	}
	return int(info.Eproc.Ucred.Uid), nil
}

// parseStart reads the kernel's record of how a process was started: the number of
// arguments, the path it was started with, padding up to the next eight bytes, then
// the arguments. It reads exactly that many strings from where the arguments start,
// so it may stop short of the last argument but never runs on into the environment
// that follows them.
func parseStart(raw []byte) (string, []string, error) {
	if len(raw) < 4 {
		return "", nil, errors.New("the record is too short")
	}
	count := int(int32(binary.NativeEndian.Uint32(raw)))
	rest := raw[4:]
	end := bytes.IndexByte(rest, 0)
	if end <= 0 {
		return "", nil, errors.New("the record has no executable path")
	}
	executable := string(rest[:end])
	start := min((end+1+7)&^7, len(rest))
	if len(bytes.Trim(rest[end:start], "\x00")) > 0 {
		return "", nil, errors.New("the record isn't laid out as expected")
	}
	rest = rest[start:]
	var args []string
	for len(args) < count {
		end := bytes.IndexByte(rest, 0)
		if end < 0 {
			break
		}
		args = append(args, string(rest[:end]))
		rest = rest[end+1:]
	}
	return executable, args, nil
}
