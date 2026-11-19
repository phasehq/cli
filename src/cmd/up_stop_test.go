//go:build !windows

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/tunnel/control"
	"github.com/phasehq/cli/internal/tunnel/engine"
)

// standInProcess starts a process that ps shows as `<program> <args>`, and that stops
// when it is asked to, as the engine does. It returns its pid, and a channel that
// closes when it has gone.
func standInProcess(t *testing.T, program string, args ...string) (int, chan struct{}) {
	t.Helper()
	script := filepath.Join(t.TempDir(), program)
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 120 &\nchild=$!\ntrap \"kill $child; exit 0\" TERM\nwait\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	process := exec.Command(script, args...)
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() {
		_ = process.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		// Asked first, so that it takes its own child with it.
		_ = process.Process.Signal(syscall.SIGTERM)
		if !gone(exited, 2*time.Second) {
			_ = process.Process.Kill()
			<-exited
		}
	})
	pid := process.Process.Pid
	// The script has been started once ps shows its own command line.
	want := script
	if len(args) > 0 {
		want += " " + strings.Join(args, " ")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		listing, _ := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "command=").Output()
		if strings.Contains(string(listing), want) {
			return pid, exited
		}
		if time.Now().After(deadline) {
			t.Skipf("ps here doesn't show the stand-in's command line: %q", listing)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// standInEngine is a stand-in for an engine started from a binary of that name.
func standInEngine(t *testing.T, program string) (int, chan struct{}) {
	t.Helper()
	return standInProcess(t, program, "tunnel", "engine")
}

func gone(exited chan struct{}, wait time.Duration) bool {
	select {
	case <-exited:
		return true
	case <-time.After(wait):
		return false
	}
}

// fakeTunnelHelper answers as the helper does, and remembers what it was asked.
type fakeTunnelHelper struct {
	mu     sync.Mutex
	status control.Status
	asked  []string
}

// startFakeTunnelHelper points the test at a helper that reports status. Once it is
// asked to step aside it has let go of its engine and captures nothing.
func startFakeTunnelHelper(t *testing.T, status control.Status) *fakeTunnelHelper {
	t.Helper()
	directory, err := os.MkdirTemp("", "pu")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	listener, err := net.Listen("unix", filepath.Join(directory, "s"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	status.Protocol = control.ProtocolVersion
	fake := &fakeTunnelHelper{status: status}
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			conn := control.Wrap(raw)
			var request control.Request
			if err := conn.Receive(&request, 5*time.Second); err == nil {
				fake.mu.Lock()
				fake.asked = append(fake.asked, request.Op)
				reply := control.Reply{}
				switch request.Op {
				case control.OpStatus:
					current := fake.status
					reply.Status = &current
				case control.OpDown:
					fake.status.Attached, fake.status.Capturing, fake.status.EnginePID, fake.status.Device = false, false, 0, ""
					fake.status.Reason = "asked to stop"
				}
				fake.mu.Unlock()
				_ = conn.Send(reply)
			}
			_ = raw.Close()
		}
	}()
	original := tunnelHelperSocket
	tunnelHelperSocket = filepath.Join(directory, "s")
	t.Cleanup(func() { tunnelHelperSocket = original })
	return fake
}

func (f *fakeTunnelHelper) askedTo(op string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, asked := range f.asked {
		if asked == op {
			count++
		}
	}
	return count
}

// recordEngine writes the pid file phase up keeps for the engine it started.
func recordEngine(t *testing.T, directory string, pid int) {
	t.Helper()
	if err := os.WriteFile(tunnelEnginePIDPath(directory), []byte(strconv.Itoa(pid)), 0o600); err != nil {
		t.Fatal(err)
	}
	if found, running := tunnelEnginePID(directory); !running || found != pid {
		t.Fatalf("the stand-in engine (pid %d) wasn't recognised: %d, %v", pid, found, running)
	}
}

// A phase up that doesn't end with Phase capturing leaves nothing running. An engine
// left to keep trying, with a helper waiting on it, would start capturing later with
// nobody told. The message says what is true once it has all been stopped.
func TestAFailedUpLeavesNothingRunning(t *testing.T) {
	for name, test := range map[string]struct {
		helper    *control.Status
		engine    *engine.Status
		interrupt bool
		cause     string
	}{
		"Phase never starts capturing": {
			helper: &control.Status{Attached: true, Reason: "waiting for the internet: dial tcp 1.1.1.1:443: i/o timeout"},
			cause:  "Phase didn't start capturing (waiting for the internet: dial tcp 1.1.1.1:443: i/o timeout)",
		},
		"the engine can't open a session": {
			helper: &control.Status{Reason: "phase up hasn't been run"},
			engine: &engine.Status{LastError: "Console answered 403"},
			cause:  "the engine couldn't start a session: Console answered 403",
		},
		"phase up is interrupted": {
			helper: &control.Status{Attached: true, Reason: "the engine isn't answering through the tunnel yet"}, interrupt: true,
			cause: "phase up was interrupted before Phase started capturing",
		},
	} {
		t.Run(name, func(t *testing.T) {
			directory := withTunnelStateDirectory(t)
			pid, exited := standInEngine(t, "phase")
			recordEngine(t, directory, pid)
			status := *test.helper
			if status.Attached {
				status.EnginePID = pid
			}
			fake := startFakeTunnelHelper(t, status)
			if test.engine != nil {
				content, _ := json.Marshal(test.engine)
				if err := os.WriteFile(engine.StatusPath(directory), content, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.interrupt {
				cancel()
			}
			_, cause := waitForCapture(ctx, directory, 700*time.Millisecond)
			if cause == nil || cause.Error() != test.cause {
				t.Fatalf("the wait ended with %v", cause)
			}
			if gone(exited, 0) {
				t.Fatal("the stand-in engine had already stopped: the test shows nothing")
			}

			err := abandonUp(directory, cause)
			if !gone(exited, 10*time.Second) {
				t.Fatal("the engine is still running after phase up failed")
			}
			if fake.askedTo(control.OpDown) != 1 {
				t.Fatalf("the helper was asked to step aside %d times", fake.askedTo(control.OpDown))
			}
			if _, statErr := os.Stat(tunnelEnginePIDPath(directory)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatal("the engine's pid file was left behind")
			}
			message := err.Error()
			for _, want := range []string{test.cause, "phase up has stopped: the engine isn't running and Phase isn't in the path", filepath.Join(directory, "engine.log")} {
				if !strings.Contains(message, want) {
					t.Errorf("the message doesn't say %q:\n%s", want, message)
				}
			}
			if !errors.Is(err, cause) || strings.Contains(message, "unchanged") || strings.Count(message, "\n") != 0 {
				t.Errorf("the message: %q", message)
			}
		})
	}

	// What it couldn't stop, it says.
	t.Run("the helper doesn't answer", func(t *testing.T) {
		directory := withTunnelStateDirectory(t)
		pid, exited := standInEngine(t, "phase")
		recordEngine(t, directory, pid)
		_, cause := waitForCapture(context.Background(), directory, 400*time.Millisecond)
		if cause == nil || cause.Error() != "Phase didn't start capturing (no reason given)" {
			t.Fatalf("the wait ended with %v", cause)
		}
		err := abandonUp(directory, cause)
		if !gone(exited, 10*time.Second) {
			t.Fatal("the engine is still running after phase up failed")
		}
		if message := err.Error(); !strings.Contains(message, "the helper didn't answer when asked to step aside") ||
			strings.Contains(message, "your network is as it was") || !strings.Contains(message, "phase status") {
			t.Fatalf("the message claims more than is known: %q", message)
		}
	})

	t.Run("something else is attached to the helper", func(t *testing.T) {
		directory := withTunnelStateDirectory(t)
		pid, exited := standInEngine(t, "phase")
		recordEngine(t, directory, pid)
		other, otherExited := standInProcess(t, "engine.test", "-test.run=OnThisMac")
		startFakeTunnelHelper(t, control.Status{Attached: true, EnginePID: other, Reason: "the engine isn't answering through the tunnel yet"})
		_, cause := waitForCapture(context.Background(), directory, 400*time.Millisecond)
		err := abandonUp(directory, cause)
		if !gone(exited, 10*time.Second) {
			t.Fatal("the engine is still running after phase up failed")
		}
		if gone(otherExited, 300*time.Millisecond) {
			t.Fatal("a process that isn't an engine of Phase's was stopped")
		}
		if message := err.Error(); !strings.Contains(message, "(process "+strconv.Itoa(other)+") is still attached to the helper") ||
			strings.Contains(message, "your network is as it was") {
			t.Fatalf("the message: %q", message)
		}
	})
}

// The engine stopping on its own is a failed phase up too.
func TestAnEngineThatStopsEndsTheWait(t *testing.T) {
	directory := withTunnelStateDirectory(t)
	fake := startFakeTunnelHelper(t, control.Status{Reason: "the engine stopped"})
	if err := os.WriteFile(tunnelEnginePIDPath(directory), []byte("2147483646"), 0o600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, cause := waitForCapture(context.Background(), directory, 30*time.Second)
	if cause == nil || cause.Error() != "the engine stopped before Phase started capturing" || time.Since(started) > 5*time.Second {
		t.Fatalf("the wait ended with %v after %s", cause, time.Since(started))
	}
	if err := abandonUp(directory, cause); !strings.Contains(err.Error(), "phase up has stopped: the engine isn't running and Phase isn't in the path") {
		t.Fatalf("the message: %v", err)
	}
	if fake.askedTo(control.OpDown) != 1 {
		t.Fatal("the helper wasn't asked to step aside")
	}
}

// Once the helper says it is capturing, the wait is over and nothing is stopped.
func TestTheWaitEndsWhenPhaseIsCapturing(t *testing.T) {
	directory := withTunnelStateDirectory(t)
	pid, exited := standInEngine(t, "phase")
	recordEngine(t, directory, pid)
	fake := startFakeTunnelHelper(t, control.Status{Attached: true, EnginePID: pid, Capturing: true, Device: "utun7"})
	status, err := waitForCapture(context.Background(), directory, 5*time.Second)
	if err != nil || !status.Capturing || status.Device != "utun7" {
		t.Fatalf("%+v, %v", status, err)
	}
	if gone(exited, 200*time.Millisecond) || fake.askedTo(control.OpDown) != 0 {
		t.Fatal("a phase up that worked stopped something")
	}
}

// phase down has to last. The helper lets go of the engine it steps aside for, and an
// engine that is still running attaches again within a second: one that phase up
// didn't start, and so kept no pid of. The helper says which process is attached, and
// phase down stops that one too when it is an engine of this user's.
func TestDownStopsTheEngineTheHelperHasAttached(t *testing.T) {
	t.Run("an engine phase up didn't start", func(t *testing.T) {
		directory := withTunnelStateDirectory(t)
		pid, exited := standInEngine(t, "phase")
		recordEngine(t, directory, pid)
		other, otherExited := standInEngine(t, "phase-dev")
		fake := startFakeTunnelHelper(t, control.Status{Attached: true, EnginePID: other, Capturing: true, Device: "utun7"})

		stopped := stopTunnel(directory)
		if !gone(exited, 10*time.Second) || !gone(otherExited, 10*time.Second) {
			t.Fatal("an engine is still running after phase down")
		}
		if !stopped.steppedAside || !stopped.stoppedEngine || stopped.stoppedOther != other || stopped.stillAttached != "" {
			t.Fatalf("stopping reported %+v", stopped)
		}
		// The helper is asked who is attached before it lets go of it.
		fake.mu.Lock()
		asked := strings.Join(fake.asked, " ")
		fake.mu.Unlock()
		if asked != control.OpStatus+" "+control.OpDown {
			t.Fatalf("the helper was asked: %s", asked)
		}
	})

	t.Run("only the engine the helper has attached", func(t *testing.T) {
		directory := withTunnelStateDirectory(t)
		other, otherExited := standInEngine(t, "phase")
		startFakeTunnelHelper(t, control.Status{Attached: true, EnginePID: other, Capturing: true})
		stopped := stopTunnel(directory)
		if !gone(otherExited, 10*time.Second) || stopped.stoppedEngine || stopped.stoppedOther != other {
			t.Fatalf("stopping reported %+v", stopped)
		}
	})

	t.Run("the engine phase up started is the one attached", func(t *testing.T) {
		directory := withTunnelStateDirectory(t)
		pid, exited := standInEngine(t, "phase")
		recordEngine(t, directory, pid)
		startFakeTunnelHelper(t, control.Status{Attached: true, EnginePID: pid, Capturing: true})
		stopped := stopTunnel(directory)
		if !gone(exited, 10*time.Second) || !stopped.stoppedEngine || stopped.stoppedOther != 0 || stopped.stillAttached != "" {
			t.Fatalf("stopping reported %+v", stopped)
		}
	})

	// A test's engine, or anything else that isn't a phase binary running the engine,
	// isn't phase down's to stop. It is named instead.
	for name, start := range map[string]func(*testing.T) (int, chan struct{}){
		"a test's engine": func(t *testing.T) (int, chan struct{}) {
			return standInProcess(t, "engine.test", "-test.run=OnThisMac")
		},
		"another command of the CLI": func(t *testing.T) (int, chan struct{}) { return standInProcess(t, "phase", "tunnel", "helper") },
		"an engine by another name":  func(t *testing.T) (int, chan struct{}) { return standInEngine(t, "notphase") },
	} {
		t.Run(name, func(t *testing.T) {
			directory := withTunnelStateDirectory(t)
			other, otherExited := start(t)
			startFakeTunnelHelper(t, control.Status{Attached: true, EnginePID: other, Capturing: true})
			stopped := stopTunnel(directory)
			if gone(otherExited, 300*time.Millisecond) {
				t.Fatal("a process that isn't an engine of Phase's was stopped")
			}
			if stopped.stoppedOther != 0 || !strings.Contains(stopped.stillAttached, "(process "+strconv.Itoa(other)+")") {
				t.Fatalf("stopping reported %+v", stopped)
			}
		})
	}

	t.Run("the process that is asking", func(t *testing.T) {
		directory := withTunnelStateDirectory(t)
		startFakeTunnelHelper(t, control.Status{Attached: true, EnginePID: os.Getpid()})
		if stopped := stopTunnel(directory); stopped.stoppedOther != 0 || stopped.stillAttached != "" {
			t.Fatalf("stopping reported %+v", stopped)
		}
	})

	t.Run("an older helper that doesn't say", func(t *testing.T) {
		directory := withTunnelStateDirectory(t)
		pid, exited := standInEngine(t, "phase")
		recordEngine(t, directory, pid)
		startFakeTunnelHelper(t, control.Status{Attached: true, Capturing: true})
		stopped := stopTunnel(directory)
		if !gone(exited, 10*time.Second) || !stopped.stoppedEngine || stopped.stoppedOther != 0 || stopped.stillAttached != "" {
			t.Fatalf("stopping reported %+v", stopped)
		}
	})
}

// phase up doesn't start a second engine beside one that is attached already: the
// two would take the helper from each other every second.
func TestUpSeesAnEngineItDidNotStart(t *testing.T) {
	directory := withTunnelStateDirectory(t)
	if description, attached := otherEngineAttached(directory); attached {
		t.Fatalf("with no helper: %s", description)
	}
	pid, _ := standInEngine(t, "phase")
	recordEngine(t, directory, pid)
	startFakeTunnelHelper(t, control.Status{Attached: true, EnginePID: pid, Capturing: true})
	if description, attached := otherEngineAttached(directory); attached {
		t.Fatalf("phase up's own engine was taken for another: %s", description)
	}
	other, _ := standInEngine(t, "phase-dev")
	startFakeTunnelHelper(t, control.Status{Attached: true, EnginePID: other})
	if description, attached := otherEngineAttached(directory); !attached || description != "phase-dev (process "+strconv.Itoa(other)+")" {
		t.Fatalf("another engine is attached, and phase up saw %q (%v)", description, attached)
	}
	for name, status := range map[string]control.Status{
		"nothing attached":          {},
		"an engine that has gone":   {Attached: true, EnginePID: 2147483646},
		"a helper that doesn't say": {Attached: true},
	} {
		startFakeTunnelHelper(t, status)
		if description, attached := otherEngineAttached(directory); attached {
			t.Errorf("%s: %s", name, description)
		}
	}
}

// The command says each thing it did, and names what it left attached.
func TestDownSaysWhatItStoppedAndWhatIsStillAttached(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("phase down is only available on macOS for now")
	}
	directory := withTunnelStateDirectory(t)
	pid, exited := standInEngine(t, "phase")
	recordEngine(t, directory, pid)
	other, otherExited := standInEngine(t, "phase-dev")
	startFakeTunnelHelper(t, control.Status{Attached: true, EnginePID: other, Capturing: true})
	out, stderr, err := runPhaseCommand(t, "", "down")
	if err != nil || stderr != "" {
		t.Fatalf("phase down: %v %s", err, stderr)
	}
	want := "✅ Phase has stepped aside: your network works as it did before phase up.\n" +
		"✅ Stopped the engine.\n" +
		"✅ Stopped another engine that was attached to the helper (pid " + strconv.Itoa(other) + ").\n"
	if out != want || !gone(exited, 5*time.Second) || !gone(otherExited, 5*time.Second) {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}

	foreign, foreignExited := standInProcess(t, "engine.test", "-test.run=OnThisMac")
	startFakeTunnelHelper(t, control.Status{Attached: true, EnginePID: foreign, Capturing: true})
	out, stderr, err = runPhaseCommand(t, "", "down")
	if err != nil || stderr != "" {
		t.Fatalf("phase down: %v %s", err, stderr)
	}
	if !strings.Contains(out, "(process "+strconv.Itoa(foreign)+") is still attached to the helper") || !strings.Contains(out, "It brings Phase back until it is stopped.") ||
		gone(foreignExited, 300*time.Millisecond) {
		t.Fatalf("got:\n%s", out)
	}
}

func TestDescribeEngineProcess(t *testing.T) {
	for _, test := range []struct {
		listing     string
		description string
		ours        bool
	}{
		{"  501 /usr/local/bin/phase tunnel engine\n", "phase (process 7)", true},
		{"  501 /Users/someone/git/cli/phase-dev tunnel engine --routes 0.0.0.0/7", "phase-dev (process 7)", true},
		{"  501 /Users/someone/My Tools/phase tunnel engine --workflow w", "phase (process 7)", true},
		{"  501 phase tunnel engine", "phase (process 7)", true},
		// Someone else's, root's included.
		{"    0 /usr/local/bin/phase tunnel engine", "phase (process 7)", false},
		{"  502 /usr/local/bin/phase tunnel engine", "phase (process 7)", false},
		// Not the engine.
		{"  501 /usr/local/bin/phase tunnel helper --uid 501", "phase (process 7)", false},
		{"  501 /usr/local/bin/phase tunnel engineer", "phase (process 7)", false},
		{"  501 /usr/local/bin/phase up", "phase (process 7)", false},
		// Not a phase binary.
		{"  501 /var/folders/ab/T/go-build1/b001/engine.test -test.run=OnThisMac -test.v", "engine.test (process 7)", false},
		{"  501 /opt/tools/notphase tunnel engine", "notphase (process 7)", false},
		{"  501 /usr/bin/python3 fake.py tunnel engine", "python3 fake.py (process 7)", false},
		// Nothing ps could say.
		{"", "an unnamed program (process 7)", false},
		{"  501", "an unnamed program (process 7)", false},
		{"user /usr/local/bin/phase tunnel engine", "phase (process 7)", false},
	} {
		description, ours := describeEngineProcess(7, test.listing, 501)
		if description != test.description || ours != test.ours {
			t.Errorf("%q: %q, %v", test.listing, description, ours)
		}
	}
}

// withTunnelLockWait shortens how long phase up and phase down wait for one another.
func withTunnelLockWait(t *testing.T, wait time.Duration) {
	t.Helper()
	original := tunnelLockWait
	tunnelLockWait = wait
	t.Cleanup(func() { tunnelLockWait = original })
}

// Two runs of phase up at once start one engine between them. Each looks for an
// engine before it starts one, and without a lock both find none: the second engine
// would take the helper from the first every second, and the machine's routes with it.
func TestTwoRunsOfUpStartOneEngine(t *testing.T) {
	directory := withTunnelStateDirectory(t)
	startFakeTunnelHelper(t, control.Status{})
	pid, _ := standInEngine(t, "phase")
	var mu sync.Mutex
	launches := 0
	original := launchTunnelEngine
	launchTunnelEngine = func(directory, _ string, _ []string) (int, error) {
		mu.Lock()
		launches++
		mu.Unlock()
		// An engine takes a moment to start, and is on record only afterwards.
		time.Sleep(300 * time.Millisecond)
		return pid, os.WriteFile(tunnelEnginePIDPath(directory), []byte(strconv.Itoa(pid)), 0o600)
	}
	t.Cleanup(func() { launchTunnelEngine = original })

	outputs := make([]bytes.Buffer, 2)
	failures := make([]error, 2)
	var done sync.WaitGroup
	for run := range outputs {
		done.Add(1)
		go func() {
			defer done.Done()
			failures[run] = ensureTunnelEngine(&outputs[run], directory, "", nil)
		}()
	}
	done.Wait()
	said := outputs[0].String() + outputs[1].String()
	if failures[0] != nil || failures[1] != nil || launches != 1 {
		t.Fatalf("%d engines were started: %v, %v\n%s", launches, failures[0], failures[1], said)
	}
	if strings.Count(said, "Started the engine as you") != 1 || strings.Count(said, "The engine is already running (pid "+strconv.Itoa(pid)+")") != 1 {
		t.Fatalf("the two runs said:\n%s", said)
	}
}

// phase down waits its turn behind a phase up that is starting an engine: looking
// before the engine is on record, it would find nothing to stop.
func TestDownWaitsForAnUpThatIsStartingAnEngine(t *testing.T) {
	directory := withTunnelStateDirectory(t)
	fake := startFakeTunnelHelper(t, control.Status{Capturing: true})
	unlock, err := lockTunnel(directory)
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan tunnelStop, 1)
	go func() { finished <- stopTunnel(directory) }()
	select {
	case stopped := <-finished:
		unlock()
		t.Fatalf("phase down didn't wait for phase up: %+v", stopped)
	case <-time.After(400 * time.Millisecond):
	}
	if fake.askedTo(control.OpDown) != 0 {
		unlock()
		t.Fatal("the helper was asked to step aside while phase up was still starting an engine")
	}
	unlock()
	select {
	case stopped := <-finished:
		if !stopped.steppedAside || fake.askedTo(control.OpDown) != 1 {
			t.Fatalf("stopping reported %+v", stopped)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("phase down never took its turn")
	}
}

// Stepping aside is never refused. When the lock can't be had, phase down goes ahead
// without it; phase up, which only adds to what runs, says to try again instead.
func TestALockThatIsNeverGivenUp(t *testing.T) {
	directory := withTunnelStateDirectory(t)
	fake := startFakeTunnelHelper(t, control.Status{Capturing: true})
	withTunnelLockWait(t, 200*time.Millisecond)
	unlock, err := lockTunnel(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	if stopped := stopTunnel(directory); !stopped.steppedAside || fake.askedTo(control.OpDown) != 1 {
		t.Fatalf("with the lock held by another, stopping reported %+v", stopped)
	}

	launched := false
	original := launchTunnelEngine
	launchTunnelEngine = func(string, string, []string) (int, error) { launched = true; return 0, nil }
	t.Cleanup(func() { launchTunnelEngine = original })
	var out bytes.Buffer
	if err := ensureTunnelEngine(&out, directory, "", nil); !errors.Is(err, errTunnelBusy) || launched {
		t.Fatalf("with the lock held by another, phase up returned %v (started an engine: %v)", err, launched)
	}
}

// With no state directory there is nothing of phase up's to wait for, and phase down
// still asks the helper to step aside. It makes no directory of its own.
func TestDownNeedsNoStateDirectory(t *testing.T) {
	directory := filepath.Join(withTunnelStateDirectory(t), "never-made")
	fake := startFakeTunnelHelper(t, control.Status{Capturing: true})
	if stopped := stopTunnel(directory); !stopped.steppedAside || fake.askedTo(control.OpDown) != 1 {
		t.Fatalf("stopping reported %+v", stopped)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("phase down made the state directory: %v", err)
	}
}
