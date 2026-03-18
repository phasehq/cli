package mcp

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/phasehq/cli/pkg/util"
)

// RingBuffer is a thread-safe fixed-size line buffer for capturing process output.
type RingBuffer struct {
	mu    sync.Mutex
	lines []string
	max   int
	pos   int
	full  bool
}

func NewRingBuffer(maxLines int) *RingBuffer {
	return &RingBuffer{
		lines: make([]string, maxLines),
		max:   maxLines,
	}
}

func (rb *RingBuffer) Write(line string) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.lines[rb.pos] = line
	rb.pos++
	if rb.pos >= rb.max {
		rb.pos = 0
		rb.full = true
	}
}

// Lines returns the last n lines in chronological order.
func (rb *RingBuffer) Lines(n int) []string {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	var total int
	if rb.full {
		total = rb.max
	} else {
		total = rb.pos
	}
	if n <= 0 || n > total {
		n = total
	}

	result := make([]string, n)
	start := rb.pos - n
	if start < 0 {
		if rb.full {
			start += rb.max
		} else {
			start = 0
			n = rb.pos
			result = result[:n]
		}
	}
	for i := 0; i < n; i++ {
		result[i] = rb.lines[(start+i)%rb.max]
	}
	return result
}

// ManagedProcess tracks a process started via phase_run.
type ManagedProcess struct {
	Cmd       *exec.Cmd
	Command   string
	Started   time.Time
	PID       int
	LogBuffer *RingBuffer
	Done      chan struct{}
	ExitCode  int
}

// ProcessManager manages background processes started via MCP tools.
type ProcessManager struct {
	mu        sync.Mutex
	processes map[int]*ManagedProcess
	nextID    int
}

func NewProcessManager() *ProcessManager {
	return &ProcessManager{
		processes: make(map[int]*ManagedProcess),
		nextID:    1,
	}
}

// Start launches a command with the given environment variables injected.
func (pm *ProcessManager) Start(command string, env map[string]string) (int, *ManagedProcess, error) {
	shell := util.GetDefaultShell()
	var cmd *exec.Cmd
	if len(shell) > 0 {
		cmd = exec.Command(shell[0], "-c", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}

	// Inherit current env + injected secrets
	envSlice := os.Environ()
	for k, v := range env {
		envSlice = append(envSlice, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = envSlice

	// Set process group so we can kill the whole tree
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	logBuf := NewRingBuffer(500)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return 0, nil, fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return 0, nil, fmt.Errorf("start: %w", err)
	}

	mp := &ManagedProcess{
		Cmd:       cmd,
		Command:   command,
		Started:   time.Now(),
		PID:       cmd.Process.Pid,
		LogBuffer: logBuf,
		Done:      make(chan struct{}),
		ExitCode:  -1,
	}

	// Stream stdout/stderr into ring buffer
	capture := func(r io.Reader, prefix string) {
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 256*1024), 256*1024)
		for scanner.Scan() {
			logBuf.Write(prefix + scanner.Text())
		}
	}
	go capture(stdout, "")
	go capture(stderr, "")

	// Wait for process in background
	go func() {
		err := cmd.Wait()
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				mp.ExitCode = exitErr.ExitCode()
			}
		} else {
			mp.ExitCode = 0
		}
		close(mp.Done)
	}()

	pm.mu.Lock()
	handle := pm.nextID
	pm.nextID++
	pm.processes[handle] = mp
	pm.mu.Unlock()

	return handle, mp, nil
}

// Stop terminates a process by handle. Sends SIGTERM, then SIGKILL after 5s.
func (pm *ProcessManager) Stop(handle int) error {
	pm.mu.Lock()
	mp, ok := pm.processes[handle]
	pm.mu.Unlock()
	if !ok {
		return fmt.Errorf("no process with handle %d", handle)
	}

	select {
	case <-mp.Done:
		return nil // already exited
	default:
	}

	// Kill the process group
	pgid, err := syscall.Getpgid(mp.PID)
	if err == nil {
		_ = syscall.Kill(-pgid, syscall.SIGTERM)
	} else {
		_ = mp.Cmd.Process.Signal(syscall.SIGTERM)
	}

	select {
	case <-mp.Done:
		return nil
	case <-time.After(5 * time.Second):
		if pgid, err := syscall.Getpgid(mp.PID); err == nil {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		} else {
			_ = mp.Cmd.Process.Kill()
		}
		<-mp.Done
		return nil
	}
}

// Get returns a managed process by handle.
func (pm *ProcessManager) Get(handle int) (*ManagedProcess, bool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	mp, ok := pm.processes[handle]
	return mp, ok
}

// IsRunning checks if a process is still running.
func (pm *ProcessManager) IsRunning(mp *ManagedProcess) bool {
	select {
	case <-mp.Done:
		return false
	default:
		return true
	}
}

// List returns info about all managed processes.
func (pm *ProcessManager) List() map[int]*ManagedProcess {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	cp := make(map[int]*ManagedProcess, len(pm.processes))
	for k, v := range pm.processes {
		cp[k] = v
	}
	return cp
}

// StopAll kills all managed processes. Called on server shutdown.
func (pm *ProcessManager) StopAll() {
	pm.mu.Lock()
	handles := make([]int, 0, len(pm.processes))
	for h := range pm.processes {
		handles = append(handles, h)
	}
	pm.mu.Unlock()

	for _, h := range handles {
		_ = pm.Stop(h)
	}
}

// Status returns a text summary of a process.
func (pm *ProcessManager) Status(handle int) string {
	mp, ok := pm.Get(handle)
	if !ok {
		return fmt.Sprintf("handle %d: not found", handle)
	}
	running := pm.IsRunning(mp)
	status := "running"
	if !running {
		status = fmt.Sprintf("exited (code %d)", mp.ExitCode)
	}
	elapsed := time.Since(mp.Started).Truncate(time.Second)
	return fmt.Sprintf("handle %d: pid=%d, command=%q, status=%s, uptime=%s",
		handle, mp.PID, mp.Command, status, elapsed)
}

// StatusAll returns a summary of all processes.
func (pm *ProcessManager) StatusAll() string {
	all := pm.List()
	if len(all) == 0 {
		return "No managed processes."
	}
	var sb strings.Builder
	for h := range all {
		sb.WriteString(pm.Status(h))
		sb.WriteString("\n")
	}
	return sb.String()
}
