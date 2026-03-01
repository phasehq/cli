package util

import (
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Spinner is a transient braille-dot spinner that writes to stderr.
type Spinner struct {
	message string
	stop    chan struct{}
	done    sync.WaitGroup
}

// NewSpinner creates a spinner with the given message.
func NewSpinner(message string) *Spinner {
	return &Spinner{
		message: message,
		stop:    make(chan struct{}),
	}
}

// Start begins the spinner animation in a background goroutine.
func (s *Spinner) Start() {
	if !term.IsTerminal(int(syscall.Stderr)) {
		return
	}

	s.done.Add(1)
	go func() {
		defer s.done.Done()
		i := 0
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-s.stop:
				// Clear the spinner line
				fmt.Fprintf(os.Stderr, "\r\033[K")
				return
			case <-ticker.C:
				frame := spinnerFrames[i%len(spinnerFrames)]
				msg := BoldGreenErr(s.message)
				fmt.Fprintf(os.Stderr, "\r%s %s", frame, msg)
				i++
			}
		}
	}()
}

// Stop halts the spinner and clears the line.
func (s *Spinner) Stop() {
	select {
	case <-s.stop:
		// Already stopped
		return
	default:
		close(s.stop)
	}
	s.done.Wait()
}
