// Package owner finds the program behind a connection on this machine, and says which
// AI coding tool it is.
//
// The tunnel sees every program's traffic. A tool's model traffic is read only for
// that tool's own processes, so the question has to be answered per connection, when
// it opens, from the program's executable: a working directory says nothing about a
// connection opened before the tool moved into the project, and tools rewrite their
// own process names.
package owner

import (
	"errors"
	"time"
)

// Process is a program that owns a connection.
type Process struct {
	PID int
	// Executable is the path the program was started with, which may be a link.
	Executable string
	// Args are its arguments, the first being the name it was started as.
	Args []string
}

// Wait is the longest a lookup takes. A caller's own deadline may be shorter.
const Wait = 500 * time.Millisecond

var (
	// ErrNotFound means no program this user can see owns the connection: it belongs
	// to another user, came from a container or another machine, or has gone.
	ErrNotFound = errors.New("no program owns that connection")
	// ErrUnsupported means this system has no way to find a connection's program yet.
	ErrUnsupported = errors.New("finding a connection's program isn't supported on this system")
	// ErrShared means programs started from different executables hold the
	// connection, so it can't be said to belong to one of them.
	ErrShared = errors.New("more than one program holds that connection")
)
