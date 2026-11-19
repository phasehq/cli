//go:build !darwin

package owner

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// Where there's no way to find a connection's program, the answer says so, and the
// router leaves the flow unread.
func TestLookupIsNotSupportedHere(t *testing.T) {
	process, err := Lookup(context.Background(), 50000, netip.MustParseAddrPort("192.0.2.1:443"))
	if !errors.Is(err, ErrUnsupported) || Identify(process) != "" {
		t.Fatalf("%+v, %v", process, err)
	}
}
