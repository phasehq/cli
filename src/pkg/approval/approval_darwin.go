//go:build darwin && cgo

package approval

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework LocalAuthentication -framework Foundation
#include <stdlib.h>
#include <string.h>
#import <LocalAuthentication/LocalAuthentication.h>

// phase_approve shows the system authentication sheet (Touch ID / Apple Watch,
// with device-password fallback) and blocks until the user acts.
// Returns 1 approved, 0 denied, -1 unavailable. errOut is malloc'd on non-1.
static int phase_approve(const char *reason, char **errOut) {
	LAContext *ctx = [[LAContext alloc] init];
	NSError *availErr = nil;
	if (![ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&availErr]) {
		if (errOut && availErr) *errOut = strdup([[availErr localizedDescription] UTF8String]);
		return -1;
	}
	dispatch_semaphore_t sema = dispatch_semaphore_create(0);
	__block int approved = 0;
	__block char *denyMsg = NULL;
	[ctx evaluatePolicy:LAPolicyDeviceOwnerAuthentication
	    localizedReason:[NSString stringWithUTF8String:reason]
	              reply:^(BOOL success, NSError *err) {
		if (success) {
			approved = 1;
		} else if (err) {
			denyMsg = strdup([[err localizedDescription] UTF8String]);
		}
		dispatch_semaphore_signal(sema);
	}];
	dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
	if (!approved && errOut) {
		*errOut = denyMsg;
	} else if (denyMsg) {
		free(denyMsg);
	}
	return approved;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Require blocks until the device owner approves via the macOS authentication
// prompt (Touch ID / Apple Watch / account password). The prompt is a system
// GUI dialog, so it works even when the caller has no TTY (agent shells).
func Require(reason string) error {
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))
	var cErr *C.char
	rc := C.phase_approve(cReason, &cErr)
	if cErr != nil {
		defer C.free(unsafe.Pointer(cErr))
	}
	switch rc {
	case 1:
		return nil
	case -1:
		return fmt.Errorf("device-owner authentication unavailable: %s", C.GoString(cErr))
	default:
		msg := "denied by user"
		if cErr != nil {
			msg = C.GoString(cErr)
		}
		return fmt.Errorf("approval not granted: %s", msg)
	}
}
