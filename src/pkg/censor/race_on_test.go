//go:build race

package censor

// raceEnabled loosens timing checks: the race detector slows scans down
// several times.
const raceEnabled = true
