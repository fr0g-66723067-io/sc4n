//go:build race

package pysrc

// raceEnabled is true in a -race build. The timing guards in this package measure
// wall time, and the race detector's instrumentation inflates them enough that a
// loaded host pushes a passing analysis over its budget (measured 8.5 s against a
// 10 s budget for TestNestedCallsAreBounded under -race, versus 1.9 s without).
// A guard that fails for the host's sake hides the regression it exists to catch,
// so it steps aside under -race: `make test` runs the untagged pass too, and that
// is where the guard does its work.
const raceEnabled = true
