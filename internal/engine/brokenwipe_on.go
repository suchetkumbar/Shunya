//go:build brokenwipe

package engine

// brokenTailPercent: TEST-ONLY BUILD. The writer skips the last 1 % of every pass while
// still journalling it as written. Built only as bin/lab/shunya-broken for the canary
// harness's negative test; never shipped (see design/SAFETY.md).
const brokenTailPercent = 1
