//go:build !brokenwipe

package engine

// brokenTailPercent is the share of each pass the writer deliberately skips. It exists
// only to prove the canary harness catches an incomplete wipe; in every build without
// the brokenwipe tag it is the constant 0 and the skip is compiled out.
const brokenTailPercent = 0
