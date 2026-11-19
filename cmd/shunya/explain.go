package main

import (
	"fmt"
	"io"
	"strings"
)

// Explanation turns a refusal or failure into plain language: what happened, why
// Shunya stops there, and what the operator can do about it.
type Explanation struct {
	What string
	Why  string
	Do   string
}

// explainRule matches messages that Shunya itself produces (the tests feed the real
// messages from the guard, the ATA layer, the engine and the log client into Explain,
// so a reworded message that no longer matches fails a test).
type explainRule struct {
	any []string // any of these substrings
	e   Explanation
}

var explainRules = []explainRule{
	{[]string{"root filesystem /", "boot filesystem", "holds the running shunya binary"}, Explanation{
		What: "This disk runs the computer you are using (system, boot or Shunya's own disk).",
		Why:  "Wiping it would destroy the running system, so Shunya never allows it, in any build.",
		Do:   "Pick another disk. To wipe this one, boot Shunya from a USB stick or another disk.",
	}},
	{[]string{"mounted at "}, Explanation{
		What: "The disk has a file system that is in use (mounted).",
		Why:  "Shunya does not wipe a disk while programs may still be writing to it.",
		Do:   "Unmount it first (save your work, then eject it or run umount on each mount point), and try again.",
	}},
	{[]string{"held by ", "member of btrfs", "logical device"}, Explanation{
		What: "The disk is part of a RAID, LVM, encrypted volume or similar set that is active.",
		Why:  "Wiping one member of an active set corrupts the whole set under the running system.",
		Do:   "Stop the set (vgchange -an, mdadm --stop, cryptsetup close …), or wipe the underlying disks one by one.",
	}},
	{[]string{"active swap"}, Explanation{
		What: "The disk is being used as swap memory.",
		Why:  "The system writes to swap at any moment; wiping it under the system crashes programs.",
		Do:   "Turn that swap off first (swapoff), then try again.",
	}},
	{[]string{"lab lock:"}, Explanation{
		What: "This is a development build, and it only touches real disks inside the lab virtual machine.",
		Why:  "Development builds are locked to the lab so that a mistake cannot wipe a developer's own computer.",
		Do:   "Use a release build on the wiping station, or run inside the lab VM (make lab-up). Image files work anywhere.",
	}},
	{[]string{"Security FROZEN mode"}, Explanation{
		What: "The drive refuses ATA Security Erase: its security is frozen.",
		Why:  "The computer's firmware froze the drive at start-up; it stays frozen until the drive loses power.",
		Do:   "Suspend the computer to RAM and wake it (or unplug and replug the drive's power if the port allows hot-plug), then run Shunya again. Or choose another method.",
	}},
	{[]string{"Sanitize FROZEN state"}, Explanation{
		What: "The drive refuses Sanitize: sanitize is frozen.",
		Why:  "The computer's firmware froze sanitize at start-up; it lasts until the drive loses power.",
		Do:   "Suspend and resume the computer (or hot-plug the drive), then try again, or choose another method.",
	}},
	{[]string{"a user password is already set", "locked with an unknown password", "password attempt counter has expired"}, Explanation{
		What: "The drive has a password that Shunya did not set.",
		Why:  "Shunya never guesses or overrides somebody else's drive password.",
		Do:   "Have the owner remove the password, or use an overwrite. If the counter expired, power-cycle the drive first.",
	}},
	{[]string{"device identity changed"}, Explanation{
		What: "The disk changed between choosing it and wiping it (different serial, size or sector size).",
		Why:  "A swapped disk must never receive another disk's wipe, nor its certificate.",
		Do:   "Check which disk is connected, choose it again and start over.",
	}},
	{[]string{"journal must not live on the wipe target"}, Explanation{
		What: "The progress journal would be on the disk being wiped.",
		Why:  "The journal proves what happened; it must survive the wipe, so it lives on Shunya's own medium.",
		Do:   "Put the journal (--journal or --journal-dir) on another disk, such as the USB stick Shunya runs from.",
	}},
	{[]string{"does not match the last", "type the last 4 characters", "is not in the approved list"}, Explanation{
		What: "The wipe was not confirmed for this disk.",
		Why:  "Typing the end of the serial number makes sure the disk on the screen is the one you mean.",
		Do:   "Read the serial on the screen (or on the drive's label) and type its last 4 characters. In fleet mode, add the disk's fingerprint to the approved list.",
	}},
	{[]string{"no serial number or WWID", "no serial number to confirm against"}, Explanation{
		What: "The disk reports no serial number.",
		Why:  "Without one, a swapped disk could not be detected and a certificate could not name the disk.",
		Do:   "Use another adapter or port that passes the serial through (some USB adapters hide it).",
	}},
	{[]string{"transparency log unreachable"}, Explanation{
		What: "The transparency log could not be reached.",
		Why:  "Without it there is no seed nobody can predict, and certificates cannot be logged yet.",
		Do:   "Check the network and the log address. The wipe still completes (full read-back instead of sampling); log the certificate later with shunya cert submit.",
	}},
	{[]string{"station key revoked"}, Explanation{
		What: "This wiping station's key has been revoked by the organisation.",
		Why:  "A revoked station must not issue certificates or get sampling seeds.",
		Do:   "Ask the organisation's administrator for a new station key and certificate.",
	}},
	{[]string{"uncertified development key"}, Explanation{
		What: "The station key has no certificate from the organisation's root.",
		Why:  "Verifiers trust only stations the organisation certified.",
		Do:   "Have the administrator run shunya keys issue-station for this station, and pass --station-cert.",
	}},
	{[]string{"device is read-only"}, Explanation{
		What: "The disk is write-protected.",
		Why:  "A read-only disk cannot be wiped.",
		Do:   "Check for a write-protect switch on the drive or adapter.",
	}},
}

// Explain returns the explanations that match an error text, most specific first, at
// most one per rule.
func Explain(text string) []Explanation {
	var out []Explanation
	for _, r := range explainRules {
		for _, s := range r.any {
			if strings.Contains(text, s) {
				out = append(out, r.e)
				break
			}
		}
	}
	return out
}

// printExplanations writes the explanations for an error text, if any match.
func printExplanations(w io.Writer, text string) {
	for _, e := range Explain(text) {
		fmt.Fprintf(w, "\nWHAT HAPPENED: %s\n  why:        %s\n  what to do: %s\n", e.What, e.Why, e.Do)
	}
}
