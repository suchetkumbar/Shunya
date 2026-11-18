# IDENTIFY DEVICE dumps

Each file holds 256 IDENTIFY DEVICE words as `hdparm --Istdout` prints them, with a
`#` header naming the drive and the page it was copied from. The dumps were published
by their owners in public bug reports, mailing-list threads, gists and blog posts. They
are factual device data (no personal data apart from drive serial numbers that are
already public on those pages). Shunya's parser tests compare them against the tool
output published *next to* each dump (hdparm -I / hdparm -i, written by a different
program) wherever that output exists.

| File | Drive | Source | Oracle published with it |
|---|---|---|---|
| `samsung-hd321kj.txt` | Samsung HD321KJ, 320 GB SATA HDD | https://www.zeitgeist.se/2014/09/07/enabling-ata-security-on-a-self-encrypting-ssd/ | `hdparm -I`: model, serial, firmware, Security state, 112 min erase times |
| `owc-mercury-extreme-pro-ssd.txt` | OWC Mercury Extreme Pro SSD | https://gist.github.com/boondaburrah/1135836 | `hdparm -i`: model, firmware, serial, LBAsects; also hdparm's IDENTIFY CDB and the drive's descriptor sense (used in `sense_test.go`) |
| `intel-ssdsa2ct040g3.txt` | Intel SSD 320 40 GB (SSDSA2CT040G3) | https://bugs.launchpad.net/ubuntu/+source/hdparm/+bug/816844 | model name quoted in the report; Security **frozen** by the reporter's BIOS |
| `sil-external-raid.txt` | "External Disk 0", a RAID volume behind a SiI SATA controller | https://linux-ide.vger.kernel.narkive.com/aPVJYXl4/sata-sil24-external-raid-storage-mistaken-as-port-multiplier | serial `070C05F_879391___0_8` quoted in the thread |

Downloaded 2026-11-18. The lab VM's QEMU drives are recorded separately by the lab
test (`lab/results/…/identify-*.txt`); they are emulated devices, not real ones.

None of these drives had an HPA, a DCO restriction or a password set when dumped.
Those states are produced by the simulated drive (`internal/ata/atafake`), which starts
from these dumps and rewrites the capacity and Security words; anything proven only
that way is labelled **pending-real-hardware**.
