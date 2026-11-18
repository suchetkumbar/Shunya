package nvme

import (
	"context"
	"fmt"
	"strings"
	"time"

	"shunya/internal/sanitize"
)

// ActionName is the method word for a sanitize action.
func ActionName(action int) string {
	return map[int]string{SanactBlockErase: "block-erase", SanactCryptoErase: "crypto-erase", SanactOverwrite: "overwrite"}[action]
}

// SanitizeOp is an NVMe Sanitize as a sanitize.Operation.
type SanitizeOp struct {
	D       Device
	Action  int
	Passes  int    // overwrite only
	Pattern uint32 // overwrite only
}

var _ sanitize.Operation = SanitizeOp{}

func (o SanitizeOp) Name() string { return "nvme-sanitize-" + ActionName(o.Action) }

// Status maps the Sanitize Status log page. A completed sanitize is attested when the
// controller reports Global Data Erased (nothing written since) and its last sanitize
// used this action.
func (o SanitizeOp) Status(ctx context.Context) (sanitize.Status, error) {
	l, err := o.D.SanitizeStatus(ctx)
	if err != nil {
		return sanitize.Status{}, err
	}
	switch l.Status {
	case SanitizeInProgress:
		return sanitize.Status{Phase: sanitize.InProgress, Progress: l.Progress}, nil
	case SanitizeCompleted, SanitizeCompletedNoDeal:
		return sanitize.Status{Phase: sanitize.Completed, Attested: l.GlobalDataErased && l.Action() == o.Action,
			Detail: fmt.Sprintf("SSTAT %d, global data erased %v, last action %s", l.Status, l.GlobalDataErased, ActionName(l.Action()))}, nil
	case SanitizeFailed:
		return sanitize.Status{Phase: sanitize.Failed, Detail: "SSTAT 3: most recent sanitize failed"}, nil
	}
	return sanitize.Status{Phase: sanitize.Idle}, nil
}

// Start sends the Sanitize command.
func (o SanitizeOp) Start(ctx context.Context) error {
	c, err := Sanitize(o.Action, o.Passes, o.Pattern)
	if err != nil {
		return err
	}
	_, err = o.D.Exec(ctx, c, nil)
	return err
}

// Refusal lists why an NVMe erase can't run.
type Refusal struct{ Reasons []string }

func (r *Refusal) Error() string { return "refused: " + strings.Join(r.Reasons, "; ") }

func refusal(why []string) error {
	if len(why) == 0 {
		return nil
	}
	return &Refusal{Reasons: why}
}

// scopeReasons: a sanitize (always) or a format whose FNA says it applies to all
// namespaces reaches every namespace and, with several controllers, data other hosts
// use. Shunya erases only when the target namespace is the only one.
func scopeReasons(c *Controller, active []uint32, what string) []string {
	var why []string
	if len(active) > 1 {
		why = append(why, fmt.Sprintf("%s would also erase %d other namespace(s) of this controller (active NSIDs %v); Shunya erases only a controller whose sole namespace is the target", what, len(active)-1, active))
	}
	if c.CMIC&2 != 0 {
		why = append(why, what+" reaches the whole NVM subsystem, which has more than one controller (CMIC bit 1): other hosts may use it")
	}
	return why
}

// CheckSanitize reports whether a Sanitize with action can run.
func CheckSanitize(c *Controller, active []uint32, action int) error {
	var why []string
	switch {
	case !c.Sanicap.Any():
		why = append(why, "the controller does not support Sanitize (SANICAP = 0)")
	case action == SanactCryptoErase && !c.Sanicap.Crypto:
		why = append(why, "crypto erase sanitize not supported (SANICAP bit 0)")
	case action == SanactBlockErase && !c.Sanicap.Block:
		why = append(why, "block erase sanitize not supported (SANICAP bit 1)")
	case action == SanactOverwrite && !c.Sanicap.Overwrite:
		why = append(why, "overwrite sanitize not supported (SANICAP bit 2)")
	}
	return refusal(append(why, scopeReasons(c, active, "Sanitize")...))
}

// CheckFormat reports whether a Format NVM with ses can run on namespace n.
func CheckFormat(c *Controller, n *Namespace, active []uint32, ses int) error {
	var why []string
	if !c.FormatSupported {
		why = append(why, "the controller does not support Format NVM (OACS bit 1)")
	}
	if ses == SESCryptoErs && !c.FNA.CryptoErase {
		why = append(why, "cryptographic erase is not supported (FNA bit 2 clear). A controller may still complete the command successfully (QEMU does) without changing any key, so Shunya trusts the capability bit, not the status")
	}
	if c.FNA.FormatAllNamespaces || c.FNA.SecureEraseAllNamespaces {
		why = append(why, scopeReasons(c, active, "Format NVM")...)
	}
	if n.Shared && c.CMIC&2 != 0 {
		why = append(why, "the namespace may be attached to another controller of this multi-controller subsystem (NMIC bit 0, CMIC bit 1)")
	}
	return refusal(why)
}

// FormatTimeout bounds a Format NVM.
const FormatTimeout = 2 * time.Hour

// FormatCmd builds the Format NVM for n that keeps its LBA format, metadata and
// protection settings.
func FormatCmd(n *Namespace, ses int) (Command, error) {
	return FormatNVM(n.NSID, n.LBAF, ses, n.MetadataExtended, n.PIType, n.PIFirst, FormatTimeout)
}
