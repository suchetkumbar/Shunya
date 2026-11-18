package engine

import (
	"fmt"

	"shunya/internal/device"
	"shunya/internal/nvme"
)

// Option is one method the planner considered for a device.
type Option struct {
	Method    string `json:"method"`
	Level     Level  `json:"nist_level"`
	Available bool   `json:"available"`
	Why       string `json:"why"`
}

// Recommendation is the planner's answer: every option in preference order and the
// one it would choose. Shunya never applies it on its own: the operator passes
// --method (a one-click mode may later apply Best).
type Recommendation struct {
	Options []Option `json:"options"`
	Best    string   `json:"best"`
	Reason  string   `json:"reason"`
}

// RecommendInput is what the probes found.
type RecommendInput struct {
	Media   device.MediaType
	Virtual bool
	Hidden  *HiddenPlan // ATA facts (nil or unchecked: not ATA)
	NVMe    *NVMePlan
	// Preconditions holds the state checks done against the live drive (frozen
	// security, frozen sanitize, foreign password, …) per method; nil error = met.
	Preconditions map[string]error
}

// Preference order per command set: strongest and cheapest Purge first. Crypto erase
// is instant and covers spare blocks; block erase next; Format (namespace-scoped,
// vendor-defined scope for SES 1) after Sanitize; overwrite sanitize last (slow, wears
// flash); ATA Security Erase after Sanitize because its reach on flash is vendor-defined.
var (
	ataOrder  = []string{MethodATASanitizeCrypto, MethodATASanitizeBlock, MethodATASanitizeOverwrite, MethodATAEnhancedErase, MethodATAErase}
	nvmeOrder = []string{MethodNVMeSanitizeCrypto, MethodNVMeSanitizeBlock, MethodNVMeFormatCrypto, MethodNVMeFormatUserData, MethodNVMeSanitizeOverwrite}
)

// Recommend ranks the methods for a device.
func Recommend(in RecommendInput) Recommendation {
	var r Recommendation
	add := func(m string, ok bool, why string) {
		lv := LevelClear
		if m != MethodOverwrite {
			lv = firmwareLevel(m, in.Media, in.Virtual, in.Hidden)
		}
		r.Options = append(r.Options, Option{Method: m, Level: lv, Available: ok, Why: why})
	}
	switch {
	case in.NVMe != nil:
		nv := in.NVMe
		for _, m := range nvmeOrder {
			var err error
			if IsSanitize(m) {
				err = nvme.CheckSanitize(&nv.Controller, nv.Active, NVMeSanitizeAction(m))
			} else {
				err = nvme.CheckFormat(&nv.Controller, &nv.Namespace, nv.Active, NVMeFormatSES(m))
			}
			if err == nil {
				err = in.Preconditions[m]
			}
			add(m, err == nil, whyOf(m, err))
		}
	case in.Hidden != nil && in.Hidden.Before.Checked:
		h := in.Hidden
		for _, m := range ataOrder {
			var err error
			switch {
			case IsSanitize(m):
				s := h.Sanitize
				if s == nil || !s.Supported {
					err = fmt.Errorf("the drive does not support the Sanitize feature set (IDENTIFY word 59)")
				} else if !map[string]bool{MethodATASanitizeCrypto: s.CryptoScramble, MethodATASanitizeBlock: s.BlockErase, MethodATASanitizeOverwrite: s.Overwrite}[m] {
					err = fmt.Errorf("not advertised in IDENTIFY word 59")
				}
			case h.Security == nil || !h.Security.Supported:
				err = fmt.Errorf("the drive does not support the ATA Security feature set")
			case m == MethodATAEnhancedErase && !h.Security.EnhancedSupported:
				err = fmt.Errorf("enhanced erase not supported (word 128 bit 5)")
			}
			if err == nil {
				err = in.Preconditions[m]
			}
			add(m, err == nil, whyOf(m, err))
		}
	}
	add(MethodOverwrite, true, "one pass of an AES-256-CTR random stream over every addressable sector, verifiable by read-back; never reaches spare, retired or remapped blocks")
	for _, o := range r.Options {
		if o.Available && o.Level == LevelPurge {
			r.Best, r.Reason = o.Method, "the strongest available method that reaches Purge on this medium"
			return r
		}
	}
	for _, o := range r.Options {
		if o.Available {
			r.Best = o.Method
			r.Reason = "no Purge method is available on this device; this is the strongest Clear method"
			if in.Virtual {
				r.Reason = "the device is virtual, so nothing can reach Purge; this is the strongest Clear method"
			}
			return r
		}
	}
	return r
}

func whyOf(m string, err error) string {
	if err != nil {
		return err.Error()
	}
	if t := methodText[m]; t != "" {
		return t
	}
	switch m {
	case MethodATAErase:
		return "ATA SECURITY ERASE UNIT, normal: the drive writes zeros to all user data (verifiable)"
	case MethodATAEnhancedErase:
		return "ATA SECURITY ERASE UNIT, enhanced: vendor pattern or key change; reach on flash is vendor-defined"
	}
	return ""
}
