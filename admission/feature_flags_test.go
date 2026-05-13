/*
FILE PATH:

	admission/feature_flags_test.go

DESCRIPTION:

	Pin LoadGatesFromEnv parsing semantics and the default-OFF
	posture of every gate. The defaults are load-bearing — a
	regression that quietly turns a gate ON would change the
	admission contract without code review.
*/
package admission

import (
	"testing"
)

func TestGates_DefaultAllOff(t *testing.T) {

	// Unset all four env vars to ensure the defaults are seen.
	t.Setenv("LEDGER_ADMISSION_MULTISIG_ENABLE", "")
	t.Setenv("LEDGER_ADMISSION_COSIG_BINDING_ENABLE", "")
	t.Setenv("LEDGER_ADMISSION_POLICY_ENABLE", "")
	t.Setenv("LEDGER_ADMISSION_EVIDENCE_CHAIN_ENABLE", "")

	g := LoadGatesFromEnv()
	if g.MultiSig {
		t.Error("MultiSig defaulted ON; expected OFF for canary discipline")
	}
	if g.CosigBinding {
		t.Error("CosigBinding defaulted ON; expected OFF for canary discipline")
	}
	if g.Policy {
		t.Error("Policy defaulted ON; expected OFF (explicit opt-in)")
	}
	if g.EvidenceChain {
		t.Error("EvidenceChain defaulted ON; expected OFF (surgical only)")
	}
}

func TestGates_TruthyValues(t *testing.T) {

	cases := []string{"true", "TRUE", "True", "1", "yes", "YES", "on", "ON", " true "}
	for _, val := range cases {
		val := val
		t.Run(val, func(t *testing.T) {
			t.Setenv("LEDGER_ADMISSION_MULTISIG_ENABLE", val)
			t.Setenv("LEDGER_ADMISSION_COSIG_BINDING_ENABLE", val)
			t.Setenv("LEDGER_ADMISSION_POLICY_ENABLE", val)
			t.Setenv("LEDGER_ADMISSION_EVIDENCE_CHAIN_ENABLE", val)

			g := LoadGatesFromEnv()
			if !g.MultiSig || !g.CosigBinding || !g.Policy || !g.EvidenceChain {
				t.Errorf("value %q did not enable all gates: %+v", val, g)
			}
		})
	}
}

func TestGates_FalsyValues(t *testing.T) {

	cases := []string{"", "false", "FALSE", "0", "no", "off", "garbage", "2", "enable"}
	for _, val := range cases {
		val := val
		t.Run(val, func(t *testing.T) {
			t.Setenv("LEDGER_ADMISSION_MULTISIG_ENABLE", val)
			t.Setenv("LEDGER_ADMISSION_COSIG_BINDING_ENABLE", val)
			t.Setenv("LEDGER_ADMISSION_POLICY_ENABLE", val)
			t.Setenv("LEDGER_ADMISSION_EVIDENCE_CHAIN_ENABLE", val)

			g := LoadGatesFromEnv()
			if g.MultiSig || g.CosigBinding || g.Policy || g.EvidenceChain {
				t.Errorf("value %q enabled at least one gate: %+v", val, g)
			}
		})
	}
}

func TestGates_IndependentToggling(t *testing.T) {

	// Each gate must be flippable in isolation. A composite kill-
	// switch would force "all on / all off" decisions; this test
	// pins the independence property that motivated splitting the
	// flags in the first place.
	t.Setenv("LEDGER_ADMISSION_MULTISIG_ENABLE", "true")
	t.Setenv("LEDGER_ADMISSION_COSIG_BINDING_ENABLE", "false")
	t.Setenv("LEDGER_ADMISSION_POLICY_ENABLE", "true")
	t.Setenv("LEDGER_ADMISSION_EVIDENCE_CHAIN_ENABLE", "false")

	g := LoadGatesFromEnv()
	if !g.MultiSig {
		t.Error("MultiSig should be ON")
	}
	if g.CosigBinding {
		t.Error("CosigBinding should be OFF — independence violated")
	}
	if !g.Policy {
		t.Error("Policy should be ON")
	}
	if g.EvidenceChain {
		t.Error("EvidenceChain should be OFF — independence violated")
	}
}
