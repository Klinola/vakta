package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"testing"
)

// The kernel only emits VK_OPEN for the paths listed in open_path_is_sensitive()
// in internal/probe/bpf/probe.bpf.c. That allowlist was derived from the rules
// below and from nothing else, so a rule that starts matching a path outside it
// silently never fires — there is no runtime error, the events simply never
// arrive. (Before the 2026-08-18→22 incident the kernel emitted every open()
// and no such coupling existed; filtering there is what stopped it filling a
// production node's root disk.)
//
// This test is the tripwire. It pins which rules consume OPEN and what each one
// matches on; touch either and it fails, pointing at the kernel allowlist. It
// deliberately does NOT try to parse CEL and derive the path set — that parsing
// would be the fragile part. It just makes drift impossible to commit silently.
var openRuleConditionDigests = map[string]string{
	"open-shadow-file":     "de346bb6d26dca64117ef03385e0d08d0955d5965e2732b85188b1a379191c49",
	"open-ssh-private-key": "77be5ff86c6e34f0bd8f11de41a28b2a025bf557b3b670adf23de8e7f253fd4f",
	"open-docker-socket":   "124bbc443f52264a60275ea6ec144ced4fd98c4d748d3d19537a501f7b64063e",
	"open-proc-kcore":      "c4b997dbd881aae5b2acc28c5abca53f4420ffbaf4a8567c648b9d1374b8f1aa",
}

func conditionDigest(cond string) string {
	// Normalise whitespace so reflowing a condition doesn't trip the guard;
	// only a semantic edit should.
	sum := sha256.Sum256([]byte(strings.Join(strings.Fields(cond), " ")))
	return hex.EncodeToString(sum[:])
}

func TestOpenRuleSetMatchesKernelAllowlist(t *testing.T) {
	rules, err := loadBuiltinRules()
	if err != nil {
		t.Fatalf("loadBuiltinRules: %v", err)
	}

	got := map[string]string{}
	for _, r := range rules {
		if r.EventType == "OPEN" {
			got[r.ID] = conditionDigest(r.Condition)
		}
	}

	for id, digest := range got {
		want, known := openRuleConditionDigests[id]
		if !known {
			t.Errorf(`new rule %q consumes OPEN events.

The kernel drops every open() whose path is not in open_path_is_sensitive()
(internal/probe/bpf/probe.bpf.c). Add this rule's paths there, extend
TestOpenFilterKeepsSensitiveDropsNoise to cover one of them, then record the
digest here:
    %q: %q,`, id, id, digest)
			continue
		}
		if want != digest {
			t.Errorf(`rule %q changed what it matches (condition digest %s -> %s).

Re-check open_path_is_sensitive() in internal/probe/bpf/probe.bpf.c: if the new
condition can match a path the kernel allowlist does not emit, the rule will
never fire. Update the allowlist if needed, then record the new digest.`,
				id, want, digest)
		}
	}

	for id := range openRuleConditionDigests {
		if _, ok := got[id]; !ok {
			t.Errorf("rule %q is pinned here but no longer consumes OPEN — if it was deleted, drop its paths from open_path_is_sensitive() and remove this entry", id)
		}
	}

	if t.Failed() {
		ids := make([]string, 0, len(got))
		for id := range got {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		t.Logf("OPEN-consuming rules currently present: %v", ids)
	}
}
