package engine

import "testing"

// Same tripwire as TestOpenRuleSetMatchesKernelAllowlist, for CONNECT.
//
// connect_port_is_watched() in internal/probe/bpf/probe.bpf.c emits only for
// the ports these rules name, plus everything above 49151. A rule that starts
// caring about a port outside that set will never fire, silently.
//
// Filtering CONNECT was the second half of the 2026-08-18→22 disk incident:
// with OPEN filtered, CONNECT became 95.6% of stored events — 78% of it port
// 53 — and none of it was readable by any rule.
var connectRuleConditionDigests = map[string]string{
	"connect-to-known-c2-port":              "6a145ab540361552243a8a10d0503b5f48ab66d4727fcdc5db1309fb4a7f4759",
	"connect-known-rat-port":                "ee9027d357eac71376f0c867f51c42977d66a61d438ce534c00f60cabec66794",
	"connect-proxy-port-noninfra":           "2f784ab11f31e5772856b258539b336bcb28db9bfacf2f2a96214f5aa9884666",
	"connect-irc-port":                      "58102b57d8beffd32002f425c3ed2aaccf3113e31b7d17c33e741b4d33d96455",
	"connect-high-port-nonstandard-process": "8320ab95e9c8b3d5b0aa2b4f65fdccd6c188931f42c310e4408af5fd1c9c01be",
	"connect-tor-socks-proxy":               "e4cb3ef1d527d9a8167824eb5b77be23150e6d78669c260b6ac385a99d736b0c",
	"connect-tor-orport":                    "1e2c66aa34c6d3d1a40c46c9cbda205adba34db67609a72066f6c2dd34681b56",
}

func TestConnectRuleSetMatchesKernelAllowlist(t *testing.T) {
	rules, err := loadBuiltinRules()
	if err != nil {
		t.Fatalf("loadBuiltinRules: %v", err)
	}

	got := map[string]string{}
	for _, r := range rules {
		if r.EventType == "CONNECT" {
			got[r.ID] = conditionDigest(r.Condition)
		}
	}

	for id, digest := range got {
		want, known := connectRuleConditionDigests[id]
		if !known {
			t.Errorf(`new rule %q consumes CONNECT events.

The kernel drops every connect() whose destination port is not in
connect_port_is_watched() (internal/probe/bpf/probe.bpf.c). Add this rule's
ports there, extend TestConnectFilterKeepsWatchedPortsDropsNoise, then record:
    %q: %q,`, id, id, digest)
			continue
		}
		if want != digest {
			t.Errorf(`rule %q changed what it matches (condition digest %s -> %s).

Re-check connect_port_is_watched() in internal/probe/bpf/probe.bpf.c: if the
new condition can match a port the kernel allowlist does not emit, the rule
will never fire.`, id, want, digest)
		}
	}

	for id := range connectRuleConditionDigests {
		if _, ok := got[id]; !ok {
			t.Errorf("rule %q is pinned here but no longer consumes CONNECT — if it was deleted, drop its ports from connect_port_is_watched() and remove this entry", id)
		}
	}
}
