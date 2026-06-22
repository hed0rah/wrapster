package mcp

import (
	"encoding/json"
	"testing"

	"github.com/hed0rah/wrapster/internal/policy"
	"github.com/hed0rah/wrapster/internal/runner"
)

// TestReadHostsResource verifies the hosts:// inventory: entries are sorted by
// name, the default port falls back to 22, and per-host metadata is surfaced.
func TestReadHostsResource(t *testing.T) {
	r := &runner.Runner{Policy: &policy.Policy{
		Hosts: map[string]policy.HostPolicy{
			"alpha": {
				Hostname:        "10.0.0.1",
				User:            "a",
				Port:            2607,
				Description:     "box a",
				AllowedCommands: []policy.CommandRule{{Command: "uptime"}, {Command: "df"}},
			},
			"beta": {Hostname: "10.0.0.2", User: "b", Trusted: true},
		},
	}}

	res, err := readHostsResource(r)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Hosts []struct {
			Name         string `json:"name"`
			Port         int    `json:"port"`
			Trusted      bool   `json:"trusted"`
			CommandCount int    `json:"command_count"`
			Description  string `json:"description"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal([]byte(res.Contents[0].Text), &parsed); err != nil {
		t.Fatal(err)
	}

	if len(parsed.Hosts) != 2 {
		t.Fatalf("want 2 hosts, got %d", len(parsed.Hosts))
	}
	// sorted by name: alpha before beta
	if parsed.Hosts[0].Name != "alpha" || parsed.Hosts[1].Name != "beta" {
		t.Errorf("not sorted by name: %s, %s", parsed.Hosts[0].Name, parsed.Hosts[1].Name)
	}
	if parsed.Hosts[0].Port != 2607 || parsed.Hosts[0].CommandCount != 2 || parsed.Hosts[0].Description != "box a" {
		t.Errorf("alpha metadata wrong: %+v", parsed.Hosts[0])
	}
	// beta has no port -> default 22, and is trusted
	if parsed.Hosts[1].Port != 22 || !parsed.Hosts[1].Trusted {
		t.Errorf("beta defaults wrong: %+v", parsed.Hosts[1])
	}
}
