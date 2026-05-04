package policy

import "testing"

func BenchmarkValidateBenign(b *testing.B) {
	hp := HostPolicy{
		AllowedCommands:     []CommandRule{{Command: "uptime"}},
		AllowShellOperators: false,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidateCommand("uptime", hp, ModeAllowlist)
	}
}

func BenchmarkValidateGuardrail(b *testing.B) {
	hp := HostPolicy{AllowShellOperators: true}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidateCommand("ls -la /var/log/nginx", hp, ModeGuardrail)
	}
}

func BenchmarkValidateBlocked(b *testing.B) {
	hp := HostPolicy{AllowShellOperators: true}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidateCommand("rm -rf /tmp/foo", hp, ModeGuardrail)
	}
}
