# Security model

wrapster sits between an LLM and a shell. The LLM proposes a command as a
string; wrapster decides whether to run it, then hands it to either the local
shell or a remote shell over `ssh host "<command>"`. This document explains how
that decision is made and, more importantly, *why* it is made the way it is,
including what wrapster can and cannot guarantee.

## The core problem: a string is not a parse tree

wrapster validates the command *text*. The shell executes a *parse tree* derived
from that text after quoting, expansion, and substitution. These are different
objects, and every shell feature that rewrites the text before execution opens a
gap between "what the validator matched" and "what bash actually ran":

```
cat${IFS}/etc/shadow      # no space, but the shell word-splits on $IFS
r''m -rf /                 # '' is removed; the shell sees rm
{rm,-rf,/}                 # brace expansion produces: rm -rf /
$'\x72\x6d' -rf /          # ANSI-C quoting decodes to: rm -rf /
$(echo rm) -rf /           # command substitution reconstructs rm at runtime
```

The honest consequence, confirmed by the research behind this design: **once a
mode allows command substitution and arbitrary one-liners, string validation is
a friction layer, not a security boundary.** A model that understands bash (they
all do) can reconstruct any blocked command. So wrapster does not pretend
otherwise. It offers two modes with very different guarantees.

## Two modes

### Allowlist mode (default for SSH hosts) -- a real boundary

Deny by default; a command runs only if every operator-separated segment matches
an `allowed_commands` rule. This mode is designed to actually hold, so it is
deliberately strict:

- **Shell operators are blocked** unless `allow_shell_operators: true`
  (`shellOperatorPattern`). With them off, `;`, `|`, `&`, `$`, `()`, `{}`, `<`,
  `>`, backtick, CR and LF never reach the shell.
- **Command/process substitution is always rejected** in allowlist mode
  (`cmdSubstPattern`: `$(`, backtick, `<(`, `>(`), even with operators on. A
  substitution hides a sub-command that cannot be validated per-segment.
- **Binary identity is exact.** `CommandRule.Matches` splits on the first space
  and requires `token == rule.Command`. This is why wrappers and path forms
  (`sudo cat`, `env cat`, `busybox cat`, `/bin/cat`, `"cat"`) simply *fail to
  match* and are denied -- the safe direction. Relaxing this would collapse the
  guarantee, so it is intentionally rigid.
- **Per-segment validation.** With operators allowed, the command is split on
  `;|&` / `&&` / `||` / newline and *each* segment must independently match a
  rule. An allowlisted prefix (`uptime`) cannot drag a trailing command through.
- **Obfuscation that only exists to fragment a keyword is rejected**
  (`fragmentPattern`): mid-word empty strings (`r''m`), backslash escapes
  (`r\m`), comma brace expansion (`{rm,-rf,/}`). These have no legitimate use in
  an allowlisted command.

What allowlist mode guarantees: the invoked binary is on the approved list, no
shell metacharacters or sub-commands reach the remote shell, and arguments
conform to the rule's `args_pattern`. What it still cannot guarantee: that an
approved binary has no dangerous side effects with approved arguments (a
permitted `curl` can still fetch attacker-controlled content). For that reason,
do not allowlist GTFOBins-class interpreters (`python`, `perl`, `awk`, `find`,
`vim`, `xargs`, ...) on a host you are trying to constrain -- they are shells in
disguise.

### Trusted mode (`trusted: true`) -- full shell, honestly labelled

A host marked `trusted: true` runs through guardrail validation instead of the
allowlist: pipes, redirects, `$()`, and complex one-liners are allowed. This is,
by design, equivalent to giving the LLM an `ssh user@host bash` session.

This is stated plainly because a false sense of safety is worse than a known
risk. In trusted mode:

- The hard-deny catastrophe net (below) and the filter chain still run -- they
  catch accidents and unsophisticated mistakes.
- They do **not** stop a determined or prompt-injected model. The real security
  boundary is the remote account, not wrapster. Use trusted mode only on hosts
  where you have set up OS-level controls: a non-root SSH user, restricted
  network egress, sensitive files unreadable by that user, and ideally a
  sandbox. wrapster logs a loud warning at startup listing trusted hosts.

## Layered enforcement (the order things run)

Every command, in both modes, passes through these layers in order
(`ValidateCommand`, then `runner.Exec` / `runner.ExecLocal`):

1. **Obfuscation rejection (all modes).** ANSI-C quoting (`$'...'`) and `IFS`
   reassignment (`IFS=,`) are rejected outright. They are evasion-only
   constructs with no legitimate use, so blocking them is low-false-positive and
   removes two whole classes of keyword smuggling.
2. **`$IFS` normalization (all modes).** `${IFS}`/`$IFS` is rewritten to a space
   *for matching only*. Without this, `rm${IFS}-rf${IFS}/` slips every
   whitespace-based rule; with it, the rule matches. The original (unmodified)
   string is what executes -- faithful, because the remote shell performs the
   same `$IFS` expansion.
3. **Hard-deny catastrophe net (all modes, no override).** A small set of
   always-blocked patterns that hold even in trusted mode. See below.
4. **Shell-operator gate (allowlist, when operators are off).**
5. **User `denied_patterns`.**
6. **Mode decision:** guardrail allows; allowlist requires every segment to
   match (after rejecting fragmentation and substitution).
7. **Filter chain** (`gtfobins` + `destructive` by default, `exfil` opt-in),
   which scans the whole string for exploit techniques (reverse shells, language
   `system()` calls, `curl|sh`, SSH-key reads). This layer carries much of the
   real safety budget and runs in trusted mode too.

## The hard-deny catastrophe net

These are the only rules guaranteed to run in every mode, so they target
*irreversible, box-destroying* actions rather than trying to be a complete
denylist (which is impossible -- see below). The set is built to survive the
common evasions:

- **`dangerousRm`** (code, not a single regex, because it is an AND of three
  conditions): a recursive `rm` (`-r`, `-rf`, `--recursive`, in any flag order
  or position, including flag-after-target like `rm /etc -rf`) aimed at root, a
  home, `--no-preserve-root`, or a system top-level directory (`/etc`, `/usr`,
  `/var`, ...). It deliberately does **not** flag deep paths (`rm -rf
  /var/log/x`) or relative targets (`rm -rf ./build`), so normal cleanup works.
- `find ... -delete`, `mv ... /dev/null` (recursive destruction without an `rm`
  signature).
- Writes to raw devices (`/dev/sd*`, `/dev/nvme*`, `/dev/mem`, `/dev/kmsg`, ...),
  `dd of=/dev/`, filesystem formatters (`mkfs`, `mke2fs`, `mkswap`, `newfs`).
- Generalized fork bomb (`name(){ ...|...& }`, not just the literal `:` form).
- `/dev/tcp/` and `/dev/udp/` (bash reverse-shell redirect).
- Reads of `/etc/passwd|shadow|sudoers`; writes to system `crontab`/`cron.*`/
  `/etc/hosts` (persistence / DNS hijack).
- `curl|wget|fetch` piped (including `|&`) to an interpreter; world-writable
  `chmod`.

### What is deliberately NOT in the net, and why

We do not try to denylist obfuscated equivalents of every dangerous command in
trusted mode (`{rm,-rf,/}`, `$(echo rm) -rf /`, variable-reconstructed commands).
That is an unwinnable arms race against a model that knows bash, and chasing it
produces false positives that break legitimate work without adding real safety.
The catastrophe net exists to stop *accidents and simple mistakes*; the actual
boundary for trusted hosts is the remote OS. This is the same conclusion reached
by SSH `ForceCommand`, `sudoers`, restricted shells, AWS SSM, and Teleport, all
of which delegate "what happens inside a session" to OS-level controls.

## Supporting hardening

- **Environment values are validated at load** (`validateEnvMap`). Host
  `environment` values are shell-expanded on the remote, so a value containing
  `$(...)`, backticks, or `;`/`|`/`&` is rejected, and loader/startup-hook keys
  (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `BASH_ENV`, `PROMPT_COMMAND`, ...) are
  forbidden. Plain `$VAR` references (`PATH: /opt/bin:$PATH`) are allowed because
  extending a variable is the legitimate use.
- **Strict policy parsing** (`yaml.Decoder` + `KnownFields(true)`). An unknown
  key is a hard error. This prevents the most dangerous documentation failure:
  an aspirational policy (workspaces, profiles, approval gates) that *looks*
  enforced but is silently ignored. If wrapster does not implement a key, it
  says so instead of pretending.
- **The SSH command is one argv element**, run via `exec.Command` (no local
  `sh -c`), so there is no second, local round of word-splitting -- the string
  wrapster validated is byte-for-byte the string the remote shell parses.

## Practical guidance

- Keep untrusted or shared hosts in **allowlist mode** with concrete
  `allowed_commands`. Do not allowlist interpreters.
- Use **`trusted: true`** only on hosts you fully control, and harden the remote
  account: non-root user, `AllowTcpForwarding no` where appropriate, egress
  firewalling, read restrictions on credential paths. Treat it as "the model has
  a shell here."
- Prefer flipping a host to trusted *temporarily* for a task and back, rather
  than leaving it on.

## References

The bypass taxonomy and the "secure the OS, not the string" position are drawn
from OWASP command-injection guidance, GTFOBins, the sudoers/rbash bypass
literature, and how SSH ForceCommand, AWS SSM, and Teleport scope sessions.
