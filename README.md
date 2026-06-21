# wrapster

Secure command gateway for LLMs. Run local and remote commands through a configurable security policy -- allowlist for SSH, guardrail filters for local. Single static binary, zero runtime dependencies.

## Install

```bash
go build -o wrapster ./cmd/wrapster

# Cross-compile
GOOS=linux GOARCH=amd64 go build -o wrapster ./cmd/wrapster
GOOS=linux GOARCH=arm GOARM=7 go build -o wrapster ./cmd/wrapster
GOOS=darwin GOARCH=arm64 go build -o wrapster ./cmd/wrapster
```

## Config wizard

`wrapster config` (alias `wrapster setup`) launches an interactive TUI that authors a policy.yaml with a live preview and registers the wrapster binary into the MCP clients detected on the machine. Registration merges into each client's existing config without clobbering it; a timestamped .bak is written first.

Supported clients: Claude Desktop, Claude Code, Cursor, Windsurf, Cline, VS Code, LM Studio.

The wizard adds charmbracelet/bubbletea, bubbles, lipgloss, huh plus natefinch/atomic as dependencies. All are statically linked, so the binary remains a single static file with zero runtime dependencies.

## Policy

Policy is loaded from `./policy.yaml`, then `~/.config/wrapster/policy.yaml`, or `-p <path>`. See `policy.example.yaml` for a full reference.

Minimal example:

```yaml
local:
  mode: guardrail      # allow all local commands unless filters catch them
  timeout: 30s

filters:
  gtfobins:
    enabled: true
    block: [shell, reverse-shell, bind-shell, inherit]
  destructive:
    enabled: true

defaults:
  timeout: 30s
  allowed_commands:
    - command: uptime
    - command: df
      args_pattern: "-[hTi]+"
  denied_patterns:
    - "sudo"

hosts:
  prod-web:
    hostname: 192.0.2.10
    user: deploy
    identity_file: ~/.ssh/id_ed25519
    allowed_commands:
      - command: nginx
        args_pattern: "-t|-s reload"
```

## CLI

```bash
# SSH (allowlist mode)
wrapster <host> <command>
wrapster --json prod-web "uptime"
wrapster --dry-run prod-web "nginx -t"
wrapster --list prod-web
wrapster --watch 30s --json prod-web "df -h"
wrapster --ssh-args "-o ProxyJump=bastion" prod-web "uptime"

# Local (guardrail mode)
wrapster local "docker ps"
wrapster --json local "uname -a"
```

## MCP Server

### stdio (Claude Desktop, Cline)

```bash
wrapster --mcp --policy /path/to/policy.yaml
```

### Streamable HTTP (modern: Cursor, Claude Code `--transport http`)

```bash
wrapster --mcp-http :8080 --policy /path/to/policy.yaml
# optional bearer auth (env preferred over the flag, which leaks via ps):
WRAPSTER_AUTH_TOKEN=secret wrapster --mcp-http :8080 --policy /path/to/policy.yaml
```

The MCP 2025-03-26 transport: single `POST/DELETE /mcp` endpoint, `Mcp-Session-Id`
sessions, loopback Origin guard. See [docs/transports.md](docs/transports.md).

### SSE (legacy: LM Studio, older HTTP clients)

```bash
wrapster --mcp-sse :8080 --policy /path/to/policy.yaml
# connects to 127.0.0.1:8080 by default
```

### Tools (9)

| Tool | Params | Description |
|------|--------|-------------|
| `exec` | `command` | Run a command locally (guardrail mode) |
| `ssh_exec` | `host`, `command` | Run a command on a remote host |
| `ssh_validate` | `host`, `command` | Dry-run validate without executing |
| `batch_exec` | `host`, `commands` | Run multiple commands in one call |
| `host_info` | `host`, `refresh?` | Fingerprint host OS/kernel/tools (cached 30min) |
| `grep_output` | `buf_id`, `pattern` | Regex search a buffered output |
| `cache_invalidate` | `host?`, `command?` | Invalidate result cache entries |
| `find_files` | `host`, `query` | Search for files by name |
| `grep_files` | `host`, `pattern` | Search file contents by regex |

### Resources

| URI | Description |
|-----|-------------|
| `stats://session` | Output processing stats (JSON) |
| `policy://current` | Active policy summary (JSON) |
| `host://{name}/allowed` | Allowed commands for a host |
| `host://{name}/info` | Cached host fingerprint (JSON) |
| `buf://{id}` | Full command output buffer (`?offset=N&length=M`) |

Truncated exec output includes a `buf://` reference automatically.

### Prompts

| Prompt | Arguments | Description |
|--------|-----------|-------------|
| `diagnose-host` | `host` | Run uptime/df/free/last and interpret |
| `compare-hosts` | `host_a`, `host_b` | Fingerprint and diff two hosts |
| `safety-review` | `host`, `command` | Validate + review for security risks |

### Claude Desktop config

```json
{
  "mcpServers": {
    "wrapster": {
      "command": "/path/to/wrapster",
      "args": ["--mcp", "--policy", "/path/to/policy.yaml"]
    }
  }
}
```

## Output processing

Command output is post-processed before returning to the LLM to save tokens:

- **ANSI stripping**: removes escape codes from colored terminal output (default: on)
- **Truncation**: keeps first 64 + last 16 lines, drops the middle with a count marker (default: on, threshold 8192 chars)
- **Stats**: tracks raw vs processed bytes across the session, exposed via `stats://session` resource

```yaml
output:
  ansi_strip: true
  truncate:
    enabled: true
    max_chars: 8192
    head_lines: 64
    tail_lines: 16
  stats: true
```

Each technique can be toggled independently. Set `ansi_strip: false` or `truncate.enabled: false` to disable.

## Security model

### Local commands (guardrail mode)

Allow by default, block on detection. Five built-in filter modules:

- **gtfobins**: matches known GTFOBins exploit patterns (shell spawn, reverse shell, file write, download). Sourced from 477 binaries, 815 techniques.
- **destructive**: blocks `rm -rf`, `dd`, `mkfs`, fork bombs, `chmod 777`, SQL `DROP`/`TRUNCATE`, `git reset --hard`, `docker system prune`, `kubectl delete --all`
- **exfil**: detects outbound curl/wget to non-RFC1918 addresses, `nc` listeners, HTTP servers, DNS tunneling (disabled by default)
- **workdir**: when `work_dir` is set, blocks absolute paths outside the directory, `..` traversal, and `cd` escapes (not a security boundary -- a focus guardrail)
- **custom**: load your own rule files with regex patterns and severity levels

Hard denies (always blocked, every mode, no override): recursive `rm` of system
paths/home/root in any flag order, `find -delete`, `dd`/`mkfs` to devices,
`/dev/tcp` reverse shells, fork bombs, `curl|sh`, reads of `/etc/shadow`, writes
to `/etc/crontab`, world-writable `chmod`, and more. Obfuscation that only exists
to dodge these (`$IFS`, `$'\x..'`, `{rm,-rf,/}`, `r''m`) is rejected. Full list
and rationale: [docs/security-model.md](docs/security-model.md).

### SSH commands (allowlist mode)

Deny by default. A command must match an `allowed_commands` rule to run.

- **Shell operators blocked**: `;`, `|`, `&&`, backticks, `$()` rejected unless `allow_shell_operators: true`
- **Hard denies**: same list as above, applied before the allowlist
- **Deny patterns**: custom regex patterns always checked before allowlist
- **No interactive shell**: `-T` and `BatchMode=yes` always set
- **Audit log**: every attempt logged as JSON with timestamp, host, command, result, output SHA-256
- **Connection pooling**: on Unix, SSH connections are multiplexed via ControlMaster (60s idle timeout). Repeated commands to the same host reuse a single connection.

### Trusted hosts (full shell)

Set `trusted: true` on a host to run it in guardrail mode: full shell (pipes,
`$()`, one-liners), gated only by the always-on hard-denies + filters. This is
*shell access* -- string validation is a friction layer, not a boundary, so
security depends on the remote account (non-root, restricted egress). wrapster
prints a startup warning listing trusted hosts. See [docs/security-model.md](docs/security-model.md).

### Strict policy parsing

Unknown policy keys are a hard error, so a policy can never silently mean less
than it says (no aspirational `workspaces`/`profiles` that look enforced but
aren't). Host `environment` values are validated too: `$VAR` extension is
allowed; command substitution and loader-hijack keys (`LD_PRELOAD`, ...) are
rejected.

## Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--policy <path>` | `-p` | Policy file |
| `--audit <path>` | `-a` | Audit log (default: stderr) |
| `--json` | `-j` | JSON output |
| `--dry-run` | `-n` | Validate only, do not execute |
| `--list` | `-l` | List allowed commands for a host |
| `--ssh-args <args>` | `-s` | Extra SSH args (comma-separated) |
| `--watch <duration>` | `-w` | Poll interval (e.g. `30s`, `1m`) |
| `--mcp` | | MCP server over stdio |
| `--mcp-http <addr>` | | MCP server over Streamable HTTP |
| `--auth-token <tok>` | | Bearer token for `--mcp-http` (or `WRAPSTER_AUTH_TOKEN`) |
| `--mcp-sse <addr>` | | MCP server over HTTP SSE (legacy) |
| `--cache-ttl <dur>` | | Result cache TTL (default: `30s`) |
| `--hostinfo-ttl <dur>` | | Host info cache TTL (default: `30m`) |
| `--bufstore-max <n>` | | Max output buffer entries (default: `64`) |
| `--version` | | Show version and exit |
