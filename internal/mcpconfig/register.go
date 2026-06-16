package mcpconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/hed0rah/wrapster/internal/atomicfile"
)

// RegisterOpts provides configuration for the Register function.
type RegisterOpts struct {
	// Env is the environment context.
	Env Env
	// Ctx is the path context.
	Ctx PathCtx
	// Entry is the ServerEntry to register.
	Entry ServerEntry
	// ServerName is the name of the server to register.
	ServerName string
	// Conflict indicates how to handle existing entries.
	Conflict Conflict
	// Probe provides filesystem and path-lookup access.
	Probe Probe
	// ReadFile reads a file; defaults to os.ReadFile.
	ReadFile func(string) ([]byte, error)
	// WriteAtom writes atomically; defaults to atomicfile.WriteWithBackup.
	WriteAtom func(string, []byte) error
	// RunCLI executes a CLI command; defaults to exec.Command.
	RunCLI func(string, ...string) error
}

// RegisterResult reports the result of a single registration attempt.
type RegisterResult struct {
	Client string
	Path   string
	Action string // one of "created", "merged", "skipped", "overwritten", "cli", "error"
	Err    error
}

// Register registers a server entry for a single client.
func Register(c Client, opts RegisterOpts) RegisterResult {
	// Fill in defaults.
	if opts.ReadFile == nil {
		opts.ReadFile = os.ReadFile
	}
	if opts.WriteAtom == nil {
		opts.WriteAtom = func(path string, data []byte) error {
			_, err := atomicfile.WriteWithBackup(path, data, 0o644)
			return err
		}
	}
	if opts.RunCLI == nil {
		opts.RunCLI = func(name string, args ...string) error {
			return exec.Command(name, args...).Run()
		}
	}

	result := RegisterResult{Client: c.Display}

	// Special case: claude-code with UseCLI and claude on PATH.
	if c.UseCLI && c.Name == "claude-code" {
		if _, err := opts.Probe.LookPath("claude"); err == nil {
			// Use the CLI to register.
			entryBytes, err := json.Marshal(opts.Entry)
			if err != nil {
				result.Action = "error"
				result.Err = fmt.Errorf("marshaling entry: %w", err)
				return result
			}
			if err := opts.RunCLI("claude", "mcp", "add-json", opts.ServerName, string(entryBytes)); err != nil {
				result.Action = "error"
				result.Err = fmt.Errorf("running claude mcp add-json: %w", err)
				return result
			}
			result.Action = "cli"
			return result
		}
	}

	// Normal flow: read, merge, and write.
	path, err := c.ConfigPath(opts.Env, opts.Ctx)
	if err != nil {
		result.Action = "error"
		result.Err = fmt.Errorf("resolving config path: %w", err)
		return result
	}
	result.Path = path

	// Read existing config. Only a genuine "not found" is treated as an empty
	// starting point; any other read error must abort so we never overwrite a
	// config we simply failed to read.
	data, err := opts.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			result.Action = "error"
			result.Err = fmt.Errorf("reading %s: %w", path, err)
			return result
		}
		data = []byte{}
	}

	dataWasEmpty := len(data) == 0

	// Determine merge function based on scope and nesting.
	var out []byte
	var changed bool
	mergeErr := error(nil)

	if c.Nested && c.Scope == ScopeProject {
		// Use MergeNested with segments ["projects", Cwd, "mcpServers"].
		out, changed, mergeErr = MergeNested(
			data,
			[]string{"projects", opts.Ctx.Cwd, c.Key},
			opts.ServerName,
			opts.Entry,
			opts.Conflict,
		)
	} else {
		// Use normal Merge.
		out, changed, mergeErr = Merge(
			data,
			c.Key,
			opts.ServerName,
			opts.Entry,
			opts.Conflict,
		)
	}

	if mergeErr != nil {
		result.Action = "error"
		result.Err = fmt.Errorf("merging: %w", mergeErr)
		return result
	}

	// Determine action based on changed and whether data was empty.
	if !changed {
		result.Action = "skipped"
		return result
	}

	if dataWasEmpty {
		result.Action = "created"
	} else {
		// Data existed; determine if we're overwriting or merging.
		// If Overwrite conflict was used, report as "overwritten".
		// Otherwise, report as "merged".
		if opts.Conflict == Overwrite {
			result.Action = "overwritten"
		} else {
			result.Action = "merged"
		}
	}

	// Write the merged output.
	if err := opts.WriteAtom(path, out); err != nil {
		result.Action = "error"
		result.Err = fmt.Errorf("writing: %w", err)
		return result
	}

	return result
}

// RegisterAll registers a server for all provided clients.
func RegisterAll(clients []Client, opts RegisterOpts) []RegisterResult {
	var results []RegisterResult
	for _, client := range clients {
		results = append(results, Register(client, opts))
	}
	return results
}
