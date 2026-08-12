// gsl, the gtmify-slashy CLI. A thin JSON-RPC client over the Slashy MCP endpoint
// (https://slashy.ctrlcenter.ai/mcp) for email, calendar, contact research,
// meeting prep, and automations.
//
// Why a CLI rather than a connected MCP server: an MCP server loads every tool
// definition into the agent's context at session boot whether or not a single
// tool is ever called. A CLI costs nothing at boot and roughly 200 tokens per
// call, because the binary does the work and returns a summary.
//
// Auth is OAuth 2.1 + PKCE with dynamic client registration. Slashy issues no
// API keys, so there is no env var to set and no secret to rotate. Run
// `gsl login` once; the token is stored at ~/.config/gsl/credentials.json (0600)
// and refreshed automatically.
//
// The tool surface is discovered at runtime rather than compiled in, so tools
// Slashy adds server-side are usable the moment they ship.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
)

const version = "0.1.0"

// ---------- error types that carry a remedy ----------

var errNotLoggedIn = errNeedsLogin{reason: "no stored credentials"}

type errNeedsLogin struct{ reason string }

func (e errNeedsLogin) Error() string {
	return fmt.Sprintf("not signed in to Slashy (%s)\n\nRun:\n  gsl login", e.reason)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "-h", "--help", "help":
		usage()
		return
	case "-v", "--version", "version":
		fmt.Printf("gsl %s (gtmify-slashy)\n", version)
		return
	case "login", "auth": // `auth` matches the verb gsh and grc use
		err = cmdLogin(ctx, args)
	case "logout":
		err = cmdLogout(ctx, args)
	case "whoami":
		err = cmdWhoami(ctx, args)
	case "tools":
		err = cmdTools(ctx, args)
	case "schema":
		err = cmdSchema(ctx, args)
	case "call":
		err = cmdCall(ctx, args)
	case "doctor":
		err = cmdDoctor(ctx, args)
	default:
		if strings.HasPrefix(cmd, "-") {
			err = fmt.Errorf("unknown flag %q; run `gsl help`", cmd)
			break
		}
		// Convenience: `gsl <tool> -a k=v` is shorthand for `gsl call <tool> ...`.
		// The tool surface is server-side, so this stays correct as it changes.
		err = cmdCall(ctx, append([]string{cmd}, args...))
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "gsl: "+err.Error())
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`gsl ` + version + `: Slashy from the command line (email, calendar, research)

USAGE
  gsl <command> [flags]
  gsl <tool-name> [-a key=value]...     shorthand for ` + "`gsl call <tool-name>`" + `

AUTH
  gsl login [--no-browser]      Sign in via browser (OAuth 2.1 + PKCE). Once.
        [--force]               Sign in again even if a valid token exists.
        [--redirect-host HOST]  Loopback host, default 127.0.0.1. Try localhost
                                if the authorization server rejects the redirect.
  gsl logout                    Revoke the token and delete the local store.
  gsl whoami                    Show the signed-in account and token state.

DISCOVERY
  gsl tools [--json] [-q TEXT]  List the tools Slashy exposes to this account.
  gsl schema <tool>             Show one tool's input schema and required args.

CALLING
  gsl call <tool> [flags]
    -a key=value                Argument. Values are JSON-coerced when possible
                                (42, true, [1,2], {"k":"v"}), else sent as text.
    -s key=value                Argument forced to a string, no coercion.
    --args '<json>'             Whole argument object as raw JSON.
    --json                      Print the raw JSON result, not the summary.
    --dry-run                   Validate args against the schema, send nothing.

DIAGNOSTICS
  gsl doctor                    Check connectivity, discovery, and token health.
  gsl version

EXAMPLES
  gsl login
  gsl tools -q calendar
  gsl schema send_email
  gsl call search_emails -a query="from:alice unread" -a limit=10
  gsl call draft_reply -a thread_id=abc123 -s body="Sounds good, Thursday works."

NOTES
  No API key exists for Slashy; auth is browser OAuth only. Credentials live in
  ~/.config/gsl/credentials.json (0600) and refresh automatically.
  Docs: https://help.slashy.com/features/integrations/mcp
`)
}

// ---------- auth commands ----------

func cmdLogin(ctx context.Context, args []string) error {
	fs := newFlagSet("login")
	noBrowser := fs.Bool("no-browser", false, "print the URL instead of opening a browser")
	force := fs.Bool("force", false, "sign in again even if a valid token exists")
	redirectHost := fs.String("redirect-host", "127.0.0.1", "loopback host in the redirect URI; try localhost if the server rejects it")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if !*force {
		if c, err := loadCreds(); err == nil && !c.expired() {
			fmt.Printf("Already signed in%s. Use --force to sign in again.\n", accountSuffix(c))
			return nil
		}
	}

	c, err := login(ctx, !*noBrowser, *redirectHost)
	if err != nil {
		return err
	}

	// Prove the token actually works rather than trusting the exchange.
	cl := newClient(c)
	if err := cl.dial(ctx); err != nil {
		return fmt.Errorf("signed in, but the first call to Slashy failed: %w", err)
	}
	tools, err := cl.listTools(ctx)
	if err != nil {
		return fmt.Errorf("signed in, but listing tools failed: %w", err)
	}
	p, _ := credsPath()
	fmt.Printf("Signed in to Slashy. %d tools available.\nToken stored at %s (0600).\n", len(tools), p)
	return nil
}

func cmdLogout(ctx context.Context, args []string) error {
	fs := newFlagSet("logout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := loadCreds()
	if err != nil {
		fmt.Println("Not signed in; nothing to do.")
		return nil
	}
	_ = revoke(ctx, c)
	if err := deleteCreds(); err != nil {
		return err
	}
	fmt.Println("Signed out. Token revoked and local store deleted.")
	return nil
}

func cmdWhoami(ctx context.Context, args []string) error {
	fs := newFlagSet("whoami")
	asJSON := fs.Bool("json", false, "raw JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := loadCreds()
	if err != nil {
		return err
	}
	cl := newClient(c)
	if err := cl.dial(ctx); err != nil {
		return err
	}
	tools, err := cl.listTools(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(map[string]any{
			"resource":   c.Resource,
			"issuer":     c.Issuer,
			"client_id":  c.ClientID,
			"scope":      c.Scope,
			"expires_at": c.ExpiresAt,
			"tool_count": len(tools),
		})
	}
	fmt.Printf("Signed in to Slashy%s\n", accountSuffix(c))
	fmt.Printf("  endpoint   %s\n", c.Resource)
	fmt.Printf("  client_id  %s\n", c.ClientID)
	if c.Scope != "" {
		fmt.Printf("  scope      %s\n", c.Scope)
	}
	if c.ExpiresAt.IsZero() {
		fmt.Printf("  token      valid, no expiry advertised\n")
	} else {
		fmt.Printf("  token      valid, expires %s\n", c.ExpiresAt.Local().Format("2006-01-02 15:04 MST"))
	}
	fmt.Printf("  tools      %d available\n", len(tools))
	return nil
}

func accountSuffix(c *credentials) string {
	if c.Account == "" {
		return ""
	}
	return " as " + c.Account
}

// ---------- discovery ----------

func cmdTools(ctx context.Context, args []string) error {
	fs := newFlagSet("tools")
	asJSON := fs.Bool("json", false, "raw JSON output")
	q := fs.String("q", "", "filter by substring in name or description")
	if err := fs.Parse(args); err != nil {
		return err
	}
	tools, err := fetchTools(ctx)
	if err != nil {
		return err
	}
	if *q != "" {
		needle := strings.ToLower(*q)
		var keep []Tool
		for _, t := range tools {
			if strings.Contains(strings.ToLower(t.Name), needle) ||
				strings.Contains(strings.ToLower(t.Description), needle) {
				keep = append(keep, t)
			}
		}
		tools = keep
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })

	if *asJSON {
		return printJSON(tools)
	}
	if len(tools) == 0 {
		fmt.Println("No tools matched.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, t := range tools {
		fmt.Fprintf(w, "%s\t%s\n", t.Name, firstLine(t.Description))
	}
	w.Flush()
	fmt.Printf("\n%d tools. `gsl schema <tool>` for arguments.\n", len(tools))
	return nil
}

func cmdSchema(ctx context.Context, args []string) error {
	fs := newFlagSet("schema")
	asJSON := fs.Bool("json", false, "raw JSON schema")
	name, err := parseWithLeadingName(fs, args)
	if err != nil {
		return err
	}
	if name == "" {
		return errors.New("usage: gsl schema <tool>")
	}
	tools, err := fetchTools(ctx)
	if err != nil {
		return err
	}
	t := findTool(tools, name)
	if t == nil {
		return unknownToolError(name, tools)
	}
	if *asJSON {
		return printJSON(t)
	}
	fmt.Printf("%s\n", t.Name)
	if t.Description != "" {
		fmt.Printf("\n%s\n", t.Description)
	}
	props, required := schemaFields(t.InputSchema)
	if len(props) == 0 {
		fmt.Println("\nTakes no arguments.")
		return nil
	}
	fmt.Println("\nARGUMENTS")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	names := make([]string, 0, len(props))
	for n := range props {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		ri, rj := required[names[i]], required[names[j]]
		if ri != rj {
			return ri // required first
		}
		return names[i] < names[j]
	})
	for _, n := range names {
		f := props[n]
		flag := "optional"
		if required[n] {
			flag = "REQUIRED"
		}
		fmt.Fprintf(w, "  -a %s=\t%s\t%s\t%s\n", n, f.Type, flag, firstLine(f.Description))
	}
	w.Flush()
	return nil
}

// ---------- calling ----------

func cmdCall(ctx context.Context, args []string) error {
	fs := newFlagSet("call")
	var kv, sv argList
	fs.Var(&kv, "a", "argument key=value (JSON-coerced when possible)")
	fs.Var(&sv, "s", "argument key=value (always a string)")
	rawArgs := fs.String("args", "", "whole argument object as JSON")
	asJSON := fs.Bool("json", false, "raw JSON result")
	dryRun := fs.Bool("dry-run", false, "validate against the schema and stop")
	name, err := parseWithLeadingName(fs, args)
	if err != nil {
		return err
	}
	if name == "" {
		return errors.New("usage: gsl call <tool> [-a key=value]...  (`gsl tools` to list)")
	}

	toolArgs := map[string]any{}
	if *rawArgs != "" {
		if err := json.Unmarshal([]byte(*rawArgs), &toolArgs); err != nil {
			return fmt.Errorf("--args is not valid JSON: %w", err)
		}
	}
	for _, pair := range kv {
		k, v, err := splitPair(pair)
		if err != nil {
			return err
		}
		toolArgs[k] = coerce(v)
	}
	for _, pair := range sv {
		k, v, err := splitPair(pair)
		if err != nil {
			return err
		}
		toolArgs[k] = v
	}

	// Validate against the live schema before spending a round trip, and so a
	// typo names the tool it meant rather than failing server-side.
	tools, err := fetchTools(ctx)
	if err != nil {
		return err
	}
	t := findTool(tools, name)
	if t == nil {
		return unknownToolError(name, tools)
	}
	name = t.Name
	if err := validateArgs(t, toolArgs); err != nil {
		return err
	}
	if *dryRun {
		fmt.Printf("Would call %s with:\n", name)
		return printJSON(toolArgs)
	}

	c, err := loadCreds()
	if err != nil {
		return err
	}
	cl := newClient(c)
	tr, raw, err := cl.callTool(ctx, name, toolArgs)
	if err != nil {
		return err
	}
	if *asJSON {
		return printRaw(raw)
	}
	printToolResult(tr)
	return nil
}

// validateArgs checks required fields and rejects unknown keys, which is where
// most call failures actually come from.
func validateArgs(t *Tool, args map[string]any) error {
	props, required := schemaFields(t.InputSchema)
	if len(props) == 0 {
		return nil // no schema published; let the server decide
	}
	var missing []string
	for name, req := range required {
		if !req {
			continue
		}
		if _, ok := args[name]; !ok {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		return fmt.Errorf("tool %q needs %s\n\nRun `gsl schema %s` for the full argument list",
			t.Name, "-a "+strings.Join(missing, "=... -a ")+"=...", t.Name)
	}
	var unknown []string
	for k := range args {
		if _, ok := props[k]; !ok {
			unknown = append(unknown, k)
		}
	}
	sort.Strings(unknown)
	if len(unknown) > 0 {
		known := make([]string, 0, len(props))
		for k := range props {
			known = append(known, k)
		}
		sort.Strings(known)
		return fmt.Errorf("tool %q has no argument %s\n\nAccepted: %s",
			t.Name, strings.Join(unknown, ", "), strings.Join(known, ", "))
	}
	return nil
}

// ---------- doctor ----------

func cmdDoctor(ctx context.Context, args []string) error {
	fs := newFlagSet("doctor")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ok := true
	step := func(label string, fn func() (string, error)) {
		detail, err := fn()
		if err != nil {
			ok = false
			fmt.Printf("  FAIL  %-24s %v\n", label, err)
			return
		}
		fmt.Printf("  ok    %-24s %s\n", label, detail)
	}

	fmt.Println("Slashy MCP diagnostics")
	var asm *authServerMeta
	step("endpoint reachable", func() (string, error) {
		var prm protectedResourceMeta
		if err := getJSON(ctx, mcpOrigin+"/.well-known/oauth-protected-resource", &prm); err != nil {
			return "", err
		}
		return prm.Resource, nil
	})
	step("authorization server", func() (string, error) {
		a, _, err := discover(ctx)
		if err != nil {
			return "", err
		}
		asm = a
		return a.Issuer, nil
	})
	step("dynamic registration", func() (string, error) {
		if asm == nil || asm.RegistrationEndpoint == "" {
			return "", errors.New("no registration_endpoint advertised")
		}
		return asm.RegistrationEndpoint, nil
	})

	c, err := loadCreds()
	if err != nil {
		fmt.Printf("  FAIL  %-24s not signed in; run `gsl login`\n", "credentials")
		return errors.New("diagnostics incomplete: not signed in")
	}
	step("credentials on disk", func() (string, error) {
		p, _ := credsPath()
		fi, err := os.Stat(p)
		if err != nil {
			return "", err
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			return "", fmt.Errorf("%s is mode %o, expected 600", p, perm)
		}
		return p + " (0600)", nil
	})
	step("token freshness", func() (string, error) {
		if c.ExpiresAt.IsZero() {
			return "no expiry advertised", nil
		}
		if c.expired() {
			return "expired, will refresh on next call", nil
		}
		return "valid until " + c.ExpiresAt.Local().Format("15:04 MST"), nil
	})
	step("refresh token", func() (string, error) {
		if c.RefreshToken == "" {
			return "", errors.New("none stored; expiry will force a fresh login")
		}
		return "present", nil
	})
	step("live tools/list", func() (string, error) {
		cl := newClient(c)
		tools, err := cl.listTools(ctx)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d tools", len(tools)), nil
	})

	if !ok {
		return errors.New("diagnostics found problems")
	}
	fmt.Println("\nAll checks passed.")
	return nil
}
