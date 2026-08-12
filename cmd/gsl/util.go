package main

// Argument parsing, JSON Schema introspection, and output rendering.
//
// The schema helpers exist so the CLI can validate a call and print real
// argument help without a compiled-in tool list. Everything here reads the
// inputSchema that tools/list returns at runtime.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
)

// newFlagSet returns a flag set that reports errors through the normal error
// path instead of calling os.Exit, and prints gsl's own usage on failure.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

// parseWithLeadingName pulls a leading positional argument off the front before
// handing the rest to the flag set, then falls back to the first remaining
// positional if the name came after the flags.
//
// This exists because Go's flag package stops parsing at the FIRST
// non-flag argument. Without it, `gsl call draft_email -a to=x` parses zero
// flags: "draft_email" halts the parser and every -a is left in fs.Args(). The
// failure is quiet and looks like a server-side problem, since the call then
// reports the required arguments missing even though they were supplied.
func parseWithLeadingName(fs *flag.FlagSet, args []string) (string, error) {
	name, rest := extractName(fs, args)
	if err := fs.Parse(rest); err != nil {
		return "", err
	}
	return name, nil
}

// extractName finds the first bare positional argument and returns it along
// with the remaining arguments, so the flag set never sees the token that would
// halt it. Flags may appear on either side of the name.
//
// It has to know which flags consume a following value, or `-a to=x draft_email`
// would mistake "to=x" for the tool name. Boolean flags advertise themselves
// through IsBoolFlag, which is how the flag package itself decides this.
func extractName(fs *flag.FlagSet, args []string) (string, []string) {
	isBool := func(n string) bool {
		f := fs.Lookup(n)
		if f == nil {
			return false
		}
		b, ok := f.Value.(interface{ IsBoolFlag() bool })
		return ok && b.IsBoolFlag()
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--": // everything after this is positional
			if i+1 < len(args) {
				return args[i+1], append(args[:i:i], args[i+2:]...)
			}
			return "", args[:i:i]
		case strings.HasPrefix(a, "-") && a != "-":
			flagName := strings.TrimLeft(a, "-")
			if strings.Contains(flagName, "=") {
				continue // -flag=value carries its own value
			}
			if !isBool(flagName) {
				i++ // the next token is this flag's value, not the name
			}
		default:
			// The three-index slice keeps the copy from aliasing args.
			return a, append(args[:i:i], args[i+1:]...)
		}
	}
	return "", args
}

// argList collects a repeated flag (-a key=value -a key2=value2).
type argList []string

func (a *argList) String() string     { return strings.Join(*a, ",") }
func (a *argList) Set(v string) error { *a = append(*a, v); return nil }

func splitPair(pair string) (string, string, error) {
	i := strings.Index(pair, "=")
	if i <= 0 {
		return "", "", fmt.Errorf("argument %q must be key=value", pair)
	}
	return pair[:i], pair[i+1:], nil
}

// coerce turns a command-line string into the most likely intended JSON type.
// Numbers, booleans, null, objects, and arrays are parsed; everything else stays
// a string. Use -s to force a string when a subject line happens to read "true".
func coerce(v string) any {
	t := strings.TrimSpace(v)
	if t == "" {
		return v
	}
	switch t {
	case "true":
		return true
	case "false":
		return false
	case "null":
		return nil
	}
	if n, err := strconv.ParseInt(t, 10, 64); err == nil {
		return n
	}
	if f, err := strconv.ParseFloat(t, 64); err == nil {
		return f
	}
	if strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
		var out any
		if err := json.Unmarshal([]byte(t), &out); err == nil {
			return out
		}
	}
	return v
}

// ---------- JSON Schema introspection ----------

type schemaField struct {
	Type        string
	Description string
}

// schemaFields flattens a tool's inputSchema into a property map plus a
// required-name set. It handles the ordinary object schema and tolerates a
// missing or unusual schema by returning nothing, which callers treat as
// "no local validation possible".
func schemaFields(raw json.RawMessage) (map[string]schemaField, map[string]bool) {
	props := map[string]schemaField{}
	required := map[string]bool{}
	if len(raw) == 0 {
		return props, required
	}
	var s struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return props, required
	}
	for name, p := range s.Properties {
		var f struct {
			Type        any    `json:"type"`
			Description string `json:"description"`
			Enum        []any  `json:"enum"`
		}
		_ = json.Unmarshal(p, &f)
		desc := f.Description
		if len(f.Enum) > 0 {
			opts := make([]string, 0, len(f.Enum))
			for _, e := range f.Enum {
				opts = append(opts, fmt.Sprint(e))
			}
			if desc != "" {
				desc += " "
			}
			desc += "(" + strings.Join(opts, "|") + ")"
		}
		props[name] = schemaField{Type: typeName(f.Type), Description: desc}
	}
	for _, r := range s.Required {
		required[r] = true
	}
	// Every property is a key, required or not, so the map covers both lookups.
	for name := range props {
		if _, ok := required[name]; !ok {
			required[name] = false
		}
	}
	return props, required
}

// typeName renders a schema "type", which may be a string or a list of strings.
func typeName(t any) string {
	switch v := t.(type) {
	case string:
		return v
	case []any:
		parts := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok && s != "null" {
				parts = append(parts, s)
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, "|")
		}
	}
	return "any"
}

// ---------- tool lookup ----------

func fetchTools(ctx context.Context) ([]Tool, error) {
	c, err := loadCreds()
	if err != nil {
		return nil, err
	}
	return newClient(c).listTools(ctx)
}

// findTool matches exactly first, then case-insensitively, then treats "-" and
// "_" as equivalent so `gsl send-email` finds `send_email`.
func findTool(tools []Tool, name string) *Tool {
	for i := range tools {
		if tools[i].Name == name {
			return &tools[i]
		}
	}
	norm := func(s string) string {
		return strings.ToLower(strings.ReplaceAll(s, "-", "_"))
	}
	target := norm(name)
	for i := range tools {
		if norm(tools[i].Name) == target {
			return &tools[i]
		}
	}
	return nil
}

// unknownToolError names the closest candidates rather than only reporting a
// miss, because the tool surface is server-side and cannot be guessed.
func unknownToolError(name string, tools []Tool) error {
	target := strings.ToLower(strings.ReplaceAll(name, "-", "_"))
	var near []string
	for _, t := range tools {
		lt := strings.ToLower(t.Name)
		if strings.Contains(lt, target) || strings.Contains(target, lt) {
			near = append(near, t.Name)
		}
	}
	// Fall back to matching any single word of the request.
	if len(near) == 0 {
		for _, word := range strings.FieldsFunc(target, func(r rune) bool { return r == '_' }) {
			if len(word) < 3 {
				continue
			}
			for _, t := range tools {
				if strings.Contains(strings.ToLower(t.Name), word) {
					near = append(near, t.Name)
				}
			}
		}
	}
	sort.Strings(near)
	near = dedupe(near)
	if len(near) > 8 {
		near = near[:8]
	}
	msg := fmt.Sprintf("no Slashy tool named %q", name)
	if len(near) > 0 {
		msg += "\n\nDid you mean: " + strings.Join(near, ", ")
	}
	return fmt.Errorf("%s\n\nRun `gsl tools` to list all %d.", msg, len(tools))
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ---------- output ----------

// Bounds on the default (non---json) rendering. The whole reason to prefer a
// CLI over a connected MCP server is that the heavy payload stays out of the
// caller's context, so an unbounded passthrough would give that away. Measured
// case: draft_email returns 180KB, nearly all of it a base64 signature image.
const (
	inlineJSONLimit = 900  // JSON at or under this prints in full
	plainTextLimit  = 4000 // prose is passed through up to here
	fieldValueLimit = 96   // per-field cap inside a digest
)

// printToolResult prints the human summary. Slashy's tools mostly return a JSON
// document as content[0].text, so a digest of the top level beats both dumping
// it and hiding it. `--json` remains the way to get everything.
func printToolResult(tr *toolResult) {
	printed := false
	for _, c := range tr.Content {
		if c.Text != "" {
			printSummary(c.Text)
			printed = true
		}
	}
	if !printed && len(tr.StructuredContent) > 0 {
		printSummary(string(tr.StructuredContent))
		printed = true
	}
	if !printed {
		fmt.Println("(the tool returned no content)")
	}
}

func printSummary(text string) {
	trimmed := strings.TrimSpace(text)
	var v any
	if err := json.Unmarshal([]byte(trimmed), &v); err != nil {
		// Prose, which is already written for a reader. Pass it through, capped.
		if len(trimmed) <= plainTextLimit {
			fmt.Println(strings.TrimRight(trimmed, "\n"))
			return
		}
		fmt.Println(strings.TrimRight(trimmed[:plainTextLimit], "\n"))
		fmt.Printf("\n... truncated, %s total. Add --json for all of it.\n", byteCount(len(trimmed)))
		return
	}
	if len(trimmed) <= inlineJSONLimit {
		_ = printJSON(v) // small enough to be worth showing whole
		return
	}
	digest(v)
	fmt.Printf("\n(%s payload digested. Add --json for the full result.)\n", byteCount(len(trimmed)))
}

// digest prints one line per top-level field, with a compact stand-in for any
// value too large to show.
func digest(v any) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, k := range keys {
			fmt.Fprintf(w, "  %s\t%s\n", k, compactValue(t[k]))
		}
		w.Flush()
	case []any:
		fmt.Printf("  [%d items]\n", len(t))
		for i, item := range t {
			if i >= 5 {
				fmt.Printf("  ... and %d more\n", len(t)-5)
				break
			}
			fmt.Printf("  %d. %s\n", i+1, compactValue(item))
		}
	default:
		fmt.Println("  " + compactValue(v))
	}
}

func compactValue(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		s := strings.TrimSpace(strings.ReplaceAll(t, "\n", " "))
		if len(s) <= fieldValueLimit {
			return s
		}
		return fmt.Sprintf("%s... (%s)", s[:fieldValueLimit-3], byteCount(len(t)))
	case bool:
		return fmt.Sprint(t)
	case float64:
		// JSON numbers decode to float64, so an id like 95792250 would otherwise
		// print as 9.579225e+07 and be useless to copy.
		if t == math.Trunc(t) && math.Abs(t) < 1e15 {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case []any:
		if len(t) == 0 {
			return "[]"
		}
		// A short list of scalars is more useful shown than counted.
		if len(t) <= 3 {
			parts := make([]string, 0, len(t))
			simple := true
			for _, x := range t {
				switch x.(type) {
				case map[string]any, []any:
					simple = false
				}
				if !simple {
					break
				}
				parts = append(parts, compactValue(x))
			}
			if simple {
				return "[" + strings.Join(parts, ", ") + "]"
			}
		}
		return fmt.Sprintf("[%d items]", len(t))
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) > 6 {
			return fmt.Sprintf("{%d fields: %s, ...}", len(keys), strings.Join(keys[:6], ", "))
		}
		return fmt.Sprintf("{%s}", strings.Join(keys, ", "))
	}
	return fmt.Sprint(v)
}

func byteCount(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%dB", n)
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// printRaw re-indents a raw JSON payload, falling back to the bytes as-is when
// the payload is not valid JSON.
func printRaw(raw json.RawMessage) error {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		fmt.Println(string(raw))
		return nil
	}
	return printJSON(v)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\n\r"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 96 {
		s = s[:93] + "..."
	}
	return s
}

// ---------- small HTTP helpers ----------

func getJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		return fmt.Errorf("GET %s returned HTTP %d", url, res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

func postJSON(ctx context.Context, url string, body any, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("POST %s returned HTTP %d with an unparseable body: %s", url, res.StatusCode, truncate(string(payload), 200))
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
