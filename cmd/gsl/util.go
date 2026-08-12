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
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
)

// newFlagSet returns a flag set that reports errors through the normal error
// path instead of calling os.Exit, and prints gsl's own usage on failure.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
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

// printToolResult prints the human summary. MCP servers usually return text
// content already written for an agent, so passing it through beats re-rendering.
func printToolResult(tr *toolResult) {
	printed := false
	for _, c := range tr.Content {
		if c.Text != "" {
			fmt.Println(strings.TrimRight(c.Text, "\n"))
			printed = true
		}
	}
	if !printed && len(tr.StructuredContent) > 0 {
		_ = printRaw(tr.StructuredContent)
		printed = true
	}
	if !printed {
		fmt.Println("(the tool returned no content)")
	}
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
