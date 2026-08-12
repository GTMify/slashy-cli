package main

// JSON-RPC client for the Slashy MCP server over Streamable HTTP.
//
// Three things about this transport bite if you assume plain JSON over POST:
//
//  1. The server may answer any POST with either application/json or an SSE
//     stream (text/event-stream). Both carry the same JSON-RPC envelope, so the
//     reader has to sniff the content type and unframe "data:" lines.
//  2. initialize returns an Mcp-Session-Id header that must be echoed on every
//     later request. Dropping it reads back as an auth failure.
//  3. The spec requires a notifications/initialized message after initialize and
//     before the first real call. Servers that enforce it reject tools/list with
//     a confusing "not initialized" error.
//
// A 401 mid-session triggers exactly one refresh-and-retry. It never loops.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	protocolVersion = "2025-06-18"
	userAgent       = "gsl (gtmify-slashy CLI)"
)

var httpClient = &http.Client{Timeout: 120 * time.Second}

// ---------- JSON-RPC envelopes ----------

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *rpcError) Error() string {
	if len(e.Data) > 0 {
		return fmt.Sprintf("%s (code %d): %s", e.Message, e.Code, string(e.Data))
	}
	return fmt.Sprintf("%s (code %d)", e.Message, e.Code)
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// ---------- tool result shapes ----------

type toolContent struct {
	Type string          `json:"type"`
	Text string          `json:"text,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

type toolResult struct {
	Content           []toolContent   `json:"content"`
	StructuredContent json.RawMessage `json:"structuredContent,omitempty"`
	IsError           bool            `json:"isError"`
}

// Tool is one entry from tools/list.
type Tool struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

type toolsListResult struct {
	Tools      []Tool `json:"tools"`
	NextCursor string `json:"nextCursor,omitempty"`
}

// ---------- client ----------

type client struct {
	creds     *credentials
	sessionID string
	nextID    int
	inited    bool
	refreshed bool // one refresh-and-retry per process
	mu        sync.Mutex
}

func newClient(c *credentials) *client { return &client{creds: c, nextID: 1} }

// dial ensures the session is initialized, refreshing a stale token first so the
// very first call does not have to fail to discover it needs one.
func (c *client) dial(ctx context.Context) error {
	if c.inited {
		return nil
	}
	if c.creds.expired() && c.creds.RefreshToken != "" {
		if err := refresh(ctx, c.creds); err != nil {
			return err
		}
	}
	initParams := map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "gsl", "version": version},
	}
	if _, err := c.rpc(ctx, "initialize", initParams); err != nil {
		return err
	}
	c.inited = true
	// Required handshake completion. It is a notification, so no response.
	_ = c.notify(ctx, "notifications/initialized", map[string]any{})
	return nil
}

// rpc issues one JSON-RPC call with a single refresh-and-retry on 401.
func (c *client) rpc(ctx context.Context, method string, params any) (json.RawMessage, error) {
	res, status, err := c.do(ctx, method, params, false)
	if status == http.StatusUnauthorized {
		c.mu.Lock()
		alreadyTried := c.refreshed
		c.refreshed = true
		c.mu.Unlock()

		if alreadyTried || c.creds.RefreshToken == "" {
			return nil, errNeedsLogin{reason: "the Slashy server rejected the stored token"}
		}
		if rerr := refresh(ctx, c.creds); rerr != nil {
			return nil, rerr
		}
		c.sessionID = "" // a refreshed identity starts a new session
		res, status, err = c.do(ctx, method, params, true)
		if status == http.StatusUnauthorized {
			return nil, errNeedsLogin{reason: "still unauthorized after refreshing the token"}
		}
	}
	return res, err
}

func (c *client) notify(ctx context.Context, method string, params any) error {
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", Method: method, Params: params})
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, body)
	if err != nil {
		return err
	}
	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	return nil
}

func (c *client) do(ctx context.Context, method string, params any, isRetry bool) (json.RawMessage, int, error) {
	c.mu.Lock()
	id := c.nextID
	c.nextID++
	c.mu.Unlock()

	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params})
	if err != nil {
		return nil, 0, err
	}
	req, err := c.newRequest(ctx, body)
	if err != nil {
		return nil, 0, err
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("call %s: Slashy MCP endpoint unreachable: %w", method, err)
	}
	defer res.Body.Close()

	// initialize hands back the session id; every later request must echo it.
	if sid := res.Header.Get("Mcp-Session-Id"); sid != "" {
		c.sessionID = sid
	}

	if res.StatusCode == http.StatusUnauthorized {
		io.Copy(io.Discard, res.Body)
		return nil, res.StatusCode, nil
	}

	raw, err := readRPCBody(res)
	if err != nil {
		return nil, res.StatusCode, fmt.Errorf("call %s: %w", method, err)
	}
	if raw == nil {
		if res.StatusCode >= 400 {
			return nil, res.StatusCode, fmt.Errorf("call %s: Slashy returned HTTP %d with no JSON-RPC body", method, res.StatusCode)
		}
		return nil, res.StatusCode, nil
	}
	var out rpcResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, res.StatusCode, fmt.Errorf("call %s: unparseable response: %w", method, err)
	}
	if out.Error != nil {
		return nil, res.StatusCode, fmt.Errorf("Slashy rejected %s: %w", method, out.Error)
	}
	return out.Result, res.StatusCode, nil
}

func (c *client) newRequest(ctx context.Context, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, mcpURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	// Accept both framings; the server picks.
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", tokenType(c.creds)+" "+c.creds.AccessToken)
	req.Header.Set("User-Agent", userAgent)
	if c.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", c.sessionID)
	}
	if c.inited {
		req.Header.Set("MCP-Protocol-Version", protocolVersion)
	}
	return req, nil
}

func tokenType(c *credentials) string {
	if c.TokenType == "" {
		return "Bearer"
	}
	// Normalise "bearer" to "Bearer"; some servers compare case-sensitively.
	if strings.EqualFold(c.TokenType, "bearer") {
		return "Bearer"
	}
	return c.TokenType
}

// readRPCBody returns the JSON-RPC payload from either a plain JSON body or an
// SSE stream. For SSE it returns the first data frame carrying a response with a
// result or an error, ignoring interleaved progress notifications.
func readRPCBody(res *http.Response) ([]byte, error) {
	ct := res.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/event-stream") {
		b, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(b)) == 0 {
			return nil, nil
		}
		return b, nil
	}

	sc := bufio.NewScanner(res.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var data strings.Builder
	flush := func() []byte {
		if data.Len() == 0 {
			return nil
		}
		payload := strings.TrimSpace(data.String())
		data.Reset()
		if payload == "" {
			return nil
		}
		var probe rpcResponse
		if err := json.Unmarshal([]byte(payload), &probe); err != nil {
			return nil // not a response frame; keep reading
		}
		if probe.Result == nil && probe.Error == nil {
			return nil // a notification, not our answer
		}
		return []byte(payload)
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "": // frame boundary
			if out := flush(); out != nil {
				return out, nil
			}
		case strings.HasPrefix(line, "data:"):
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		case strings.HasPrefix(line, ":"): // comment / keepalive
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read event stream: %w", err)
	}
	if out := flush(); out != nil {
		return out, nil
	}
	return nil, nil
}

// ---------- high level ----------

func (c *client) listTools(ctx context.Context) ([]Tool, error) {
	if err := c.dial(ctx); err != nil {
		return nil, err
	}
	var all []Tool
	params := map[string]any{}
	for page := 0; page < 50; page++ { // bounded; guards a server that never clears the cursor
		raw, err := c.rpc(ctx, "tools/list", params)
		if err != nil {
			return nil, err
		}
		var out toolsListResult
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("parse tools/list: %w", err)
		}
		all = append(all, out.Tools...)
		if out.NextCursor == "" {
			break
		}
		params = map[string]any{"cursor": out.NextCursor}
	}
	return all, nil
}

// callTool invokes one tool and returns its content plus the raw result.
func (c *client) callTool(ctx context.Context, name string, args map[string]any) (*toolResult, json.RawMessage, error) {
	if err := c.dial(ctx); err != nil {
		return nil, nil, err
	}
	if args == nil {
		args = map[string]any{}
	}
	raw, err := c.rpc(ctx, "tools/call", map[string]any{"name": name, "arguments": args})
	if err != nil {
		return nil, nil, err
	}
	var tr toolResult
	if err := json.Unmarshal(raw, &tr); err != nil {
		return nil, raw, fmt.Errorf("parse result of tool %q: %w", name, err)
	}
	if tr.IsError {
		return &tr, raw, fmt.Errorf("tool %q reported an error: %s", name, firstText(&tr))
	}
	return &tr, raw, nil
}

func firstText(tr *toolResult) string {
	for _, c := range tr.Content {
		if c.Text != "" {
			return c.Text
		}
	}
	return "(no message)"
}
