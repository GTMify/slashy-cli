package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The --redirect-host escape hatch is only useful if the listener binds the same
// host that goes into the redirect URI. Binding 127.0.0.1 while redirecting to
// "localhost" fails on macOS, where localhost resolves to ::1 first, and that
// failure only surfaces against a server that rejects the 127.0.0.1 literal.
func TestRedirectHostBindsWhatItAdvertises(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "localhost", ""} {
		ln, uri, err := bindLoopback(host)
		if err != nil {
			t.Fatalf("bindLoopback(%q): %v", host, err)
		}

		// Reach the listener through the URI it advertised, which is what the
		// browser does. If the two disagree, this is the connection refused a
		// real login would hit.
		u, perr := url.Parse(uri)
		if perr != nil {
			ln.Close()
			t.Fatalf("bindLoopback(%q) produced an unparseable URI %q", host, uri)
		}
		conn, derr := net.DialTimeout("tcp", u.Host, 2*time.Second)
		if derr != nil {
			ln.Close()
			t.Fatalf("redirect URI %s is not reachable at the bound listener: %v", uri, derr)
		}
		conn.Close()
		ln.Close()

		want := host
		if want == "" {
			want = "127.0.0.1" // the documented default
		}
		if u.Hostname() != want {
			t.Errorf("bindLoopback(%q) advertised host %q, want %q", host, u.Hostname(), want)
		}
		if u.Path != "/callback" {
			t.Errorf("redirect path = %q, want /callback", u.Path)
		}
	}
}

// Two concurrent logins must not be handed the same port.
func TestBindLoopbackPortsAreDistinct(t *testing.T) {
	a, uriA, err := bindLoopback("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, uriB, err := bindLoopback("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if uriA == uriB {
		t.Errorf("two listeners share the redirect URI %s", uriA)
	}
}

// Go's flag package stops parsing at the first non-flag argument, so
// `gsl call draft_email -a to=x` parsed ZERO flags until this was fixed: the
// tool name halted the parser and every -a was left in fs.Args(). The call then
// reported its required arguments missing even though they were supplied, which
// reads like a server problem rather than a parsing one.
func TestParseWithLeadingName(t *testing.T) {
	cases := []struct {
		desc     string
		argv     []string
		wantName string
		wantArgs []string
		wantJSON bool
	}{
		{"name first, then flags", []string{"draft_email", "-a", "to=x", "-a", "subject=hi"},
			"draft_email", []string{"to=x", "subject=hi"}, false},
		{"bool flag first, then name", []string{"--json", "draft_email", "-a", "to=x"},
			"draft_email", []string{"to=x"}, true},
		// The value-carrying flag must not have its value mistaken for the name.
		{"value flag before the name", []string{"-a", "to=x", "draft_email", "-a", "subject=hi"},
			"draft_email", []string{"to=x", "subject=hi"}, false},
		{"joined flag syntax", []string{"-a=to=x", "draft_email"},
			"draft_email", []string{"to=x"}, false},
		{"flags on both sides", []string{"--json", "-a", "to=x", "draft_email", "-a", "subject=hi"},
			"draft_email", []string{"to=x", "subject=hi"}, true},
		{"name only", []string{"get_user_info"}, "get_user_info", nil, false},
		{"nothing", nil, "", nil, false},
		{"flags but no name", []string{"--json"}, "", nil, true},
	}
	for _, c := range cases {
		fs := newFlagSet("call")
		var kv argList
		fs.Var(&kv, "a", "")
		asJSON := fs.Bool("json", false, "")

		name, err := parseWithLeadingName(fs, c.argv)
		if err != nil {
			t.Fatalf("%s: %v", c.desc, err)
		}
		if name != c.wantName {
			t.Errorf("%s: name = %q, want %q", c.desc, name, c.wantName)
		}
		if !reflect.DeepEqual([]string(kv), c.wantArgs) {
			t.Errorf("%s: -a flags = %v, want %v", c.desc, []string(kv), c.wantArgs)
		}
		if *asJSON != c.wantJSON {
			t.Errorf("%s: --json = %v, want %v", c.desc, *asJSON, c.wantJSON)
		}
	}
}

// The end-to-end shape the bug actually broke: every supplied argument must
// survive parsing and satisfy the schema.
func TestArgsSurviveParsingIntoValidation(t *testing.T) {
	fs := newFlagSet("call")
	var kv argList
	fs.Var(&kv, "a", "")
	name, err := parseWithLeadingName(fs, []string{
		"draft_email", "-a", "inbox_email=a@b.com", "-a", "subject=hi",
	})
	if err != nil {
		t.Fatal(err)
	}
	if name != "draft_email" {
		t.Fatalf("name = %q", name)
	}
	args := map[string]any{}
	for _, pair := range kv {
		k, v, perr := splitPair(pair)
		if perr != nil {
			t.Fatal(perr)
		}
		args[k] = coerce(v)
	}
	tool := &Tool{Name: "draft_email", InputSchema: json.RawMessage(
		`{"type":"object","properties":{"inbox_email":{"type":"string"},"subject":{"type":"string"}},"required":["inbox_email"]}`)}
	if err := validateArgs(tool, args); err != nil {
		t.Errorf("arguments supplied on the command line failed validation: %v", err)
	}
}

func TestCoerce(t *testing.T) {
	cases := []struct {
		in   string
		want any
	}{
		{"true", true},
		{"false", false},
		{"null", nil},
		{"42", int64(42)},
		{"-7", int64(-7)},
		{"3.5", 3.5},
		{`{"a":1}`, map[string]any{"a": float64(1)}},
		{`[1,2]`, []any{float64(1), float64(2)}},
		{"hello", "hello"},
		{"from:alice unread", "from:alice unread"},
		{"", ""},
		// A bare word that looks like a type but is not valid JSON stays text.
		{"True", "True"},
		// Unparseable JSON-ish input falls back to the literal string.
		{"{not json", "{not json"},
	}
	for _, c := range cases {
		got := coerce(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("coerce(%q) = %#v (%T), want %#v (%T)", c.in, got, got, c.want, c.want)
		}
	}
}

func TestSplitPair(t *testing.T) {
	k, v, err := splitPair("subject=Hello = World")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if k != "subject" || v != "Hello = World" {
		t.Errorf("got key=%q value=%q, want key=subject value=%q", k, v, "Hello = World")
	}
	// An empty value is legitimate.
	if _, v, err := splitPair("body="); err != nil || v != "" {
		t.Errorf("splitPair(body=) = %q, %v; want empty value and no error", v, err)
	}
	// A missing "=" and a leading "=" are both errors.
	for _, bad := range []string{"noequals", "=novalue"} {
		if _, _, err := splitPair(bad); err == nil {
			t.Errorf("splitPair(%q) should have failed", bad)
		}
	}
}

func TestSchemaFields(t *testing.T) {
	raw := json.RawMessage(`{
	  "type": "object",
	  "properties": {
	    "to":      {"type": "string",  "description": "Recipient"},
	    "limit":   {"type": "integer", "description": "Max results"},
	    "urgent":  {"type": ["boolean","null"]},
	    "mode":    {"type": "string", "enum": ["draft","send"]}
	  },
	  "required": ["to"]
	}`)
	props, required := schemaFields(raw)
	if len(props) != 4 {
		t.Fatalf("got %d properties, want 4", len(props))
	}
	if !required["to"] {
		t.Error("field 'to' should be required")
	}
	if required["limit"] {
		t.Error("field 'limit' should not be required")
	}
	// A nullable union renders without the null arm.
	if got := props["urgent"].Type; got != "boolean" {
		t.Errorf("urgent type = %q, want boolean", got)
	}
	// Enum options are appended to the description so `gsl schema` shows them.
	if !strings.Contains(props["mode"].Description, "draft|send") {
		t.Errorf("mode description = %q, want it to list the enum", props["mode"].Description)
	}
	// Optional fields must still be present as keys so unknown-arg detection works.
	if _, ok := required["limit"]; !ok {
		t.Error("optional fields must appear in the required map as false")
	}
}

func TestSchemaFieldsTolerantOfJunk(t *testing.T) {
	for _, raw := range []json.RawMessage{nil, json.RawMessage(``), json.RawMessage(`"a string"`), json.RawMessage(`{}`)} {
		props, required := schemaFields(raw)
		if props == nil || required == nil {
			t.Errorf("schemaFields(%q) returned a nil map; callers index these", string(raw))
		}
	}
}

func TestValidateArgs(t *testing.T) {
	tool := &Tool{
		Name: "send_email",
		InputSchema: json.RawMessage(`{"type":"object",
		  "properties":{"to":{"type":"string"},"body":{"type":"string"}},
		  "required":["to","body"]}`),
	}
	if err := validateArgs(tool, map[string]any{"to": "a@b.com", "body": "hi"}); err != nil {
		t.Errorf("valid args rejected: %v", err)
	}
	err := validateArgs(tool, map[string]any{"to": "a@b.com"})
	if err == nil || !strings.Contains(err.Error(), "body") {
		t.Errorf("missing required arg should be named in the error, got: %v", err)
	}
	err = validateArgs(tool, map[string]any{"to": "a@b.com", "body": "hi", "cc": "x@y.com"})
	if err == nil || !strings.Contains(err.Error(), "cc") {
		t.Errorf("unknown arg should be named in the error, got: %v", err)
	}
	// With no schema published, validation defers to the server.
	if err := validateArgs(&Tool{Name: "x"}, map[string]any{"anything": 1}); err != nil {
		t.Errorf("no-schema tool should skip local validation, got: %v", err)
	}
}

func TestFindTool(t *testing.T) {
	tools := []Tool{{Name: "send_email"}, {Name: "listEvents"}}
	for _, q := range []string{"send_email", "send-email", "SEND_EMAIL", "Send-Email"} {
		if got := findTool(tools, q); got == nil || got.Name != "send_email" {
			t.Errorf("findTool(%q) did not resolve to send_email", q)
		}
	}
	if got := findTool(tools, "listevents"); got == nil || got.Name != "listEvents" {
		t.Error("findTool should match case-insensitively")
	}
	if findTool(tools, "nope") != nil {
		t.Error("findTool should return nil for an unknown name")
	}
}

func TestUnknownToolErrorSuggests(t *testing.T) {
	tools := []Tool{{Name: "send_email"}, {Name: "draft_email"}, {Name: "list_events"}}
	err := unknownToolError("email", tools)
	msg := err.Error()
	if !strings.Contains(msg, "send_email") || !strings.Contains(msg, "draft_email") {
		t.Errorf("expected near-matches in the error, got: %s", msg)
	}
	if strings.Contains(msg, "list_events") {
		t.Errorf("unrelated tool should not be suggested, got: %s", msg)
	}
}

// readRPCBody is the transport detail most likely to break silently, so both
// framings and the notification-interleaving case are covered.
func TestReadRPCBodyPlainJSON(t *testing.T) {
	res := fakeResponse("application/json", `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`)
	got, err := readRPCBody(res)
	if err != nil {
		t.Fatal(err)
	}
	var out rpcResponse
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatal(err)
	}
	if string(out.Result) != `{"ok":true}` {
		t.Errorf("result = %s", out.Result)
	}
}

func TestReadRPCBodySSE(t *testing.T) {
	body := "event: message\n" +
		"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n" +
		"\n"
	res := fakeResponse("text/event-stream", body)
	got, err := readRPCBody(res)
	if err != nil {
		t.Fatal(err)
	}
	var out rpcResponse
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("SSE payload did not unframe to JSON-RPC: %v (raw %q)", err, got)
	}
	if out.Result == nil {
		t.Error("expected a result in the unframed SSE response")
	}
}

func TestReadRPCBodySSESkipsNotifications(t *testing.T) {
	// A progress notification arrives before the real answer. The reader must
	// step over it rather than returning it as the response.
	body := ": keepalive\n" +
		"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"p\":10}}\n" +
		"\n" +
		"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"done\":true}}\n" +
		"\n"
	res := fakeResponse("text/event-stream", body)
	got, err := readRPCBody(res)
	if err != nil {
		t.Fatal(err)
	}
	var out rpcResponse
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatal(err)
	}
	if string(out.Result) != `{"done":true}` {
		t.Errorf("expected the response frame, got %s", out.Result)
	}
}

func TestReadRPCBodySSEError(t *testing.T) {
	body := "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602,\"message\":\"bad args\"}}\n\n"
	res := fakeResponse("text/event-stream", body)
	got, err := readRPCBody(res)
	if err != nil {
		t.Fatal(err)
	}
	var out rpcResponse
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatal(err)
	}
	if out.Error == nil || out.Error.Code != -32602 {
		t.Errorf("error frame did not survive unframing: %+v", out.Error)
	}
}

// A multi-line SSE data field is concatenated per the spec.
func TestReadRPCBodySSEMultilineData(t *testing.T) {
	body := "data: {\"jsonrpc\":\"2.0\",\"id\":1,\n" +
		"data: \"result\":{\"ok\":1}}\n\n"
	res := fakeResponse("text/event-stream", body)
	got, err := readRPCBody(res)
	if err != nil {
		t.Fatal(err)
	}
	var out rpcResponse
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("multi-line data frame did not reassemble: %v (raw %q)", err, got)
	}
	if out.Result == nil {
		t.Error("expected a result from the reassembled frame")
	}
}

func TestCredentialsExpiry(t *testing.T) {
	var c credentials
	if c.expired() {
		t.Error("a zero expiry means none was advertised, so it is not expired")
	}
	c.ExpiresAt = nowPlus(-1)
	if !c.expired() {
		t.Error("a past expiry should read as expired")
	}
	// Inside the skew window it is treated as expired so a call in flight does
	// not land on the far side of the boundary.
	c.ExpiresAt = nowPlus(30)
	if !c.expired() {
		t.Error("an expiry inside the skew window should read as expired")
	}
	c.ExpiresAt = nowPlus(3600)
	if c.expired() {
		t.Error("an expiry well in the future should not read as expired")
	}
}

func TestApplyTokenKeepsRefreshTokenWhenOmitted(t *testing.T) {
	c := &credentials{RefreshToken: "original"}
	applyToken(c, &tokenResponse{AccessToken: "a1", ExpiresIn: 3600})
	if c.RefreshToken != "original" {
		t.Error("a response without a refresh_token must not clear the stored one")
	}
	if c.TokenType != "Bearer" {
		t.Errorf("token type should default to Bearer, got %q", c.TokenType)
	}
	// Rotation: a new refresh token replaces the old one.
	applyToken(c, &tokenResponse{AccessToken: "a2", RefreshToken: "rotated", ExpiresIn: 3600})
	if c.RefreshToken != "rotated" {
		t.Error("a rotated refresh token must be persisted, or the next refresh fails")
	}
	if c.ExpiresAt.IsZero() {
		t.Error("expires_in should produce an absolute expiry")
	}
}

func TestTokenTypeNormalises(t *testing.T) {
	if got := tokenType(&credentials{TokenType: "bearer"}); got != "Bearer" {
		t.Errorf("tokenType(bearer) = %q, want Bearer", got)
	}
	if got := tokenType(&credentials{}); got != "Bearer" {
		t.Errorf("empty token type should default to Bearer, got %q", got)
	}
}

func TestPKCEPairIsVerifiable(t *testing.T) {
	v, ch, err := pkcePair()
	if err != nil {
		t.Fatal(err)
	}
	if len(v) < 43 || len(v) > 128 {
		t.Errorf("verifier length %d is outside the RFC 7636 range of 43 to 128", len(v))
	}
	if strings.ContainsAny(v+ch, "+/=") {
		t.Error("verifier and challenge must be base64url without padding")
	}
	if v == ch {
		t.Error("challenge must be the hash of the verifier, not the verifier")
	}
	v2, _, _ := pkcePair()
	if v == v2 {
		t.Error("each login must use a fresh verifier")
	}
}

// The digest is what keeps a call cheap. Measured case: draft_email returns
// 185KB, almost all of it a base64 signature image, and an unbounded
// passthrough would put every byte in the caller's context.
func TestCompactValue(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{nil, "null"},
		{true, "true"},
		// JSON numbers arrive as float64; an id must not print as 9.579225e+07.
		{float64(95792250), "95792250"},
		{float64(1.5), "1.5"},
		{"short", "short"},
		{[]any{}, "[]"},
		{[]any{"a", "b"}, "[a, b]"},
		{[]any{map[string]any{"x": 1}}, "[1 items]"},
		{map[string]any{"b": 1, "a": 2}, "{a, b}"},
	}
	for _, c := range cases {
		if got := compactValue(c.in); got != c.want {
			t.Errorf("compactValue(%#v) = %q, want %q", c.in, got, c.want)
		}
	}
	// A long string is truncated and reports its true size.
	long := compactValue(strings.Repeat("x", 5000))
	if len(long) > fieldValueLimit+20 {
		t.Errorf("long string rendered %d chars, should be capped near %d", len(long), fieldValueLimit)
	}
	if !strings.Contains(long, "4.9KB") {
		t.Errorf("truncated value should report the real size, got %q", long)
	}
	// Multi-line values must not break the one-line-per-field layout.
	if got := compactValue("a\nb"); strings.Contains(got, "\n") {
		t.Errorf("newlines should be flattened, got %q", got)
	}
}

func TestByteCount(t *testing.T) {
	cases := map[int]string{0: "0B", 512: "512B", 1536: "1.5KB", 2 << 20: "2.0MB"}
	for in, want := range cases {
		if got := byteCount(in); got != want {
			t.Errorf("byteCount(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestPrintSummaryBoundsOutput(t *testing.T) {
	// A big JSON document must be digested, not dumped.
	big := map[string]any{"success": true, "body_html": strings.Repeat("z", 180_000)}
	raw, _ := json.Marshal(big)
	out := captureStdout(func() { printSummary(string(raw)) })
	if len(out) > 2000 {
		t.Errorf("a %s payload rendered %d bytes; the digest is not bounding it", byteCount(len(raw)), len(out))
	}
	for _, want := range []string{"success", "body_html", "--json"} {
		if !strings.Contains(out, want) {
			t.Errorf("digest should mention %q, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, strings.Repeat("z", 200)) {
		t.Error("the digest leaked the full field value")
	}

	// Small JSON is more useful shown whole.
	small := captureStdout(func() { printSummary(`{"ok":true,"id":"abc"}`) })
	if !strings.Contains(small, `"ok": true`) {
		t.Errorf("small JSON should print in full, got:\n%s", small)
	}

	// Prose is passed through untouched.
	prose := captureStdout(func() { printSummary("Draft created successfully.") })
	if strings.TrimSpace(prose) != "Draft created successfully." {
		t.Errorf("prose should pass through, got %q", prose)
	}
}

func captureStdout(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	b, _ := io.ReadAll(r)
	return string(b)
}

func TestFirstLineTruncates(t *testing.T) {
	if got := firstLine("one\ntwo"); got != "one" {
		t.Errorf("got %q, want one", got)
	}
	long := strings.Repeat("x", 200)
	if got := firstLine(long); len(got) != 96 || !strings.HasSuffix(got, "...") {
		t.Errorf("long text should truncate to 96 chars ending in an ellipsis, got %d", len(got))
	}
}

// ---------- helpers ----------

func fakeResponse(contentType, body string) *http.Response {
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{contentType}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func nowPlus(seconds int) time.Time { return time.Now().Add(time.Duration(seconds) * time.Second) }
