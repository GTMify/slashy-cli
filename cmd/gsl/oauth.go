package main

// OAuth 2.1 + PKCE for the Slashy MCP server.
//
// Slashy issues no API keys. The server advertises RFC 9728 protected-resource
// metadata, RFC 8414 authorization-server metadata, and RFC 7591 dynamic client
// registration, all unauthenticated, so the CLI registers itself as a public
// client at login time and never needs a client secret.
//
// Four details here are load-bearing and each one fails in a way that looks like
// something else:
//
//  1. The RFC 8707 "resource" parameter goes on BOTH the authorize request and
//     the token exchange. Omitting it reads back as a scope error.
//  2. The loopback listener is bound BEFORE registration, so the redirect URI we
//     register is a port we actually hold.
//  3. Refresh tokens rotate. The new one is persisted on every refresh, or the
//     second refresh fails with an opaque invalid_grant.
//  4. "state" is verified on the callback, not just echoed.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	// mcpURL is the Slashy MCP endpoint and doubles as the RFC 8707 resource
	// indicator. Documented at https://help.slashy.com/features/integrations/mcp
	mcpURL = "https://slashy.ctrlcenter.ai/mcp"
	// mcpOrigin is the base used for well-known discovery.
	mcpOrigin = "https://slashy.ctrlcenter.ai"
	// defaultScope is what the protected-resource metadata advertises.
	defaultScope = "slashy.full_access"

	// expirySkew treats a token as stale slightly early so a call in flight does
	// not land on the far side of the expiry.
	expirySkew = 90 * time.Second
	// loginTimeout bounds the wait on the browser round trip.
	loginTimeout = 5 * time.Minute
)

// protectedResourceMeta is RFC 9728.
type protectedResourceMeta struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

// authServerMeta is RFC 8414.
type authServerMeta struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	RegistrationEndpoint          string   `json:"registration_endpoint"`
	RevocationEndpoint            string   `json:"revocation_endpoint"`
	GrantTypesSupported           []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	ScopesSupported               []string `json:"scopes_supported"`
}

// credentials is the on-disk token store, mode 0600.
type credentials struct {
	Issuer       string    `json:"issuer"`
	Resource     string    `json:"resource"`
	ClientID     string    `json:"client_id"`
	RedirectURI  string    `json:"redirect_uri"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type"`
	Scope        string    `json:"scope,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	Account      string    `json:"account,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (c *credentials) expired() bool {
	if c.ExpiresAt.IsZero() {
		return false // no expiry advertised; rely on a 401 to trigger refresh
	}
	return time.Now().Add(expirySkew).After(c.ExpiresAt)
}

// ---------- store ----------

// configDir honours XDG_CONFIG_HOME, else ~/.config/gsl.
func configDir() (string, error) {
	if d := os.Getenv("GSL_CONFIG_DIR"); d != "" {
		return d, nil
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("locate home directory: %w", err)
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "gsl"), nil
}

func credsPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "credentials.json"), nil
}

// storeMu guards the read-modify-write of the credentials file so two
// concurrent gsl processes refreshing at once cannot truncate each other.
var storeMu sync.Mutex

func loadCreds() (*credentials, error) {
	p, err := credsPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errNotLoggedIn
		}
		return nil, fmt.Errorf("read %s: %w", p, err)
	}
	var c credentials
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s (corrupt store, run `gsl login` to rebuild): %w", p, err)
	}
	if c.AccessToken == "" {
		return nil, errNotLoggedIn
	}
	return &c, nil
}

// saveCreds writes atomically at 0600 so a crash mid-write cannot leave a
// half-written token file behind.
func saveCreds(c *credentials) error {
	p, err := credsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	c.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("write token store: %w", err)
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("commit token store: %w", err)
	}
	return nil
}

func deleteCreds() error {
	p, err := credsPath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ---------- discovery ----------

func discover(ctx context.Context) (*authServerMeta, string, error) {
	resource := mcpURL
	issuer := mcpOrigin

	// RFC 9728. Both the bare and path-suffixed forms are served; the bare one
	// is what the WWW-Authenticate challenge points at.
	var prm protectedResourceMeta
	if err := getJSON(ctx, mcpOrigin+"/.well-known/oauth-protected-resource", &prm); err == nil {
		if prm.Resource != "" {
			resource = prm.Resource
		}
		if len(prm.AuthorizationServers) > 0 && prm.AuthorizationServers[0] != "" {
			issuer = strings.TrimRight(prm.AuthorizationServers[0], "/")
		}
	}

	var asm authServerMeta
	if err := getJSON(ctx, issuer+"/.well-known/oauth-authorization-server", &asm); err != nil {
		return nil, "", fmt.Errorf("discover authorization server at %s: %w", issuer, err)
	}
	if asm.AuthorizationEndpoint == "" || asm.TokenEndpoint == "" {
		return nil, "", fmt.Errorf("authorization server metadata at %s is missing authorization_endpoint or token_endpoint", issuer)
	}
	if asm.Issuer == "" {
		asm.Issuer = issuer
	}
	return &asm, resource, nil
}

// ---------- login ----------

// login runs the full browser flow. redirectHost is normally "127.0.0.1"; some
// vendors' WAFs reject that literal and accept only "localhost" (Reclaim does
// this, per the grc CLI), so it is switchable rather than hardcoded.
func login(ctx context.Context, openBrowser bool, redirectHost string) (*credentials, error) {
	asm, resource, err := discover(ctx)
	if err != nil {
		return nil, err
	}
	if redirectHost == "" {
		redirectHost = "127.0.0.1"
	}

	ln, redirectURI, err := bindLoopback(redirectHost)
	if err != nil {
		return nil, err
	}
	defer ln.Close()

	clientID, err := registerClient(ctx, asm.RegistrationEndpoint, redirectURI)
	if err != nil {
		return nil, err
	}

	verifier, challenge, err := pkcePair()
	if err != nil {
		return nil, err
	}
	state, err := randB64(24)
	if err != nil {
		return nil, err
	}

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scopeOrDefault(asm.ScopesSupported))
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("resource", resource) // RFC 8707, required by MCP auth spec
	authorizeURL := asm.AuthorizationEndpoint + "?" + q.Encode()

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	srv := &http.Server{Handler: callbackHandler(state, codeCh, errCh)}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	fmt.Fprintln(os.Stderr, "Opening your browser to sign in to Slashy.")
	fmt.Fprintln(os.Stderr, "If it does not open, paste this URL:")
	fmt.Fprintln(os.Stderr, "\n  "+authorizeURL+"\n")
	if openBrowser {
		if err := browse(authorizeURL); err != nil {
			fmt.Fprintf(os.Stderr, "(could not launch a browser automatically: %v)\n", err)
		}
	}

	var code string
	select {
	case code = <-codeCh:
	case err := <-errCh:
		return nil, err
	case <-time.After(loginTimeout):
		return nil, fmt.Errorf("timed out after %s waiting for the browser redirect", loginTimeout)
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)
	form.Set("code_verifier", verifier)
	form.Set("resource", resource) // RFC 8707 again, on the exchange

	tok, err := postToken(ctx, asm.TokenEndpoint, form)
	if err != nil {
		return nil, err
	}

	c := &credentials{
		Issuer:      asm.Issuer,
		Resource:    resource,
		ClientID:    clientID,
		RedirectURI: redirectURI,
	}
	applyToken(c, tok)
	if err := saveCreds(c); err != nil {
		return nil, err
	}
	return c, nil
}

// bindLoopback opens the callback listener and returns it with the matching
// redirect URI. Two things are deliberate and both are load-bearing:
//
// The listener is bound BEFORE client registration, so the redirect URI we
// register is a port we actually hold. Registering a port that turns out to be
// taken produces a login that dies at the redirect with no useful error.
//
// It binds the SAME host that goes into the URI. Binding 127.0.0.1 while
// redirecting to "localhost" fails on macOS, where localhost resolves to ::1
// first, so the browser would land on a port nothing is listening on. That
// matters because "localhost" is the documented workaround for servers whose
// WAF rejects the 127.0.0.1 literal.
func bindLoopback(redirectHost string) (net.Listener, string, error) {
	if redirectHost == "" {
		redirectHost = "127.0.0.1"
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(redirectHost, "0"))
	if err != nil {
		return nil, "", fmt.Errorf("bind %s for the OAuth redirect: %w", redirectHost, err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	return ln, fmt.Sprintf("http://%s:%d/callback", redirectHost, port), nil
}

func callbackHandler(wantState string, codeCh chan<- string, errCh chan<- error) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			msg := e
			if d := q.Get("error_description"); d != "" {
				msg += ": " + d
			}
			writePage(w, "Sign-in failed", msg)
			errCh <- fmt.Errorf("authorization server returned %s", msg)
			return
		}
		// Verify state rather than merely accepting it back.
		if got := q.Get("state"); got != wantState {
			writePage(w, "Sign-in failed", "State mismatch. Start the login again.")
			errCh <- fmt.Errorf("state mismatch on OAuth callback (possible CSRF or a stale browser tab); run `gsl login` again")
			return
		}
		code := q.Get("code")
		if code == "" {
			writePage(w, "Sign-in failed", "No authorization code in the redirect.")
			errCh <- fmt.Errorf("no authorization code in the OAuth redirect")
			return
		}
		writePage(w, "Signed in to Slashy", "You can close this tab and return to the terminal.")
		codeCh <- code
	})
	return mux
}

func writePage(w http.ResponseWriter, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>%s</title>
<style>body{font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
max-width:34rem;margin:18vh auto;padding:0 1.5rem;color:#111}
h1{font-size:1.35rem;margin:0 0 .5rem}p{color:#555;margin:0}
@media(prefers-color-scheme:dark){body{background:#111;color:#eee}p{color:#aaa}}</style>
<h1>%s</h1><p>%s</p>`, title, title, body)
}

// registerClient performs RFC 7591 dynamic client registration. Slashy accepts
// this unauthenticated and returns a public client (no secret), which is exactly
// the shape a CLI needs.
func registerClient(ctx context.Context, endpoint, redirectURI string) (string, error) {
	if endpoint == "" {
		return "", fmt.Errorf("authorization server advertises no registration_endpoint, so gsl cannot self-register a client")
	}
	body := map[string]any{
		"client_name":                userAgent,
		"redirect_uris":              []string{redirectURI},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"scope":                      defaultScope,
	}
	var out struct {
		ClientID string `json:"client_id"`
		Error    string `json:"error"`
		ErrDesc  string `json:"error_description"`
	}
	if err := postJSON(ctx, endpoint, body, &out); err != nil {
		return "", fmt.Errorf("register OAuth client: %w", err)
	}
	if out.ClientID == "" {
		if out.Error != "" {
			return "", fmt.Errorf("register OAuth client: %s %s", out.Error, out.ErrDesc)
		}
		return "", fmt.Errorf("register OAuth client: no client_id in response")
	}
	return out.ClientID, nil
}

// ---------- refresh ----------

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	Error        string `json:"error"`
	ErrDesc      string `json:"error_description"`
}

func applyToken(c *credentials, t *tokenResponse) {
	c.AccessToken = t.AccessToken
	// Rotation: OAuth 2.1 servers commonly issue a new refresh token on every
	// use. Persist it. Keep the old one only when the response omits it.
	if t.RefreshToken != "" {
		c.RefreshToken = t.RefreshToken
	}
	if t.TokenType != "" {
		c.TokenType = t.TokenType
	} else if c.TokenType == "" {
		c.TokenType = "Bearer"
	}
	if t.Scope != "" {
		c.Scope = t.Scope
	}
	if t.ExpiresIn > 0 {
		c.ExpiresAt = time.Now().Add(time.Duration(t.ExpiresIn) * time.Second).UTC()
	} else {
		c.ExpiresAt = time.Time{}
	}
}

// refresh exchanges the refresh token and persists the rotated result.
func refresh(ctx context.Context, c *credentials) error {
	if c.RefreshToken == "" {
		return errNeedsLogin{reason: "no refresh token stored"}
	}
	asm, resource, err := discover(ctx)
	if err != nil {
		return err
	}
	if resource != "" {
		c.Resource = resource
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", c.RefreshToken)
	form.Set("client_id", c.ClientID)
	if c.Resource != "" {
		form.Set("resource", c.Resource)
	}
	tok, err := postToken(ctx, asm.TokenEndpoint, form)
	if err != nil {
		return errNeedsLogin{reason: err.Error()}
	}
	applyToken(c, tok)

	storeMu.Lock()
	defer storeMu.Unlock()
	return saveCreds(c)
}

func postToken(ctx context.Context, endpoint string, form url.Values) (*tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token endpoint unreachable: %w", err)
	}
	defer res.Body.Close()
	var t tokenResponse
	if err := json.NewDecoder(res.Body).Decode(&t); err != nil {
		return nil, fmt.Errorf("token endpoint returned HTTP %d with an unparseable body: %w", res.StatusCode, err)
	}
	if t.Error != "" {
		return nil, fmt.Errorf("token exchange rejected: %s %s", t.Error, t.ErrDesc)
	}
	if res.StatusCode >= 400 {
		return nil, fmt.Errorf("token endpoint returned HTTP %d", res.StatusCode)
	}
	if t.AccessToken == "" {
		return nil, fmt.Errorf("token endpoint returned no access_token")
	}
	return &t, nil
}

func revoke(ctx context.Context, c *credentials) error {
	asm, _, err := discover(ctx)
	if err != nil || asm.RevocationEndpoint == "" {
		return nil // best effort; the local delete is what matters
	}
	tok := c.RefreshToken
	hint := "refresh_token"
	if tok == "" {
		tok, hint = c.AccessToken, "access_token"
	}
	form := url.Values{}
	form.Set("token", tok)
	form.Set("token_type_hint", hint)
	form.Set("client_id", c.ClientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, asm.RevocationEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)
	res, err := httpClient.Do(req)
	if err == nil {
		res.Body.Close()
	}
	return nil
}

// ---------- helpers ----------

func pkcePair() (verifier, challenge string, err error) {
	verifier, err = randB64(48)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func randB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func scopeOrDefault(supported []string) string {
	if len(supported) > 0 {
		return strings.Join(supported, " ")
	}
	return defaultScope
}

func browse(u string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	return cmd.Start()
}
