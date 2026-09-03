package main

// NASC - the service a 3DS asks "where is this game's server, and what is my
// token?". Nintendo's is gone; Pretendo runs a replacement that has no entry
// for Final Fantasy Explorers, which is why the console reports 002-0110.
//
// This implementation answers for FF Explorers only (game server 0x0010E200)
// and forwards every other title upstream to Pretendo, so the rest of the
// console's online games keep working exactly as before.

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// FF Explorers' game server ID, recovered from the retail executable.
	FFEGameServerID = "0010E200"
	UpstreamNASC    = "https://nasc.pretendo.cc/ac"
)

// Nintendo's base64 variant: '+' -> '.', '/' -> '-', '=' -> '*'
var (
	ninEncoder = strings.NewReplacer("+", ".", "/", "-", "=", "*")
	ninDecoder = strings.NewReplacer(".", "+", "-", "/", "*", "=")
)

func ninB64Encode(b []byte) string {
	return ninEncoder.Replace(base64.StdEncoding.EncodeToString(b))
}

func ninB64DecodeString(s string) string {
	b, err := base64.StdEncoding.DecodeString(ninDecoder.Replace(s))
	if err != nil {
		return ""
	}
	return string(b)
}

func nascDateTime() string { return time.Now().Format("20060102150405") }

// issuedTokens lets the NEX server recognise consoles we have vouched for.
var (
	tokenMu      sync.Mutex
	issuedTokens = map[string]string{} // sha256(token) -> pid
)

func nascError(code string) url.Values {
	v := url.Values{}
	v.Set("retry", ninB64Encode([]byte("1")))
	if code == "null" {
		v.Set("returncd", code)
	} else {
		v.Set("returncd", ninB64Encode([]byte(code)))
	}
	v.Set("datetime", ninB64Encode([]byte(nascDateTime())))
	return v
}

func startNASCServer(wg *sync.WaitGroup) {
	defer wg.Done()

	mux := http.NewServeMux()
	mux.HandleFunc("/ac", handleAC)
	mux.HandleFunc("/ac/", handleAC)
	mux.HandleFunc("/register", handleRegister) // patcher posts pid+password here
	mux.HandleFunc("/stats", handleStats)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/dashboard" {
			handleDashboard(w, r)
			return
		}
		logf("NASC   unexpected path %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		http.NotFound(w, r)
	})

	addr := env("FFE_NASC_ADDR", ":443")
	cert := env("FFE_TLS_CERT", "certs/nasc.crt")
	key := env("FFE_TLS_KEY", "certs/nasc.key")

	// The 3DS accepts our self-signed cert (Nimbus disables verification) and sends
	// NO SNI. Browsers send SNI and demand a real cert - so serve the Let's Encrypt
	// cert to anything with SNI, and the self-signed cert to the SNI-less 3DS. This
	// keeps the proven 3DS NASC path untouched while giving the dashboard real HTTPS.
	selfSigned, sErr := tls.LoadX509KeyPair(cert, key)
	if sErr != nil {
		logf("NASC   fatal: self-signed cert: %v", sErr)
		os.Exit(1)
	}
	leCertPath := env("FFE_LE_CERT", "/etc/letsencrypt/live/ffe.freakybigfoot.com/fullchain.pem")
	leKeyPath := env("FFE_LE_KEY", "/etc/letsencrypt/live/ffe.freakybigfoot.com/privkey.pem")

	logf("NASC   listening on %s (TLS %s) - serving game server %s, proxying the rest to Pretendo",
		addr, cert, FFEGameServerID)

	// The 3DS speaks TLS 1.0/1.1 with old RSA and CBC cipher suites. Modern Go
	// rejects all of that by default, so we have to opt back in deliberately.
	// (The GODEBUG settings in the Dockerfile re-enable RSA key exchange and 3DES.)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			// Log exactly what the console offers, so we stop guessing at
			// which ancient TLS dialect it wants.
			GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
				logf("TLS    ClientHello from %s: versions=%v suites=%v sni=%q",
					hi.Conn.RemoteAddr(), versionNames(hi.SupportedVersions),
					suiteNames(hi.CipherSuites), hi.ServerName)
				return nil, nil
			},
			GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if hi.ServerName != "" { // browsers send SNI; the 3DS does not
					if c, err := tls.LoadX509KeyPair(leCertPath, leKeyPath); err == nil {
						return &c, nil
					}
				}
				return &selfSigned, nil
			},
			MinVersion: tls.VersionTLS10,
			MaxVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		},
	}
	// Certs come from GetCertificate (SNI-based), so pass empty paths here.
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		logf("NASC   fatal: %v", err)
		os.Exit(1)
	}
}

func handleAC(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		logf("NASC   could not read request: %v", err)
		writeValues(w, nascError("null"))
		return
	}

	params, err := url.ParseQuery(string(body))
	if err != nil {
		logf("NASC   malformed body: %v", err)
		writeValues(w, nascError("null"))
		return
	}

	action := ninB64DecodeString(params.Get("action"))
	gameID := ninB64DecodeString(params.Get("gameid"))
	titleID := ninB64DecodeString(params.Get("titleid"))
	gameCode := ninB64DecodeString(params.Get("gamecd"))
	userID := ninB64DecodeString(params.Get("userid"))

	logf("NASC   %s from %s: action=%s gameid=%s titleid=%s gamecd=%s userid=%s",
		r.Method, clientIP(r), action, gameID, titleID, gameCode, userID)

	game := gameByID(gameID)
	if game == nil {
		proxyUpstream(w, r, body, gameID, titleID)
		return
	}

	switch action {
	case "LOGIN":
		// Match a real NASC response EXACTLY: fields in wire order (locator
		// first), and RAW nintendo-base64 values. Go's url.Values.Encode()
		// sorts alphabetically AND url-escapes the '*' padding char to %2A,
		// which corrupts the base64 the 3DS decodes.
		writeRawOrdered(w, []string{"locator", "retry", "returncd", "token", "datetime"}, gameLogin(game, userID))
	case "SVCLOC":
		// Service tokens are for the Square Enix backend. We have never seen
		// the game reach it, so log loudly and refuse rather than guess.
		logf("NASC   %s requested a SERVICE TOKEN (SVCLOC); params: %s", game.Name, summarise(params))
		writeValues(w, nascError("110"))
	default:
		logf("NASC   %s unknown action %q", game.Name, action)
		writeValues(w, nascError("null"))
	}
}

func gameLogin(game *gameServer, userID string) url.Values {
	raw := make([]byte, 112)
	if _, err := rand.Read(raw); err != nil {
		logf("NASC   token generation failed: %v", err)
		return nascError("110")
	}
	token := ninB64Encode(raw)

	sum := sha256.Sum256([]byte(token))
	tokenMu.Lock()
	issuedTokens[hex.EncodeToString(sum[:])] = userID
	tokenMu.Unlock()

	locator := fmt.Sprintf("%s:%d", env("FFE_PUBLIC_HOST", "10.0.0.95"), game.AuthPort)

	logf("NASC   ISSUED %s token to pid=%s -> %s", game.Name, userID, locator)

	v := url.Values{}
	v.Set("locator", ninB64Encode([]byte(locator)))
	v.Set("retry", ninB64Encode([]byte("0")))
	v.Set("returncd", ninB64Encode([]byte("001")))
	v.Set("token", token)
	v.Set("datetime", ninB64Encode([]byte(nascDateTime())))
	logf("NASC   FFE-RESP: %q", v.Encode())
	return v
}

// proxyUpstream keeps every other Pretendo game working. We are only
// intercepting DNS for this hostname, so we must be a faithful relay.
func proxyUpstream(w http.ResponseWriter, r *http.Request, body []byte, gameID, titleID string) {
	req, err := http.NewRequest(http.MethodPost, UpstreamNASC, strings.NewReader(string(body)))
	if err != nil {
		logf("NASC   proxy build failed: %v", err)
		writeValues(w, nascError("null"))
		return
	}
	for k, vs := range r.Header {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	resp, err := upstreamClient.Do(req)
	if err != nil {
		logf("NASC   proxy to Pretendo failed (gameid=%s): %v", gameID, err)
		writeValues(w, nascError("null"))
		return
	}
	defer resp.Body.Close()

	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	logf("NASC   proxied gameid=%s titleid=%s upstream -> %d, %d bytes", gameID, titleID, resp.StatusCode, len(out))
	logf("NASC   PRETENDO-RESP gameid=%s: %q", gameID, string(out))

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(out)
}

func writeValues(w http.ResponseWriter, v url.Values) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, v.Encode())
}

// writeRawOrdered writes key=value pairs in the given order with the values
// left RAW (already nintendo-base64), matching a real NASC response byte-for-byte.
// Go's url.Values.Encode() would sort keys and url-escape '*' -> %2A, which the
// 3DS's NASC parser does not expect.
func writeRawOrdered(w http.ResponseWriter, order []string, v url.Values) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	var b strings.Builder
	for i, k := range order {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v.Get(k))
	}
	resp := b.String()
	logf("NASC   FFE-RESP-RAW: %s", resp)
	io.WriteString(w, resp)
}

func clientIP(r *http.Request) string {
	if i := strings.LastIndex(r.RemoteAddr, ":"); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}

func summarise(params url.Values) string {
	var b strings.Builder
	for _, k := range []string{"action", "gameid", "titleid", "gamecd", "userid", "keyhash", "svc"} {
		if v := params.Get(k); v != "" {
			fmt.Fprintf(&b, "%s=%s ", k, ninB64DecodeString(v))
		}
	}
	return strings.TrimSpace(b.String())
}


func versionNames(vs []uint16) []string {
	names := make([]string, 0, len(vs))
	for _, v := range vs {
		switch v {
		case tls.VersionTLS10:
			names = append(names, "TLS1.0")
		case tls.VersionTLS11:
			names = append(names, "TLS1.1")
		case tls.VersionTLS12:
			names = append(names, "TLS1.2")
		case tls.VersionTLS13:
			names = append(names, "TLS1.3")
		default:
			names = append(names, fmt.Sprintf("0x%04x", v))
		}
	}
	return names
}

func suiteNames(cs []uint16) []string {
	names := make([]string, 0, len(cs))
	for _, c := range cs {
		if n := tls.CipherSuiteName(c); n != "" {
			names = append(names, n)
		} else {
			names = append(names, fmt.Sprintf("0x%04x", c))
		}
	}
	return names
}


// The container resolves DNS through the LAN resolver, which is exactly where
// we installed the nasc.pretendo.cc override - so a naive upstream request
// loops straight back into this process. Resolve upstream names with public
// DNS instead, so relayed traffic reaches the real Pretendo.
var upstreamResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, network, env("FFE_UPSTREAM_DNS", "1.1.1.1:53"))
	},
}

var upstreamClient = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := upstreamResolver.LookupHost(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("upstream resolve %s: %w", host, err)
			}
			var lastErr error
			for _, ip := range ips {
				if ip == env("FFE_PUBLIC_HOST", "10.0.0.95") {
					continue // never dial ourselves
				}
				d := net.Dialer{Timeout: 8 * time.Second}
				conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip, port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			if lastErr == nil {
				lastErr = fmt.Errorf("no usable address for %s", host)
			}
			return nil, lastErr
		},
	},
}
