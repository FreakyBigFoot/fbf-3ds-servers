package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// startHTTPRegister serves /register over PLAIN HTTP. The 3DS's SSL stack refuses
// our self-signed cert (fails with a d8a0/d8a8 SSL error even with verify off), so
// the patcher app posts here over http instead. The NEX password is anonymous and
// this is a self-hosted server, so plain http is an acceptable trade for it.
func startHTTPRegister(wg *sync.WaitGroup) {
	defer wg.Done()
	mux := http.NewServeMux()
	mux.HandleFunc("/register", handleRegister)
	mux.HandleFunc("/stats", handleStats)
	// Let's Encrypt HTTP-01 challenge (certbot --webroot -w /opt/ffe/acme).
	mux.Handle("/.well-known/acme-challenge/", http.FileServer(http.Dir(env("FFE_ACME_WEBROOT", "/opt/ffe/acme"))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/dashboard" {
			handleDashboard(w, r)
			return
		}
		http.NotFound(w, r)
	})
	addr := env("FFE_HTTP_ADDR", ":80")
	logf("HTTP   /register listening on %s (plain http for 3DS homebrew)", addr)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		logf("HTTP   fatal: %v", err)
	}
}

// accountStore maps a console's NEX PID (decimal string) to its NEX password.
// It is seeded from FFE_NEX_ACCOUNTS and from Postgres at startup, updated live
// by /register, and every registration is persisted to Postgres so it survives
// restarts. Reads happen on every LoginEx, so access is guarded by a RWMutex.
type accountStore struct {
	mu sync.RWMutex
	m  map[string]string
}

var accounts = &accountStore{m: map[string]string{}}

func (a *accountStore) get(pid string) (string, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	pw, ok := a.m[pid]
	return pw, ok
}

func (a *accountStore) set(pid, pw string) {
	a.mu.Lock()
	a.m[pid] = pw
	a.mu.Unlock()
}

// allPIDs returns every registered console PID as uint32. Used as the "friend
// list" for matchmaking: friends-only sessions (participation_policy 98, which
// Fantasy Life uses) are only browsable when the owner is in the searcher's
// friend list. The real friend graph lives on Pretendo, not here, so on this
// small community server we treat every registered account as everyone's friend.
func (a *accountStore) allPIDs() []uint32 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]uint32, 0, len(a.m))
	for pid := range a.m {
		if n, err := strconv.ParseUint(pid, 10, 32); err == nil {
			out = append(out, uint32(n))
		}
	}
	return out
}

func (a *accountStore) size() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.m)
}

// seedAccountsFromEnv loads the FFE_NEX_ACCOUNTS "pid:pw,pid:pw" pairs. These are
// the manually-dumped accounts; the Postgres table (loaded afterwards) overrides
// them so a re-registration always wins.
func seedAccountsFromEnv() {
	for _, pair := range strings.Split(os.Getenv("FFE_NEX_ACCOUNTS"), ",") {
		pair = strings.TrimSpace(pair)
		if i := strings.Index(pair, ":"); i > 0 {
			accounts.set(pair[:i], pair[i+1:])
		}
	}
}

// ensureAccountsTable creates the registrations table if it does not exist.
func ensureAccountsTable() {
	if postgres == nil {
		return
	}
	_, err := postgres.Exec(`CREATE TABLE IF NOT EXISTS ffe_accounts (
		pid        TEXT PRIMARY KEY,
		password   TEXT NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`)
	if err != nil {
		logf("ACCOUNTS ensure table failed: %v", err)
	}
}

// loadAccountsFromDB pulls every registered account into the in-memory store.
func loadAccountsFromDB() {
	if postgres == nil {
		return
	}
	rows, err := postgres.Query(`SELECT pid, password FROM ffe_accounts`)
	if err != nil {
		logf("ACCOUNTS load failed: %v", err)
		return
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var pid, pw string
		if err := rows.Scan(&pid, &pw); err == nil {
			accounts.set(pid, pw)
			n++
		}
	}
	logf("ACCOUNTS %d registered account(s) loaded from db (%d total incl. env)", n, accounts.size())
}

// saveAccount upserts one registration. Idempotent: a console re-registering
// (e.g. after its Pretendo NEX password changed) overwrites the stored value.
func saveAccount(pid, pw string) error {
	if postgres == nil {
		return nil // memory-only when no DB is configured
	}
	_, err := postgres.Exec(`INSERT INTO ffe_accounts (pid, password, updated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (pid) DO UPDATE SET password = EXCLUDED.password, updated_at = now()`,
		pid, pw)
	return err
}

// handleRegister accepts a console's NEX PID + password (JSON or form) and stores
// it, so the server can build a decryptable kerberos ticket for that console
// without anyone dumping/pasting passwords by hand. The patcher app posts here.
//
// It is a deliberate upsert: if a player's Pretendo NEX password ever changes,
// re-running the patcher re-posts the current password and overwrites the old
// one. Registering someone else's PID only affects FFE auth for that PID, and
// the real owner fixes it by re-registering; low stakes for a hobby server.
func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var pid, pw string
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			PID      string `json:"pid"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		pid, pw = body.PID, body.Password
	} else {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		pid, pw = r.FormValue("pid"), r.FormValue("password")
	}
	pid = strings.TrimSpace(pid)
	pw = strings.TrimSpace(pw)

	if _, err := strconv.ParseUint(pid, 10, 64); err != nil {
		http.Error(w, "invalid pid", http.StatusBadRequest)
		return
	}
	if len(pw) == 0 || len(pw) > 64 {
		http.Error(w, "invalid password", http.StatusBadRequest)
		return
	}

	if err := saveAccount(pid, pw); err != nil {
		logf("REGISTER save failed pid=%s: %v", pid, err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	accounts.set(pid, pw)
	logf("REGISTER pid=%s registered (%d-char password) from %s", pid, len(pw), clientIP(r))

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}
