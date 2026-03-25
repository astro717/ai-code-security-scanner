package main

import (
	"crypto/md5"
	"crypto/sha1"
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"os/exec"
	"path/filepath"
	"text/template"
)

// ── SQL Injection ───────────────────────────────────────────────────────────

func unsafeQuery(db *sql.DB, userInput string) {
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", userInput))
}

func unsafeQueryConcat(db *sql.DB, userInput string) {
	db.Exec("DELETE FROM users WHERE id = " + userInput)
}

// ── Command Injection ───────────────────────────────────────────────────────

func unsafeExec(r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	exec.Command("bash", "-c", cmd).Run()
}

func unsafeExecFromRequest(r *http.Request) {
	input := r.FormValue("file")
	exec.Command(input).Run()
}

// ── SSRF ────────────────────────────────────────────────────────────────────

func unsafeFetch(r *http.Request) {
	http.Get(r.URL.Query().Get("url"))
}

func unsafeNewRequest(r *http.Request) {
	http.NewRequest("GET", r.FormValue("target"), nil)
}

// ── Hardcoded Secrets ───────────────────────────────────────────────────────

var apiKey = "sk-live-1234567890abcdef"
var password = "supersecretpassword123"

// ── Weak Crypto ─────────────────────────────────────────────────────────────

func weakHash(data []byte) {
	md5.Sum(data)
	sha1.Sum(data)
}

// ── Path Traversal ──────────────────────────────────────────────────────────

func unsafePath(r *http.Request) {
	filepath.Join("/uploads", r.FormValue("file"))
}

// ── Insecure Random ─────────────────────────────────────────────────────────

func insecureToken() string {
	return fmt.Sprintf("%d", rand.Intn(999999))
}

// ── Template Injection ──────────────────────────────────────────────────────

func unsafeTemplate(r *http.Request) {
	template.New("t").Parse(r.FormValue("body"))
}

// ── Open Redirect ───────────────────────────────────────────────────────────

func unsafeRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.FormValue("next"), 302)
}

func main() {}
