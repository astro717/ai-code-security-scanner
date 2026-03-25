package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/http"
	"os"
)

// Safe: parameterised query
func safeQuery(db *sql.DB, userID string) {
	db.Query("SELECT * FROM users WHERE id = $1", userID)
}

// Safe: secret from env var
var apiKey = os.Getenv("API_KEY")

// Safe: crypto/rand
func secureToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// Safe: SHA-256
func strongHash(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// Safe: static redirect
func safeRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/dashboard", 302)
}

func main() {}
