/**
 * Integration tests for Go file scanning via POST /scan.
 *
 * Verifies that submitting Go code with filename ending in .go is correctly
 * routed through the Go scanner (go-parser.ts) and returns Go-specific findings.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import net from 'net';

// ── Vulnerable Go fixture ────────────────────────────────────────────────────
const VULNERABLE_GO = `
package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"os/exec"
)

// SQL injection via string concatenation
func getUser(db *sql.DB, id string) (*sql.Row) {
	return db.QueryRow("SELECT * FROM users WHERE id = " + id)
}

// Command injection via exec.Command with user input
func runCommand(input string) ([]byte, error) {
	return exec.Command("sh", "-c", input).Output()
}

// Weak crypto: MD5
func hashData(data []byte) [16]byte {
	return md5.Sum(data)
}

// Hardcoded secret
var apiKey = "sk-secret-1234567890abcdef"

// Insecure random
func generateToken() int {
	return rand.Int()
}

// Open redirect
func handleRedirect(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	http.Redirect(w, r, url, http.StatusFound)
}

// SSRF via user-controlled URL
func fetchURL(r *http.Request) (*http.Response, error) {
	url := r.FormValue("url")
	return http.Get(url)
}
`;

// Clean Go code — no findings expected
const CLEAN_GO = `
package main

import (
	"crypto/sha256"
	"fmt"
)

type SafeService struct {
	name string
}

func NewSafeService(name string) *SafeService {
	return &SafeService{name: name}
}

func (s *SafeService) GetName() string {
	return s.name
}

func hashData(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func main() {
	svc := NewSafeService("test")
	fmt.Println(svc.GetName())
}
`;

// ── Helpers ─────────────────────────────────────────────────────────────────

function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      srv.close((err) => (err ? reject(err) : resolve(port)));
    });
  });
}

interface ScanResponse {
  statusCode: number;
  body: unknown;
}

function post(port: number, urlPath: string, payload: unknown): Promise<ScanResponse> {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(payload);
    const opts: http.RequestOptions = {
      hostname: '127.0.0.1',
      port,
      path: urlPath,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
      },
    };

    const req = http.request(opts, (res) => {
      let raw = '';
      res.on('data', (chunk) => (raw += chunk));
      res.on('end', () => {
        try {
          resolve({ statusCode: res.statusCode ?? 0, body: JSON.parse(raw) });
        } catch {
          resolve({ statusCode: res.statusCode ?? 0, body: raw });
        }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

// ── Server lifecycle ────────────────────────────────────────────────────────

let serverPort: number;
let serverHandle: http.Server | null = null;

beforeAll(async () => {
  serverPort = await getFreePort();

  delete process.env.SERVER_API_KEY;
  process.env.PORT = String(serverPort);

  const origWarn = console.warn;
  const origLog = console.log;
  console.warn = () => {};
  console.log = () => {};

  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ts-node/register');
  } catch { /* already registered */ }

  Object.keys(require.cache ?? {}).forEach((k) => {
    if (k.includes('/src/server')) delete require.cache[k];
  });

  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const mod = require('../../src/server');
  serverHandle = (mod?.default ?? mod?.server ?? null) as http.Server | null;

  await new Promise((r) => setTimeout(r, 400));

  console.warn = origWarn;
  console.log = origLog;
}, 10_000);

afterAll(() => {
  delete process.env.PORT;
  return new Promise<void>((resolve) => {
    if (serverHandle && typeof serverHandle.close === 'function') {
      serverHandle.close(() => resolve());
    } else {
      resolve();
    }
  });
});

// ── Tests ───────────────────────────────────────────────────────────────────

describe('/scan with Go files', () => {
  test('vulnerable Go code returns findings with filename ending in .go', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_GO,
      filename: 'main.go',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string }> };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBeGreaterThan(0);

    const types = new Set(body.findings.map((f) => f.type));

    expect(types.has('SQL_INJECTION')).toBe(true);
    expect(types.has('COMMAND_INJECTION')).toBe(true);
    expect(types.has('WEAK_CRYPTO')).toBe(true);
    expect(types.has('SECRET_HARDCODED')).toBe(true);
    expect(types.has('INSECURE_RANDOM')).toBe(true);
  });

  test('clean Go code returns zero findings', async () => {
    const res = await post(serverPort, '/scan', {
      code: CLEAN_GO,
      filename: 'safe.go',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBe(0);
  });

  test('Go findings include correct file field', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_GO,
      filename: 'app.go',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ file: string }> };
    expect(body.findings.length).toBeGreaterThan(0);
    for (const f of body.findings) {
      expect(f.file).toBe('app.go');
    }
  });

  test('response includes summary object', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_GO,
      filename: 'test.go',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: unknown[]; summary: { total: number } };
    expect(typeof body.summary).toBe('object');
    expect(body.summary.total).toBeGreaterThan(0);
  });
});
