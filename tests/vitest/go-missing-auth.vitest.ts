/**
 * Unit tests for Go MISSING_AUTH stateful detector.
 *
 * Covers http.HandleFunc handlers that access request data without an auth guard,
 * and verifies that handlers with auth checks are NOT flagged.
 */

import { describe, test, expect } from 'vitest';
import { parseGoCode, scanGo } from '../../src/scanner/go-parser';

function scan(code: string) {
  return scanGo(parseGoCode(code, 'main.go'));
}

function missingAuthFindings(code: string) {
  return scan(code).filter((f) => f.type === 'MISSING_AUTH');
}

// ── Inline handler func literals ────────────────────────────────────────────

describe('Go MISSING_AUTH — inline handler func literals', () => {
  test('flags http.HandleFunc with inline func reading r.FormValue without auth', () => {
    const code = `
package main

import "net/http"

func main() {
  http.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("name")
    w.Write([]byte(name))
  })
}
`;
    expect(missingAuthFindings(code).length).toBeGreaterThan(0);
  });

  test('flags http.HandleFunc with inline func reading r.Body without auth', () => {
    const code = `
package main

import (
  "io"
  "net/http"
)

func main() {
  http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(r.Body)
    w.Write(body)
  })
}
`;
    expect(missingAuthFindings(code).length).toBeGreaterThan(0);
  });

  test('flags mux.HandleFunc reading r.URL.Query without auth', () => {
    const code = `
package main

import "net/http"

func register(mux *http.ServeMux) {
  mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query().Get("q")
    w.Write([]byte(q))
  })
}
`;
    expect(missingAuthFindings(code).length).toBeGreaterThan(0);
  });
});

// ── Named handler functions ─────────────────────────────────────────────────

describe('Go MISSING_AUTH — named handler functions', () => {
  test('flags named handler accessing r.FormValue without auth guard', () => {
    const code = `
package main

import "net/http"

func handleCreate(w http.ResponseWriter, r *http.Request) {
  title := r.FormValue("title")
  w.Write([]byte(title))
}
`;
    expect(missingAuthFindings(code).length).toBeGreaterThan(0);
  });

  test('flags named handler reading r.Body without auth guard', () => {
    const code = `
package main

import (
  "io"
  "net/http"
)

func updateHandler(w http.ResponseWriter, r *http.Request) {
  data, _ := io.ReadAll(r.Body)
  w.Write(data)
}
`;
    expect(missingAuthFindings(code).length).toBeGreaterThan(0);
  });
});

// ── Authenticated handlers (should NOT be flagged) ──────────────────────────

describe('Go MISSING_AUTH — authenticated handlers (negative cases)', () => {
  test('does not flag named handler that calls verifyToken', () => {
    const code = `
package main

import "net/http"

func secureHandler(w http.ResponseWriter, r *http.Request) {
  if !verifyToken(r) {
    http.Error(w, "Unauthorized", 401)
    return
  }
  name := r.FormValue("name")
  w.Write([]byte(name))
}
`;
    expect(missingAuthFindings(code).length).toBe(0);
  });

  test('does not flag named handler that calls checkAuth', () => {
    const code = `
package main

import "net/http"

func profileHandler(w http.ResponseWriter, r *http.Request) {
  user := checkAuth(r)
  if user == nil {
    http.Error(w, "Unauthorized", 401)
    return
  }
  data := r.URL.Query().Get("field")
  w.Write([]byte(data))
}
`;
    expect(missingAuthFindings(code).length).toBe(0);
  });

  test('does not flag inline handler with requireAuth call', () => {
    const code = `
package main

import "net/http"

func main() {
  http.HandleFunc("/secure", func(w http.ResponseWriter, r *http.Request) {
    requireAuth(w, r)
    val := r.FormValue("val")
    w.Write([]byte(val))
  })
}
`;
    expect(missingAuthFindings(code).length).toBe(0);
  });

  test('does not flag handler that does not access request data', () => {
    const code = `
package main

import "net/http"

func healthHandler(w http.ResponseWriter, r *http.Request) {
  w.Write([]byte("ok"))
}
`;
    expect(missingAuthFindings(code).length).toBe(0);
  });

  test('does not flag non-handler function reading request-like variable', () => {
    const code = `
package main

func processData(data string) string {
  return data
}
`;
    expect(missingAuthFindings(code).length).toBe(0);
  });
});

// ── Finding properties ──────────────────────────────────────────────────────

describe('Go MISSING_AUTH — finding properties', () => {
  test('finding severity is high', () => {
    const code = `
package main

import "net/http"

func handlePost(w http.ResponseWriter, r *http.Request) {
  val := r.FormValue("val")
  w.Write([]byte(val))
}
`;
    const findings = missingAuthFindings(code);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.severity).toBe('high');
    }
  });

  test('finding includes file reference', () => {
    const result = scanGo(parseGoCode(`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
  val := r.FormValue("x")
  w.Write([]byte(val))
}
`, 'handlers/api.go'));
    const findings = result.filter((f) => f.type === 'MISSING_AUTH');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.file).toBe('handlers/api.go');
  });

  test('finding includes confidence', () => {
    const code = `
package main

import "net/http"

func postHandler(w http.ResponseWriter, r *http.Request) {
  body := r.FormValue("body")
  w.Write([]byte(body))
}
`;
    const findings = missingAuthFindings(code);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.confidence).toBeDefined();
    expect(findings[0]!.confidence).toBeGreaterThan(0);
  });
});
