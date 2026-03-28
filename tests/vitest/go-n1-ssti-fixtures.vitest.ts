/**
 * Fixture-based unit tests for the PERFORMANCE_N_PLUS_ONE and SSTI detectors
 * added to go-parser.ts.
 */

import { describe, it, expect } from 'vitest';
import { parseGoCode, scanGo } from '../../src/scanner/go-parser';

function scan(code: string): string[] {
  return scanGo(parseGoCode(code, 'test.go')).map((f) => f.type);
}

function scanFull(code: string) {
  return scanGo(parseGoCode(code, 'test.go'));
}

// ── PERFORMANCE_N_PLUS_ONE ────────────────────────────────────────────────────

describe('PERFORMANCE_N_PLUS_ONE — Go', () => {
  it('fires on db.Query inside a range loop', () => {
    const code = `for _, id := range ids {
  rows, _ := db.Query("SELECT * FROM orders WHERE user_id = ?", id)
  _ = rows
}`;
    expect(scan(code)).toContain('PERFORMANCE_N_PLUS_ONE');
  });

  it('fires on db.QueryRow inside a range loop', () => {
    const code = `for _, id := range userIDs {
  row := db.QueryRow("SELECT name FROM users WHERE id = ?", id)
  _ = row
}`;
    expect(scan(code)).toContain('PERFORMANCE_N_PLUS_ONE');
  });

  it('fires on gorm.Find inside a range loop', () => {
    const code = `for _, u := range users {
  db.Find(&orders, "user_id = ?", u.ID)
}`;
    expect(scan(code)).toContain('PERFORMANCE_N_PLUS_ONE');
  });

  it('does NOT fire on db.Query outside a loop', () => {
    const code = `rows, err := db.Query("SELECT * FROM users WHERE id IN (?)", ids)`;
    expect(scan(code)).not.toContain('PERFORMANCE_N_PLUS_ONE');
  });

  it('does NOT fire on non-DB code inside a loop', () => {
    const code = `for _, v := range values {
  fmt.Println(v)
}`;
    expect(scan(code)).not.toContain('PERFORMANCE_N_PLUS_ONE');
  });

  it('finding has severity low', () => {
    const code = `for _, id := range ids {
  row := db.QueryRow("SELECT * FROM t WHERE id=?", id)
  _ = row
}`;
    const f = scanFull(code).find((r) => r.type === 'PERFORMANCE_N_PLUS_ONE');
    expect(f?.severity).toBe('low');
  });
});

// ── SSTI ──────────────────────────────────────────────────────────────────────

describe('SSTI — Go', () => {
  it('fires on template.Execute with request input', () => {
    const code = `t.Execute(w, r.URL.Query().Get("name"))`;
    expect(scan(code)).toContain('SSTI');
  });

  it('fires on template.Execute with body variable', () => {
    const code = `tmpl.Execute(w, body)`;
    // This alone may not match the pattern — need more context
    // The pattern checks for r. / request. / input / body
    expect(scan(code)).toContain('SSTI');
  });

  it('fires on template.ExecuteTemplate with param', () => {
    const code = `t.ExecuteTemplate(w, "main", r.FormValue("data"))`;
    expect(scan(code)).toContain('SSTI');
  });

  it('fires on template Parse from request body', () => {
    const code = `template.Must(t.Parse(r.Body))`;
    expect(scan(code)).toContain('SSTI');
  });

  it('does NOT fire on Execute with a static struct', () => {
    const code = `t.Execute(w, PageData{Title: "Home", User: user})`;
    expect(scan(code)).not.toContain('SSTI');
  });

  it('finding has severity critical', () => {
    const code = `t.Execute(w, request.input)`;
    const f = scanFull(code).find((r) => r.type === 'SSTI');
    expect(f?.severity).toBe('critical');
  });
});
