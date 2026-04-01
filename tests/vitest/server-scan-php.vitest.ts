/**
 * Integration tests for PHP file scanning via POST /scan.
 *
 * Verifies that submitting PHP code with filename ending in .php is correctly
 * routed through the PHP scanner (php-parser.ts) and returns PHP-specific
 * findings.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import request from 'supertest';
import { app } from '../../src/server';

// ── Vulnerable PHP fixture ───────────────────────────────────────────────────
const VULNERABLE_PHP = `<?php
// SQL injection via concatenation
$result = mysqli_query($conn, "SELECT * FROM users WHERE id=" . $_GET['id']);

// XSS via direct echo
echo $_GET['name'];

// Command injection via shell_exec
shell_exec("ls " . $_GET['dir']);

// Path traversal via file_get_contents
$data = file_get_contents($_GET['file']);

// Eval injection
eval($_POST['code']);

// Hardcoded secret
$password = "s3cretP@ss123!";

// Insecure random
$token = rand(100000, 999999);

// Weak crypto
$hash = md5($password);
`;

// Clean PHP code — no findings expected
const CLEAN_PHP = `<?php
// Safe SQL via prepared statement
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);

// Safe output with escaping
echo htmlspecialchars($name, ENT_QUOTES, 'UTF-8');

// Safe random
$token = random_int(100000, 999999);

// Safe password hashing
$hash = password_hash($password, PASSWORD_BCRYPT);

// Static shell command
shell_exec("ls -la /tmp");
`;

// ── Tests ────────────────────────────────────────────────────────────────────

describe('/scan with PHP files', () => {
  test('vulnerable PHP code returns findings with filename ending in .php', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_PHP,
      filename: 'vulnerable.php',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string }> };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBeGreaterThan(0);

    const types = new Set(body.findings.map((f) => f.type));

    expect(types.has('SQL_INJECTION')).toBe(true);
    expect(types.has('XSS')).toBe(true);
    expect(types.has('COMMAND_INJECTION')).toBe(true);
    expect(types.has('SECRET_HARDCODED')).toBe(true);
    expect(types.has('INSECURE_RANDOM')).toBe(true);
    expect(types.has('WEAK_CRYPTO')).toBe(true);
  });

  test('clean PHP code returns zero findings', async () => {
    const res = await request(app).post('/scan').send({
      code: CLEAN_PHP,
      filename: 'safe.php',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBe(0);
  });

  test('PHP findings include correct file field', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_PHP,
      filename: 'app.php',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ file: string }> };
    expect(body.findings.length).toBeGreaterThan(0);
    for (const f of body.findings) {
      expect(f.file).toBe('app.php');
    }
  });

  test('response includes summary object', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_PHP,
      filename: 'test.php',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: unknown[]; summary: { total: number } };
    expect(typeof body.summary).toBe('object');
    expect(body.summary.total).toBeGreaterThan(0);
  });

  test('PHP eval injection is detected', async () => {
    const evalCode = `<?php\neval($_POST['code']);`;
    const res = await request(app).post('/scan').send({
      code: evalCode,
      filename: 'dynamic.php',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ type: string }> };
    const types = new Set(body.findings.map((f) => f.type));
    expect(types.has('EVAL_INJECTION')).toBe(true);
  });
});

// ── SSTI detection test ──────────────────────────────────────────────────────

const SSTI_PHP = `<?php
$twig->render($twig->createTemplate($_GET['tpl']));
`;

describe('/scan with PHP — SSTI detection', () => {
  test('Twig createTemplate with user input is detected as SSTI', async () => {
    const res = await request(app).post('/scan').send({
      code: SSTI_PHP,
      filename: 'template.php',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string }> };
    expect(Array.isArray(body.findings)).toBe(true);

    const types = new Set(body.findings.map((f) => f.type));
    expect(types.has('SSTI')).toBe(true);
  });
});
