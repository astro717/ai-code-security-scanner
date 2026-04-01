/**
 * Integration tests for PHP file scanning via POST /scan.
 *
 * Verifies that submitting PHP code with filename ending in .php is correctly
 * routed through the PHP scanner (php-parser.ts) and returns PHP-specific
 * findings (SQL_INJECTION, XSS, COMMAND_INJECTION, etc.).
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import request from 'supertest';
import { app } from '../../src/server';

// ── Vulnerable PHP fixture ──────────────────────────────────────────────────

const VULNERABLE_PHP = `<?php
// SQL injection via string concatenation with superglobal
$result = mysqli_query($conn, "SELECT * FROM users WHERE id=" . $_GET['id']);

// XSS via direct echo of user input
echo $_POST['name'];

// Command injection via shell_exec with user input
$output = shell_exec("ping -c 1 " . $_GET['host']);

// Path traversal via file_get_contents with user input
$data = file_get_contents($_REQUEST['file']);

// Eval injection
eval($_POST['code']);

// Hardcoded secret
$api_key = "sk-proj-abc123xyz456def789ghi012jkl345mno678";

// Weak crypto
$hash = md5($password);

// Open redirect
header("Location: " . $_GET['url']);
?>`;

const CLEAN_PHP = `<?php
class UserService {
    private PDO $db;

    public function __construct(PDO $db) {
        $this->db = $db;
    }

    public function findById(int $id): ?array {
        $stmt = $this->db->prepare("SELECT * FROM users WHERE id = :id");
        $stmt->bindParam(':id', $id, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }

    public function greet(string $name): string {
        return "Hello, " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
    }
}
?>`;

// ── Tests ───────────────────────────────────────────────────────────────────

describe('/scan with PHP files', () => {
  test('vulnerable PHP code returns findings with filename ending in .php', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_PHP,
      filename: 'input.php',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string }> };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBeGreaterThan(0);

    const types = new Set(body.findings.map((f) => f.type));

    // The vulnerable fixture should trigger at least these PHP-detected types
    expect(types.has('SQL_INJECTION')).toBe(true);
    expect(types.has('XSS')).toBe(true);
    expect(types.has('COMMAND_INJECTION')).toBe(true);
    expect(types.has('WEAK_CRYPTO')).toBe(true);
  });

  test('clean PHP code returns zero findings', async () => {
    const res = await request(app).post('/scan').send({
      code: CLEAN_PHP,
      filename: 'safe_service.php',
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
});
