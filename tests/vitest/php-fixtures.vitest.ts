/**
 * Fixture-based tests for the PHP scanner (php-parser.ts).
 *
 * Verifies all 13 vulnerability classes with positive and negative test cases.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import { parsePHPCode, scanPHP } from '../../src/scanner/php-parser';

function scan(code: string) {
  return scanPHP(parsePHPCode(code, 'test.php'));
}

function findingsOfType(code: string, type: string) {
  return scan(code).filter((f) => f.type === type);
}

// ── SQL_INJECTION ──────────────────────────────────────────────────────────────

describe('PHP scanner — SQL_INJECTION', () => {
  test('detects mysqli_query with concatenated $_GET', () => {
    const code = `<?php\nmysqli_query($conn, "SELECT * FROM users WHERE id=" . $_GET['id']);`;
    expect(findingsOfType(code, 'SQL_INJECTION').length).toBeGreaterThan(0);
  });

  test('detects string interpolation with $_POST in query', () => {
    // Pattern matches ->query("$var...$_POST...")
    const code = `<?php\n$db->query("$query WHERE name = $_POST[name]");`;
    expect(findingsOfType(code, 'SQL_INJECTION').length).toBeGreaterThan(0);
  });

  test('detects raw SQL SELECT with $_REQUEST concatenation', () => {
    const code = `<?php\n$sql = "SELECT * FROM users WHERE id=" . $_REQUEST['id'];`;
    expect(findingsOfType(code, 'SQL_INJECTION').length).toBeGreaterThan(0);
  });

  test('does not flag prepared statements', () => {
    const code = `<?php\n$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");\n$stmt->execute([$id]);`;
    expect(findingsOfType(code, 'SQL_INJECTION').length).toBe(0);
  });
});

// ── XSS ────────────────────────────────────────────────────────────────────────

describe('PHP scanner — XSS', () => {
  test('detects echo $_GET directly', () => {
    const code = `<?php\necho $_GET['name'];`;
    expect(findingsOfType(code, 'XSS').length).toBeGreaterThan(0);
  });

  test('detects print with $_POST in expression', () => {
    const code = `<?php\nprint "Hello " . $_POST['user'];`;
    expect(findingsOfType(code, 'XSS').length).toBeGreaterThan(0);
  });

  test('does not flag echo with htmlspecialchars', () => {
    const code = `<?php\necho htmlspecialchars($name, ENT_QUOTES, 'UTF-8');`;
    expect(findingsOfType(code, 'XSS').length).toBe(0);
  });
});

// ── COMMAND_INJECTION ──────────────────────────────────────────────────────────

describe('PHP scanner — COMMAND_INJECTION', () => {
  test('detects shell_exec with $_GET', () => {
    const code = `<?php\nshell_exec("ls " . $_GET['dir']);`;
    expect(findingsOfType(code, 'COMMAND_INJECTION').length).toBeGreaterThan(0);
  });

  test('detects backtick execution with $_REQUEST', () => {
    const code = '<?php\n$out = `cat $_REQUEST[file]`;';
    expect(findingsOfType(code, 'COMMAND_INJECTION').length).toBeGreaterThan(0);
  });

  test('does not flag shell_exec with static string', () => {
    const code = `<?php\nshell_exec("ls -la /tmp");`;
    expect(findingsOfType(code, 'COMMAND_INJECTION').length).toBe(0);
  });
});

// ── PATH_TRAVERSAL ─────────────────────────────────────────────────────────────

describe('PHP scanner — PATH_TRAVERSAL', () => {
  test('detects file_get_contents with $_GET', () => {
    const code = `<?php\n$data = file_get_contents($_GET['file']);`;
    expect(findingsOfType(code, 'PATH_TRAVERSAL').length).toBeGreaterThan(0);
  });

  test('detects include with $_REQUEST', () => {
    const code = `<?php\ninclude($_REQUEST['page']);`;
    expect(findingsOfType(code, 'PATH_TRAVERSAL').length).toBeGreaterThan(0);
  });

  test('does not flag file_get_contents with static path', () => {
    const code = `<?php\n$data = file_get_contents('/etc/config.json');`;
    expect(findingsOfType(code, 'PATH_TRAVERSAL').length).toBe(0);
  });
});

// ── EVAL_INJECTION ─────────────────────────────────────────────────────────────

describe('PHP scanner — EVAL_INJECTION', () => {
  test('detects eval with $_POST', () => {
    const code = `<?php\neval($_POST['code']);`;
    expect(findingsOfType(code, 'EVAL_INJECTION').length).toBeGreaterThan(0);
  });

  test('detects preg_replace with /e modifier', () => {
    const code = `<?php\npreg_replace('/pattern/e', 'replacement', $str);`;
    expect(findingsOfType(code, 'EVAL_INJECTION').length).toBeGreaterThan(0);
  });

  test('does not flag preg_replace without /e modifier', () => {
    const code = `<?php\npreg_replace('/pattern/', 'replacement', $str);`;
    expect(findingsOfType(code, 'EVAL_INJECTION').length).toBe(0);
  });
});

// ── SECRET_HARDCODED ───────────────────────────────────────────────────────────

describe('PHP scanner — SECRET_HARDCODED', () => {
  test('detects hardcoded password variable', () => {
    const code = `<?php\n$password = "s3cretP@ss123";`;
    expect(findingsOfType(code, 'SECRET_HARDCODED').length).toBeGreaterThan(0);
  });

  test('detects hardcoded api_key', () => {
    const code = `<?php\n$api_key = "abcd1234efgh5678";`;
    expect(findingsOfType(code, 'SECRET_HARDCODED').length).toBeGreaterThan(0);
  });

  test('does not flag short values (likely constants)', () => {
    const code = `<?php\n$password = "ab";`;
    expect(findingsOfType(code, 'SECRET_HARDCODED').length).toBe(0);
  });
});

// ── SSRF ───────────────────────────────────────────────────────────────────────

describe('PHP scanner — SSRF', () => {
  test('detects file_get_contents with $_GET URL', () => {
    const code = `<?php\n$data = file_get_contents($_GET['url']);`;
    // This may also trigger PATH_TRAVERSAL; we only care about SSRF here
    expect(findingsOfType(code, 'SSRF').length).toBeGreaterThan(0);
  });

  test('detects curl_setopt CURLOPT_URL with $_POST', () => {
    const code = `<?php\ncurl_setopt($ch, CURLOPT_URL, $_POST['target']);`;
    expect(findingsOfType(code, 'SSRF').length).toBeGreaterThan(0);
  });

  test('does not flag curl with static URL', () => {
    const code = `<?php\ncurl_setopt($ch, CURLOPT_URL, "https://api.example.com/data");`;
    expect(findingsOfType(code, 'SSRF').length).toBe(0);
  });
});

// ── OPEN_REDIRECT ──────────────────────────────────────────────────────────────

describe('PHP scanner — OPEN_REDIRECT', () => {
  test('detects header Location with $_GET', () => {
    // Pattern expects $_GET inside the header string argument
    const code = `<?php\nheader("Location: $_GET[url]");`;
    expect(findingsOfType(code, 'OPEN_REDIRECT').length).toBeGreaterThan(0);
  });

  test('does not flag static redirect', () => {
    const code = `<?php\nheader("Location: /dashboard");`;
    expect(findingsOfType(code, 'OPEN_REDIRECT').length).toBe(0);
  });
});

// ── UNSAFE_DESERIALIZATION ─────────────────────────────────────────────────────

describe('PHP scanner — UNSAFE_DESERIALIZATION', () => {
  test('detects unserialize with $_COOKIE', () => {
    const code = `<?php\n$obj = unserialize($_COOKIE['data']);`;
    expect(findingsOfType(code, 'UNSAFE_DESERIALIZATION').length).toBeGreaterThan(0);
  });

  test('does not flag json_decode', () => {
    const code = `<?php\n$data = json_decode($_POST['json'], true);`;
    expect(findingsOfType(code, 'UNSAFE_DESERIALIZATION').length).toBe(0);
  });
});

// ── INSECURE_RANDOM ────────────────────────────────────────────────────────────

describe('PHP scanner — INSECURE_RANDOM', () => {
  test('detects rand()', () => {
    const code = `<?php\n$token = rand(100000, 999999);`;
    expect(findingsOfType(code, 'INSECURE_RANDOM').length).toBeGreaterThan(0);
  });

  test('detects mt_rand()', () => {
    const code = `<?php\n$code = mt_rand();`;
    expect(findingsOfType(code, 'INSECURE_RANDOM').length).toBeGreaterThan(0);
  });

  test('does not flag random_int()', () => {
    const code = `<?php\n$token = random_int(100000, 999999);`;
    expect(findingsOfType(code, 'INSECURE_RANDOM').length).toBe(0);
  });
});

// ── WEAK_CRYPTO ────────────────────────────────────────────────────────────────

describe('PHP scanner — WEAK_CRYPTO', () => {
  test('detects md5() on variable', () => {
    const code = `<?php\n$hash = md5($password);`;
    expect(findingsOfType(code, 'WEAK_CRYPTO').length).toBeGreaterThan(0);
  });

  test('detects sha1() on variable', () => {
    const code = `<?php\n$hash = sha1($data);`;
    expect(findingsOfType(code, 'WEAK_CRYPTO').length).toBeGreaterThan(0);
  });

  test('does not flag password_hash()', () => {
    const code = `<?php\n$hash = password_hash($password, PASSWORD_BCRYPT);`;
    expect(findingsOfType(code, 'WEAK_CRYPTO').length).toBe(0);
  });
});

// ── XML_INJECTION ──────────────────────────────────────────────────────────────

describe('PHP scanner — XML_INJECTION', () => {
  test('detects simplexml_load_string', () => {
    const code = `<?php\n$xml = simplexml_load_string($data);`;
    expect(findingsOfType(code, 'XML_INJECTION').length).toBeGreaterThan(0);
  });

  test('does not flag json_decode', () => {
    const code = `<?php\n$data = json_decode($input);`;
    expect(findingsOfType(code, 'XML_INJECTION').length).toBe(0);
  });
});

// ── SSTI ───────────────────────────────────────────────────────────────────────

describe('PHP scanner — SSTI', () => {
  test('detects Twig createTemplate with $_GET', () => {
    const code = `<?php\n$twig->render($twig->createTemplate($_GET['tpl']));`;
    expect(findingsOfType(code, 'SSTI').length).toBeGreaterThan(0);
  });

  test('does not flag render with static template name', () => {
    const code = `<?php\n$twig->render('index.html', ['name' => $name]);`;
    expect(findingsOfType(code, 'SSTI').length).toBe(0);
  });
});

// ── MISSING_AUTH ─────────────────────────────────────────────────────────────

describe('PHP scanner — MISSING_AUTH', () => {
  test('detects function accessing $_POST without session_start or auth guard', () => {
    const code = `<?php
function handleUpdate() {
  $id = $_POST['id'];
  $name = $_POST['name'];
  $db->query("UPDATE users SET name='$name' WHERE id=$id");
}
`;
    expect(findingsOfType(code, 'MISSING_AUTH').length).toBeGreaterThan(0);
  });

  test('does not flag function with session_start before sensitive operation', () => {
    const code = `<?php
function handleUpdate() {
  session_start();
  if (!isset($_SESSION['user_id'])) { header('Location: /login'); exit; }
  $id = $_POST['id'];
  $stmt = $pdo->prepare("UPDATE users SET name=? WHERE id=?");
  $stmt->execute([$_POST['name'], $id]);
}
`;
    expect(findingsOfType(code, 'MISSING_AUTH').length).toBe(0);
  });

  test('detects REQUEST_METHOD check without auth guard', () => {
    const code = `<?php
if ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
  $db->query("DELETE FROM items WHERE id=" . $_GET['id']);
}
`;
    expect(findingsOfType(code, 'MISSING_AUTH').length).toBeGreaterThan(0);
  });
});

// ── Cross-cutting tests ────────────────────────────────────────────────────────

describe('PHP scanner — cross-cutting', () => {
  test('all findings have valid severity levels', () => {
    const code = `<?php
echo $_GET['name'];
eval($_POST['code']);
$password = "secret1234";
$x = rand(1, 100);
$h = md5($data);
`;
    const findings = scan(code);
    const validSeverities = new Set(['critical', 'high', 'medium', 'low']);
    for (const f of findings) {
      expect(validSeverities.has(f.severity)).toBe(true);
    }
  });

  test('all findings include file path', () => {
    const code = `<?php\necho $_GET['x'];`;
    const findings = scan(code);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.file).toBe('test.php');
    }
  });

  test('all findings include confidence values', () => {
    const code = `<?php
echo $_GET['name'];
eval($_POST['code']);
$hash = md5($pw);
$token = rand(1, 100);
`;
    const findings = scan(code);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.confidence).toBeDefined();
      expect(f.confidence).toBeGreaterThan(0);
      expect(f.confidence).toBeLessThanOrEqual(1);
    }
  });

  test('skips comment lines', () => {
    const code = `<?php\n// echo $_GET['name'];\n# eval($_POST['code']);`;
    expect(scan(code).length).toBe(0);
  });
});
