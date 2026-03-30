<?php
/**
 * clean.php — PHP fixture with safe equivalents of all 13 vulnerability classes.
 * Should produce zero findings when scanned.
 */

// ── SQL_INJECTION (safe: prepared statement) ─────────────────────────────────
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);

// ── XSS (safe: htmlspecialchars) ─────────────────────────────────────────────
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
print htmlspecialchars($username, ENT_QUOTES, 'UTF-8');

// ── COMMAND_INJECTION (safe: static string) ───────────────────────────────────
shell_exec("ls -la /tmp");

// ── PATH_TRAVERSAL (safe: static path) ───────────────────────────────────────
$data = file_get_contents('/etc/config.json');
include('/var/www/html/templates/page.php');

// ── EVAL_INJECTION (safe: no eval, preg_replace without /e) ──────────────────
preg_replace('/pattern/', 'replacement', $str);

// ── SECRET_HARDCODED (safe: env-based) ───────────────────────────────────────
$password = getenv('DB_PASSWORD');
$api_key = getenv('API_KEY');

// ── SSRF (safe: static URL) ───────────────────────────────────────────────────
$response = file_get_contents('https://api.example.com/data');
curl_setopt($ch, CURLOPT_URL, 'https://api.example.com/endpoint');

// ── OPEN_REDIRECT (safe: static redirect) ────────────────────────────────────
header('Location: /dashboard');

// ── UNSAFE_DESERIALIZATION (safe: json_decode) ────────────────────────────────
$data = json_decode($_POST['json'], true);

// ── INSECURE_RANDOM (safe: random_int / random_bytes) ────────────────────────
$token = random_int(100000, 999999);
$bytes = random_bytes(32);

// ── WEAK_CRYPTO (safe: password_hash / hash sha256) ──────────────────────────
$hash = password_hash($password, PASSWORD_BCRYPT);
$sig = hash('sha256', $data);

// ── XML_INJECTION (safe: no XML parsing from user input) ─────────────────────
$data = json_decode($input);

// ── SSTI (safe: static template name) ────────────────────────────────────────
$twig->render('index.html', ['name' => $safeName]);
