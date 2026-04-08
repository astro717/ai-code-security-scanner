<?php
/**
 * vulnerable.php — PHP fixture with all 13 vulnerability classes.
 * Used by php-fixtures.vitest.ts and server-scan-php.vitest.ts.
 * DO NOT use this code in production — it is intentionally insecure.
 */

// ── SQL_INJECTION ────────────────────────────────────────────────────────────
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id=" . $id);

// ── XSS ─────────────────────────────────────────────────────────────────────
echo $_GET['name'];
print "Hello " . $_POST['user'];

// ── COMMAND_INJECTION ────────────────────────────────────────────────────────
shell_exec("ls " . $_GET['dir']);
$out = `cat $_REQUEST[file]`;

// ── PATH_TRAVERSAL ───────────────────────────────────────────────────────────
$data = file_get_contents($_GET['file']);
include($_REQUEST['page']);

// ── EVAL_INJECTION ───────────────────────────────────────────────────────────
eval($_POST['code']);
preg_replace('/pattern/e', 'replacement', $str);

// ── SECRET_HARDCODED ─────────────────────────────────────────────────────────
$password = "s3cretP@ss123";
$api_key = "abcd1234efgh5678ijkl";

// ── SSRF ─────────────────────────────────────────────────────────────────────
$response = file_get_contents($_GET['url']);
curl_setopt($ch, CURLOPT_URL, $_POST['target']);

// ── OPEN_REDIRECT ────────────────────────────────────────────────────────────
header("Location: $_GET[url]");

// ── UNSAFE_DESERIALIZATION ───────────────────────────────────────────────────
$obj = unserialize($_COOKIE['data']);

// ── INSECURE_RANDOM ──────────────────────────────────────────────────────────
$token = rand(100000, 999999);
$code = mt_rand();

// ── WEAK_CRYPTO ──────────────────────────────────────────────────────────────
$hash = md5($password);
$sig = sha1($data);

// ── XML_INJECTION ────────────────────────────────────────────────────────────
$xml = simplexml_load_string($data);

// ── SSTI ─────────────────────────────────────────────────────────────────────
$twig->render($twig->createTemplate($_GET['tpl']));

// ── MISSING_AUTH (vulnerable: accesses $_POST without auth guard) ─────────────
function processUserData() {
  $name = $_POST['name'];
  $email = $_POST['email'];
  // No authentication check — direct access to $_POST
  mysqli_query($conn, "INSERT INTO users (name, email) VALUES ('$name', '$email')");
}
