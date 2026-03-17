// Test fixture: clean code with no vulnerabilities

import { execFile } from 'child_process';

// ── Safe database queries ─────────────────────────────────────────────────────
function getUserById(id: number, db: any) {
  return db.query('SELECT * FROM users WHERE id = ?', [id]);
}

function getProductBySlug(slug: string, db: any) {
  return db.execute('SELECT * FROM products WHERE slug = $1', [slug]);
}

// ── Safe shell execution (fixed args array) ───────────────────────────────────
function resizeImage(inputPath: string, outputPath: string) {
  execFile('convert', [inputPath, '-resize', '800x600', outputPath]);
}

// ── Safe credential handling ──────────────────────────────────────────────────
function getApiClient() {
  const apiKey = process.env.API_KEY;
  const secret = process.env.APP_SECRET;
  return { apiKey, secret };
}

// ── Safe dynamic execution ────────────────────────────────────────────────────
function delayedLog(message: string) {
  setTimeout(() => console.log(message), 1000);
}

function parseUserData(raw: string) {
  return JSON.parse(raw);
}

// ── Safe math computation ─────────────────────────────────────────────────────
function add(a: number, b: number): number {
  return a + b;
}

// ── Safe XSS patterns ─────────────────────────────────────────────────────────
function setStaticContent() {
  const el = document.getElementById('content')!;
  // Static string literal — not a vulnerability
  el.innerHTML = '<strong>Hello, world!</strong>';
}

// ── Safe object merging ───────────────────────────────────────────────────────
function mergeDefaults() {
  // Object.assign with all literal object expressions — safe
  return Object.assign({}, { timeout: 3000, retries: 3 }, { timeout: 5000 });
}

// ── Safe path operations ──────────────────────────────────────────────────────
import * as path from 'path';
import * as fs from 'fs';

function getConfigFile() {
  // All path.join arguments are string literals — safe
  return path.join('/etc', 'myapp', 'config.json');
}

function readStaticFile() {
  // Hardcoded path — safe
  return fs.readFileSync('/var/www/html/index.html', 'utf8');
}

// ── Safe random usage (non-security contexts) ─────────────────────────────────
function getRandomIndex(arr: unknown[]) {
  // Math.random() for array indexing — non-security variable name, safe
  return Math.floor(Math.random() * arr.length);
}

function rollDice(): number {
  // Math.random() for game mechanics — safe context
  return Math.ceil(Math.random() * 6);
}

// ── Safe redirects ────────────────────────────────────────────────────────────
function redirectToHome(_req: unknown, res: any) {
  // Static string literal — safe
  res.redirect('/home');
}

function redirectWithStatusStatic(_req: unknown, res: any) {
  // Status + static string — safe
  res.redirect(301, 'https://example.com/new-path');
}

// ── Safe outbound HTTP (static URLs) ─────────────────────────────────────────
async function fetchPublicData() {
  // Fully hardcoded URL — safe
  const response = await fetch('https://api.example.com/public/data');
  return response.json();
}

async function pingHealthCheck() {
  // Static template literal with no expressions — safe
  const res = await fetch(`https://health.example.com/ping`);
  return res.ok;
}

// ── Safe spawn usage (hardcoded command) ──────────────────────────────────────
import { spawn as _spawn, spawnSync as _spawnSync } from 'child_process';

function convertImage(inputPath: string, outputPath: string) {
  // Static command string — only args are dynamic, which is safe for spawn
  _spawn('convert', [inputPath, '-resize', '800x600', outputPath]);
}

function listDirectory(dirPath: string) {
  // Hardcoded command, dynamic args — safe
  _spawnSync('ls', ['-la', dirPath]);
}

export { getUserById, getProductBySlug, resizeImage, getApiClient, add, setStaticContent, getConfigFile, readStaticFile, getRandomIndex, rollDice, redirectToHome, redirectWithStatusStatic, fetchPublicData, pingHealthCheck, convertImage, listDirectory };
