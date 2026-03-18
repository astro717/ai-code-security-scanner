// Test fixture: vulnerable code examples for each detector
// This file intentionally contains security vulnerabilities for testing purposes.

import { exec } from 'child_process';

// ── 1. SECRET HARDCODED ─────────────────────────────────────────────────────
const apiKey = 'sk-proj-abc123xyz456def789ghi012jkl345mno678pqr901stu';
const password = 'super-secret-password-123';
const githubToken = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345';

// ── 2. SQL INJECTION ─────────────────────────────────────────────────────────
function getUserByEmail(email: string, db: any) {
  // Direct string concatenation in query
  return db.query('SELECT * FROM users WHERE email = ' + email);
}

function getProduct(id: string, db: any) {
  // Template literal with variable
  return db.execute(`SELECT * FROM products WHERE id = ${id}`);
}

// ── 3. SHELL INJECTION ───────────────────────────────────────────────────────
function processFile(userInput: string) {
  // Variable passed directly to exec
  exec(`convert ${userInput} output.png`);
}

function runCommand(cmd: string) {
  const { execSync } = require('child_process');
  execSync(cmd);
}

// ── 4. EVAL INJECTION ────────────────────────────────────────────────────────
function runUserCode(userCode: string) {
  eval(userCode);
}

function dynamicFunction(body: string) {
  const fn = new Function('x', body);
  return fn(42);
}

function delayedExec(code: string) {
  setTimeout(code, 1000);
}

// ── 5. XSS ───────────────────────────────────────────────────────────────────
function renderUserContent(userHtml: string) {
  // dangerouslySetInnerHTML with dynamic value
  // <div dangerouslySetInnerHTML={{ __html: userHtml }} />
  const el = document.getElementById('content')!;
  el.innerHTML = userHtml;
}

function writeUserInput(input: string) {
  document.write(input);
}

// ── 6. PATH TRAVERSAL ────────────────────────────────────────────────────────
import * as fs from 'fs';
import * as path from 'path';

function readUserFile(userInput: string) {
  return fs.readFileSync(userInput, 'utf8');
}

function buildFilePath(userInput: string) {
  return path.join('/var/www/uploads', userInput);
}

// ── 7. PROTOTYPE POLLUTION ────────────────────────────────────────────────────
function mergeOptions(userInput: Record<string, unknown>) {
  const config: Record<string, unknown> = {};
  // Object.assign with dynamic source
  Object.assign(config, userInput);
}

function applyPayload(obj: Record<string, unknown>, payload: Record<string, unknown>) {
  // Direct __proto__ assignment
  (obj as any).__proto__ = payload;
}

// ── 8. INSECURE RANDOM ────────────────────────────────────────────────────────
function generateResetToken() {
  // Math.random() used for security-sensitive token — insecure
  const resetToken = Math.random().toString(36).slice(2);
  return resetToken;
}

function makeSessionId() {
  // Math.random() assigned to security-sensitive var
  const sessionId = Math.floor(Math.random() * 1e12);
  return sessionId;
}

// ── 9. OPEN REDIRECT ─────────────────────────────────────────────────────────
function handleRedirectVuln(req: any, res: any) {
  // Dynamic redirect target from user input — vulnerable
  const target = req.query.redirect;
  res.redirect(target);
}

function handleRedirectWithStatus(req: any, res: any) {
  // Status + dynamic URL — also vulnerable
  res.redirect(302, req.body.returnUrl);
}

// ── 10. SSRF ──────────────────────────────────────────────────────────────────
async function fetchUserProfile(userId: string) {
  // Dynamic URL built from user input — SSRF risk
  const response = await fetch(`https://internal-api/users/${userId}`);
  return response.json();
}

async function proxyRequest(targetUrl: string) {
  // User-controlled URL passed directly to http.get — SSRF risk
  const http = require('http');
  http.get(targetUrl, (res: any) => res.pipe(process.stdout));
}

// ── 11. JWT HARDCODED SECRET ──────────────────────────────────────────────────
import jwt from 'jsonwebtoken';

function createTokenHardcoded(userId: number) {
  // Hardcoded string secret — JWT_HARDCODED_SECRET
  return jwt.sign({ userId }, 'my-super-secret-key-that-is-long-enough-here');
}

function createTokenWeak(userId: number) {
  // Short hardcoded secret — JWT_WEAK_SECRET
  return jwt.sign({ userId }, 'weak');
}

// ── 12. UNSAFE DEPS — see package.json with "latest" versions ─────────────────
// (deps detector reads package.json, not this file)

// ── 12. COMMAND INJECTION ────────────────────────────────────────────────────
import { spawn, spawnSync } from 'child_process';

function runTool(toolName: string) {
  // Dynamic command name — attacker can run any program
  spawn(toolName, ['--help']);
}

function runToolSync(cmd: string, args: string[]) {
  spawnSync(cmd, args);
}

function runWithTemplate(userInput: string) {
  // Template literal command — still dynamic
  spawn(`${userInput}`, ['-v']);
}
