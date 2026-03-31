/**
 * Integration tests for Rust file scanning via POST /scan.
 *
 * Verifies that submitting Rust code with filename ending in .rs is correctly
 * routed through the Rust scanner (rust-parser.ts) and returns Rust-specific
 * findings (BUFFER_OVERFLOW, COMMAND_INJECTION, WEAK_CRYPTO, SECRET_HARDCODED,
 * INSECURE_RANDOM). Uses supertest for lightweight in-process HTTP testing.
 *
 * Run with: npm run test:vitest
 */

import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { app } from '../../src/server';

// ── Vulnerable Rust fixture ───────────────────────────────────────────────────

const VULNERABLE_RUST = `
use std::process::Command;

// Hardcoded API key — should be read from env
let api_key = "sk_live_abcdef1234567890abcdef1234";

// Insecure random for session token generation
let token: u64 = rand::random();

// Weak crypto — MD5 should not be used
let digest = md5::compute(b"hello");

// Buffer overflow risk — unsafe raw pointer dereference
unsafe { let x = *ptr; }

// Command injection — passing user-controlled variable to Command::new
let output = Command::new(user_cmd).output().unwrap();
`;

// ── Clean Rust fixture ────────────────────────────────────────────────────────

const CLEAN_RUST = `
use std::collections::HashMap;

fn greet(name: &str) -> String {
    format!("Hello, {}!", name)
}

fn add(a: i32, b: i32) -> i32 {
    a + b
}

fn main() {
    let mut scores: HashMap<&str, i32> = HashMap::new();
    scores.insert("Alice", 100);
    scores.insert("Bob", 95);
    println!("{:?}", scores);
}
`;

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('/scan with Rust files (.rs)', () => {
  it('vulnerable Rust code returns findings with filename ending in .rs', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ code: VULNERABLE_RUST, filename: 'vulnerable.rs' });

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.findings)).toBe(true);
    expect(res.body.findings.length).toBeGreaterThan(0);

    const types = new Set((res.body.findings as Array<{ type: string }>).map((f) => f.type));

    // The fixture must trigger these Rust-specific finding types
    expect(types.has('BUFFER_OVERFLOW')).toBe(true);
    expect(types.has('COMMAND_INJECTION')).toBe(true);
    expect(types.has('WEAK_CRYPTO')).toBe(true);
    expect(types.has('SECRET_HARDCODED')).toBe(true);
    expect(types.has('INSECURE_RANDOM')).toBe(true);
  });

  it('clean Rust code returns zero findings', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ code: CLEAN_RUST, filename: 'safe_lib.rs' });

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.findings)).toBe(true);
    expect(res.body.findings.length).toBe(0);
  });

  it('findings include correct filename in file field', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ code: VULNERABLE_RUST, filename: 'main.rs' });

    expect(res.status).toBe(200);
    const findings = res.body.findings as Array<{ file: string }>;
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.file).toBe('main.rs');
    }
  });

  it('response includes summary with correct total count', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ code: VULNERABLE_RUST, filename: 'vulnerable.rs' });

    expect(res.status).toBe(200);
    const body = res.body as { findings: unknown[]; summary: { total: number } };
    expect(typeof body.summary).toBe('object');
    expect(body.summary.total).toBe(body.findings.length);
    expect(body.summary.total).toBeGreaterThan(0);
  });

  it('all Rust findings have required fields (type, severity, line, message, file)', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ code: VULNERABLE_RUST, filename: 'vulnerable.rs' });

    expect(res.status).toBe(200);
    const findings = res.body.findings as Array<Record<string, unknown>>;
    for (const f of findings) {
      expect(typeof f['type']).toBe('string');
      expect(typeof f['severity']).toBe('string');
      expect(['critical', 'high', 'medium', 'low']).toContain(f['severity']);
      expect(typeof f['line']).toBe('number');
      expect((f['line'] as number)).toBeGreaterThan(0);
      expect(typeof f['message']).toBe('string');
      expect((f['message'] as string).length).toBeGreaterThan(0);
      expect(f['file']).toBe('vulnerable.rs');
    }
  });
});
