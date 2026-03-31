/**
 * Integration tests for Kotlin file scanning via POST /scan.
 *
 * Verifies that submitting Kotlin code with filename ending in .kt is correctly
 * routed through the Kotlin scanner (kotlin-parser.ts) and returns Kotlin-specific
 * findings (SECRET_HARDCODED, INSECURE_RANDOM, SQL_INJECTION).
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import request from 'supertest';
import { app } from '../../src/server';

// ── Vulnerable Kotlin fixture ─────────────────────────────────────────────────
// Triggers: SECRET_HARDCODED, INSECURE_RANDOM, SQL_INJECTION

const VULNERABLE_KOTLIN = `
package com.example.app

import java.util.Random
import android.database.sqlite.SQLiteDatabase
import java.security.MessageDigest

class VulnerableRepository(private val db: SQLiteDatabase) {

    // Hardcoded API key — should use Android Keystore
    val apiKey = "sk-liveabcdef1234567890secret"

    // Insecure random for generating session tokens
    fun generateSessionId(): Int {
        val rng = Random()
        return rng.nextInt()
    }

    // SQL injection via string concatenation in rawQuery
    fun getOrdersByUser(userId: String): android.database.Cursor {
        return db.rawQuery("SELECT * FROM orders WHERE user_id = " + userId, null)
    }

    // Hardcoded secret token
    val secretToken = "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"
}
`;

// Clean Kotlin code — no findings expected
const CLEAN_KOTLIN = `
package com.example.app

import java.security.SecureRandom
import android.database.sqlite.SQLiteDatabase

class SafeRepository(private val db: SQLiteDatabase) {

    fun generateToken(): ByteArray {
        val sr = SecureRandom()
        val bytes = ByteArray(32)
        sr.nextBytes(bytes)
        return bytes
    }

    fun getUserById(userId: String): android.database.Cursor {
        return db.rawQuery("SELECT * FROM users WHERE id = ?", arrayOf(userId))
    }
}
`;

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('/scan with Kotlin files (.kt)', () => {
  test('vulnerable Kotlin code returns findings with filename ending in .kt', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_KOTLIN,
      filename: 'VulnerableRepository.kt',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string; message: string }> };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBeGreaterThan(0);

    const types = new Set(body.findings.map((f) => f.type));

    // The fixture must trigger these Kotlin-specific findings
    expect(types.has('SECRET_HARDCODED')).toBe(true);
    expect(types.has('INSECURE_RANDOM')).toBe(true);
    expect(types.has('SQL_INJECTION')).toBe(true);
  });

  test('clean Kotlin code returns zero findings', async () => {
    const res = await request(app).post('/scan').send({
      code: CLEAN_KOTLIN,
      filename: 'SafeRepository.kt',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBe(0);
  });

  test('.kts extension is also routed to the Kotlin scanner', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_KOTLIN,
      filename: 'build.kts',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBeGreaterThan(0);
  });

  test('findings include correct filename in file field', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_KOTLIN,
      filename: 'MainActivity.kt',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ file: string }> };
    expect(body.findings.length).toBeGreaterThan(0);
    for (const f of body.findings) {
      expect(f.file).toBe('MainActivity.kt');
    }
  });

  test('response includes summary with correct total count', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_KOTLIN,
      filename: 'VulnerableRepository.kt',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: unknown[]; summary: { total: number } };
    expect(typeof body.summary).toBe('object');
    expect(body.summary.total).toBe(body.findings.length);
    expect(body.summary.total).toBeGreaterThan(0);
  });

  test('all Kotlin findings have required shape (type, severity, line, message, file)', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_KOTLIN,
      filename: 'VulnerableRepository.kt',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<Record<string, unknown>> };
    for (const f of body.findings) {
      expect(typeof f.type).toBe('string');
      expect(typeof f.severity).toBe('string');
      expect(['critical', 'high', 'medium', 'low']).toContain(f.severity);
      expect(typeof f.line).toBe('number');
      expect(f.line).toBeGreaterThan(0);
      expect(typeof f.message).toBe('string');
      expect(f.message.length).toBeGreaterThan(0);
      expect(f.file).toBe('VulnerableRepository.kt');
    }
  });
});

// ── PERFORMANCE_N_PLUS_ONE unit tests ─────────────────────────────────────────

import { parseKotlinCode, scanKotlin } from '../../src/scanner/kotlin-parser';

describe('Kotlin scanner — PERFORMANCE_N_PLUS_ONE detection', () => {
  test('detects N+1 query in a for loop calling dao.findById on the next line', () => {
    const code = [
      'fun loadAll(ids: List<Int>) {',
      '    for (id in ids) {',
      '        val user = dao.findById(id)',
      '        println(user.name)',
      '    }',
      '}',
    ].join('\n');
    const result = parseKotlinCode(code, 'repo.kt');
    const findings = scanKotlin(result);
    const types = findings.map((f) => f.type);
    expect(types).toContain('PERFORMANCE_N_PLUS_ONE');
  });

  test('detects N+1 query in a forEach block with dao.query inside', () => {
    const code = [
      'fun processAll(items: List<String>) {',
      '    items.forEach {',
      '        val row = dao.query("SELECT * FROM t WHERE name = ?", it)',
      '        handle(row)',
      '    }',
      '}',
    ].join('\n');
    const result = parseKotlinCode(code, 'service.kt');
    const findings = scanKotlin(result);
    const types = findings.map((f) => f.type);
    expect(types).toContain('PERFORMANCE_N_PLUS_ONE');
  });

  test('detects N+1 query in a map call with dao.load inside', () => {
    const code = [
      'val details = userIds.map { id ->',
      '    val profile = dao.load(id)',
      '    profile.toDto()',
      '}',
    ].join('\n');
    const result = parseKotlinCode(code, 'mapper.kt');
    const findings = scanKotlin(result);
    const types = findings.map((f) => f.type);
    expect(types).toContain('PERFORMANCE_N_PLUS_ONE');
  });

  test('does NOT flag a single DAO call outside any loop', () => {
    const code = [
      'fun getUser(id: Int): User {',
      '    return dao.findById(id)',
      '}',
    ].join('\n');
    const result = parseKotlinCode(code, 'clean.kt');
    const findings = scanKotlin(result);
    const n1 = findings.filter((f) => f.type === 'PERFORMANCE_N_PLUS_ONE');
    expect(n1).toHaveLength(0);
  });

  test('PERFORMANCE_N_PLUS_ONE findings report the loop line and have severity low', () => {
    const code = [
      'for (item in items) {',
      '    val r = dao.select(item.id)',
      '    process(r)',
      '}',
    ].join('\n');
    const result = parseKotlinCode(code, 'loop.kt');
    const findings = scanKotlin(result).filter((f) => f.type === 'PERFORMANCE_N_PLUS_ONE');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.line).toBe(1); // The for-loop is on line 1
    for (const f of findings) {
      expect(f.severity).toBe('low');
    }
  });
});
