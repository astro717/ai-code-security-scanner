/**
 * Integration tests for C/C++ file scanning via POST /scan.
 *
 * Verifies that submitting C/C++ code with filename ending in .c/.cpp/.h is
 * correctly routed through the C scanner (c-parser.ts) and returns C-specific
 * findings (BUFFER_OVERFLOW, FORMAT_STRING, COMMAND_INJECTION, etc.).
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import request from 'supertest';
import { app } from '../../src/server';

// ── Vulnerable C fixture ──────────��─────────────────────────────────────────

const VULNERABLE_C = `
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Buffer overflow: gets
void read_input() {
    char buf[64];
    gets(buf);
}

// Buffer overflow: strcpy
void copy_name(const char *src) {
    char dest[32];
    strcpy(dest, src);
}

// Format string vulnerability
void log_message(const char *userInput) {
    printf(userInput);
}

// Command injection via system()
void run_cmd(const char *userInput) {
    char cmd[256];
    sprintf(cmd, "ls %s", userInput);
    system(cmd);
}

// Weak crypto: MD5
void hash_data() {
    MD5_CTX ctx;
    MD5_Init(&ctx);
}
`;

const CLEAN_C = `
#include <stdio.h>
#include <string.h>

int add(int a, int b) {
    return a + b;
}

void print_message(const char *msg) {
    printf("%s\\n", msg);
}
`;

// Fixture specifically for COMMAND_INJECTION_C detection
const C_COMMAND_INJECTION = `
#include <stdlib.h>

void execute_user_cmd(char *argv[]) {
    system(argv[1]);
}

void open_pipe(const char *user) {
    FILE *fp = popen(user, "r");
    fclose(fp);
}
`;

const COMMAND_INJECTION_C_CODE = `
#include <stdlib.h>
#include <stdio.h>

void run_user_cmd(int argc, char *argv[]) {
    system(argv[1]);
}
`;

// ── Helpers ────────���────────────────────────────���───────────────────────────


// ── Server lifecycle ────────────────────────���───────────────────────────────


// ── Tests ──────���───────────────────────────────���────────────────────────────

describe('/scan with C/C++ files', () => {
  test('vulnerable C code returns findings with filename ending in .c', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_C,
      filename: 'vulnerable.c',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string }> };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBeGreaterThan(0);

    const types = new Set(body.findings.map((f) => f.type));

    // The vulnerable fixture should trigger at least these C-detected types
    expect(types.has('BUFFER_OVERFLOW')).toBe(true);
    expect(types.has('FORMAT_STRING')).toBe(true);
    expect(types.has('WEAK_CRYPTO')).toBe(true);
  });

  test('vulnerable code works with .cpp extension too', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_C,
      filename: 'vulnerable.cpp',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ type: string }> };
    expect(body.findings.length).toBeGreaterThan(0);
  });

  test('clean C code returns zero findings', async () => {
    const res = await request(app).post('/scan').send({
      code: CLEAN_C,
      filename: 'safe.c',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBe(0);
  });

  test('C findings include correct file field', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_C,
      filename: 'main.c',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ file: string }> };
    expect(body.findings.length).toBeGreaterThan(0);
    for (const f of body.findings) {
      expect(f.file).toBe('main.c');
    }
  });

  test('response includes summary object', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_C,
      filename: 'test.c',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: unknown[]; summary: { total: number } };
    expect(typeof body.summary).toBe('object');
    expect(body.summary.total).toBeGreaterThan(0);
  });

  test('C command injection via system() with argv is detected as COMMAND_INJECTION_C', async () => {
    const res = await request(app).post('/scan').send({
      code: COMMAND_INJECTION_C_CODE,
      filename: 'cmd_inject.c',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string }> };
    expect(Array.isArray(body.findings)).toBe(true);

    const cmdInjectionFindings = body.findings.filter((f) => f.type === 'COMMAND_INJECTION_C');
    expect(cmdInjectionFindings.length).toBeGreaterThan(0);

    for (const f of cmdInjectionFindings) {
      expect(f.severity).toBe('critical');
    }
  });

});