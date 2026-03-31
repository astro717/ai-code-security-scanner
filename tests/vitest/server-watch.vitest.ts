/**
 * Integration tests for GET /watch SSE file-change triggered scan events.
 *
 * Verifies that:
 *   1. A file-change event on a watched path causes the server to emit a
 *      scan SSE event containing a findings structure.
 *   2. The scan SSE payload includes the expected shape (files, findings, summary, ts).
 *   3. A file whose extension is not in the watched set does NOT trigger a scan event.
 *
 * The server's /watch endpoint uses Node's native fs.watch internally. These tests
 * work with real temporary directories and actual filesystem writes to keep the
 * test surface close to production behaviour. A 1.5 s timeout guards against flaky
 * timing on slow CI machines.
 */

import { describe, test, expect } from 'vitest';
import request from 'supertest';
import { app } from '../../src/server';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Open a supertest SSE connection to GET /watch and collect raw SSE text until
 * the given predicate returns true or the timeout fires.
 * Returns the accumulated SSE text.
 */
function collectSSE(watchPath: string, timeoutMs: number): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    const req = request(app)
      .get(`/watch?path=${encodeURIComponent(watchPath)}`)
      .set('Accept', 'text/event-stream')
      .buffer(true)
      .parse((res, cb) => {
        res.on('data', (chunk: Buffer) => {
          data += chunk.toString();
        });
        res.on('error', () => cb(null, data));
        res.on('close', () => cb(null, data));
      });

    const timer = setTimeout(() => {
      req.abort?.();
      resolve(data);
    }, timeoutMs);

    req.then(() => {
      clearTimeout(timer);
      resolve(data);
    }).catch(() => {
      clearTimeout(timer);
      resolve(data);
    });
  });
}

/**
 * Parse SSE text into an array of { event, data } objects.
 */
function parseSSEEvents(text: string): Array<{ event: string; data: unknown }> {
  const events: Array<{ event: string; data: unknown }> = [];
  const blocks = text.split('\n\n').filter(Boolean);
  for (const block of blocks) {
    let eventName = 'message';
    let dataLine = '';
    for (const line of block.split('\n')) {
      if (line.startsWith('event: ')) eventName = line.slice(7).trim();
      if (line.startsWith('data: ')) dataLine = line.slice(6).trim();
    }
    if (dataLine) {
      try {
        events.push({ event: eventName, data: JSON.parse(dataLine) });
      } catch {
        events.push({ event: eventName, data: dataLine });
      }
    }
  }
  return events;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('GET /watch — file-change triggered scan events', () => {
  test(
    'emits a scan event when a .ts file is written inside the watched directory',
    async () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'watch-scan-'));
      const targetFile = path.join(tmpDir, 'vulnerable.ts');

      // Start collecting SSE events before writing the file
      const ssePromise = collectSSE(tmpDir, 1500);

      // Give the watcher time to attach, then write a file with a known finding
      await new Promise((r) => setTimeout(r, 150));
      fs.writeFileSync(
        targetFile,
        'const q = db.query("SELECT * FROM users WHERE id = " + userId);\n',
      );

      const rawSSE = await ssePromise;
      const events = parseSSEEvents(rawSSE);

      const scanEvent = events.find((e) => e.event === 'scan');
      expect(scanEvent, 'expected a scan event after file write').toBeDefined();

      const payload = scanEvent!.data as {
        files: string[];
        findings: unknown[];
        summary: unknown;
        ts: string;
      };
      expect(Array.isArray(payload.files)).toBe(true);
      expect(Array.isArray(payload.findings)).toBe(true);
      expect(typeof payload.ts).toBe('string');
      expect(typeof payload.summary).toBe('object');

      fs.rmSync(tmpDir, { recursive: true, force: true });
    },
    4000,
  );

  test(
    'scan event payload contains findings for a vulnerable Swift file',
    async () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'watch-swift-'));
      const targetFile = path.join(tmpDir, 'leak.swift');

      const ssePromise = collectSSE(tmpDir, 1500);

      await new Promise((r) => setTimeout(r, 150));
      // Write a Swift file with a hardcoded secret — should produce a SECRET_HARDCODED finding
      fs.writeFileSync(
        targetFile,
        'let apiKey: String = "sk-liveabcdef1234567890secretkey"\n',
      );

      const rawSSE = await ssePromise;
      const events = parseSSEEvents(rawSSE);

      const scanEvent = events.find((e) => e.event === 'scan');
      expect(scanEvent, 'expected a scan event for swift file').toBeDefined();

      const payload = scanEvent!.data as { findings: Array<{ type: string }> };
      const findingTypes = payload.findings.map((f) => f.type);
      expect(findingTypes).toContain('SECRET_HARDCODED');

      fs.rmSync(tmpDir, { recursive: true, force: true });
    },
    4000,
  );

  test(
    'does NOT emit a scan event when a non-source file (.txt) is written',
    async () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'watch-noscan-'));
      const targetFile = path.join(tmpDir, 'notes.txt');

      const ssePromise = collectSSE(tmpDir, 800);

      await new Promise((r) => setTimeout(r, 150));
      fs.writeFileSync(targetFile, 'just some text\n');

      const rawSSE = await ssePromise;
      const events = parseSSEEvents(rawSSE);

      const scanEvents = events.filter((e) => e.event === 'scan');
      expect(scanEvents).toHaveLength(0);

      fs.rmSync(tmpDir, { recursive: true, force: true });
    },
    3000,
  );
});
