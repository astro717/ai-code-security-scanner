#!/usr/bin/env node
/**
 * reset-stuck-tasks.js
 *
 * Resets Aether Kanban tasks that have been stuck in `in_progress` for more
 * than STUCK_THRESHOLD_HOURS hours back to `todo` so they can be retried by
 * the next agent cycle.
 *
 * Usage:
 *   AETHER_TOKEN=<jwt> AETHER_ORG_ID=<uuid> node scripts/reset-stuck-tasks.js
 *
 * Optional environment variables:
 *   AETHER_BASE_URL         — Backend base URL (default: https://aether-api-summer-sun-4778.fly.dev)
 *   STUCK_THRESHOLD_HOURS   — Hours after which in_progress is considered stuck (default: 2)
 */

'use strict';

const https = require('https');
const http = require('http');
const url = require('url');

const BASE_URL = (process.env.AETHER_BASE_URL || 'https://aether-api-summer-sun-4778.fly.dev').replace(/\/$/, '');
const TOKEN = process.env.AETHER_TOKEN;
const ORG_ID = process.env.AETHER_ORG_ID;
const STUCK_THRESHOLD_HOURS = parseFloat(process.env.STUCK_THRESHOLD_HOURS || '2');

if (!TOKEN) { console.error('ERROR: AETHER_TOKEN environment variable is required.'); process.exit(1); }
if (!ORG_ID) { console.error('ERROR: AETHER_ORG_ID environment variable is required.'); process.exit(1); }

function request(method, reqPath, body) {
  return new Promise((resolve, reject) => {
    const parsed = new url.URL(BASE_URL + reqPath);
    const lib = parsed.protocol === 'https:' ? https : http;
    const payload = body ? JSON.stringify(body) : null;
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method,
      headers: {
        'Authorization': `Bearer ${TOKEN}`,
        'Content-Type': 'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
      },
    };
    const req = lib.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function main() {
  console.log(`[reset-stuck-tasks] Fetching kanban board for org ${ORG_ID}...`);
  const kanbanRes = await request('GET', `/tasks/organization/${ORG_ID}/kanban`);
  if (kanbanRes.status !== 200) {
    console.error(`ERROR: Failed to fetch kanban (HTTP ${kanbanRes.status}): ${JSON.stringify(kanbanRes.body)}`);
    process.exit(1);
  }

  const board = kanbanRes.body;
  const inProgressTasks = board.in_progress || [];
  const thresholdMs = STUCK_THRESHOLD_HOURS * 60 * 60 * 1000;
  const now = Date.now();

  const stuckTasks = inProgressTasks.filter((task) => {
    const updatedAt = task.updated_at ? new Date(task.updated_at).getTime() : 0;
    return (now - updatedAt) >= thresholdMs;
  });

  console.log(`[reset-stuck-tasks] Found ${inProgressTasks.length} in_progress task(s), ${stuckTasks.length} stuck (>= ${STUCK_THRESHOLD_HOURS}h).`);

  if (stuckTasks.length === 0) {
    console.log('[reset-stuck-tasks] Nothing to reset.');
    return;
  }

  let resetCount = 0;
  let errorCount = 0;

  for (const task of stuckTasks) {
    const ageHours = ((now - new Date(task.updated_at).getTime()) / (60 * 60 * 1000)).toFixed(1);
    process.stdout.write(`  Resetting "${task.title}" (stuck ${ageHours}h)... `);
    const patchRes = await request('PATCH', `/tasks/${task.id}`, { status: 'todo' });
    if (patchRes.status >= 200 && patchRes.status < 300) {
      console.log('done');
      resetCount++;
    } else {
      console.log(`FAILED (HTTP ${patchRes.status})`);
      errorCount++;
    }
  }

  console.log(`\n[reset-stuck-tasks] Reset ${resetCount} task(s).${errorCount > 0 ? ` ${errorCount} error(s).` : ''}`);
  if (errorCount > 0) process.exit(1);
}

main().catch((err) => {
  console.error('[reset-stuck-tasks] Unexpected error:', err.message || err);
  process.exit(1);
});
