/**
 * Integration tests for Java file scanning via POST /scan.
 *
 * Verifies that submitting Java code with filename ending in .java is correctly
 * routed through the Java scanner (java-parser.ts) and returns Java-specific
 * findings (SQL_INJECTION, COMMAND_INJECTION, WEAK_CRYPTO, UNSAFE_DESERIALIZATION,
 * XML_INJECTION).
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import request from 'supertest';
import { app } from '../../src/server';

// ── Vulnerable Java fixture ─────────────────────────────────────────────────
// Triggers: SQL_INJECTION, COMMAND_INJECTION, WEAK_CRYPTO, UNSAFE_DESERIALIZATION,
//           XML_INJECTION, INSECURE_RANDOM

const VULNERABLE_JAVA = `
import java.sql.*;
import java.io.*;
import java.security.*;
import javax.xml.parsers.*;

public class VulnerableService {
    // SQL injection via string concatenation
    public ResultSet getUser(Connection conn, String userId) throws SQLException {
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
    }

    // Command injection via Runtime.exec with variable
    public void runCommand(String userInput) throws IOException {
        Runtime.getRuntime().exec(userInput);
    }

    // Weak crypto: MD5
    public byte[] hashData(String data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data.getBytes());
    }

    // Unsafe deserialization
    public Object deserialize(InputStream input) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(input);
        return ois.readObject();
    }

    // XXE: DocumentBuilderFactory without secure config
    public void parseXml(InputStream xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.newDocumentBuilder().parse(xml);
    }

    // Insecure random
    public int generateToken() {
        return new java.util.Random().nextInt();
    }
}
`;

// Clean Java code — no findings expected
const CLEAN_JAVA = `
public class SafeService {
    private final String name;

    public SafeService(String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }
}
`;

// ── Tests ───────────────────────────────────────────────────────────────────

describe('/scan with Java files', () => {
  test('vulnerable Java code returns findings with filename ending in .java', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_JAVA,
      filename: 'VulnerableService.java',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string; message: string }> };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBeGreaterThan(0);

    const types = new Set(body.findings.map((f) => f.type));

    // The vulnerable fixture should trigger at least these Java-detected types
    expect(types.has('SQL_INJECTION')).toBe(true);
    expect(types.has('COMMAND_INJECTION')).toBe(true);
    expect(types.has('WEAK_CRYPTO')).toBe(true);
    expect(types.has('UNSAFE_DESERIALIZATION')).toBe(true);
    expect(types.has('XML_INJECTION')).toBe(true);
    expect(types.has('INSECURE_RANDOM')).toBe(true);
  });

  test('clean Java code returns zero findings', async () => {
    const res = await request(app).post('/scan').send({
      code: CLEAN_JAVA,
      filename: 'SafeService.java',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBe(0);
  });

  test('Java findings include correct file field', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_JAVA,
      filename: 'MyApp.java',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ file: string }> };
    expect(body.findings.length).toBeGreaterThan(0);
    for (const f of body.findings) {
      expect(f.file).toBe('MyApp.java');
    }
  });

  test('response includes summary object', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_JAVA,
      filename: 'Test.java',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: unknown[]; summary: { total: number } };
    expect(typeof body.summary).toBe('object');
    expect(body.summary.total).toBeGreaterThan(0);
  });
});
