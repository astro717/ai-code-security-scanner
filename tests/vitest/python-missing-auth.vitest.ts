/**
 * Unit tests for Python MISSING_AUTH stateful detector.
 *
 * Covers Flask and FastAPI route handlers that access request data without
 * an authentication guard, and verifies that authenticated handlers are NOT flagged.
 */

import { describe, test, expect } from 'vitest';
import { parsePythonCode, scanPython } from '../../src/scanner/python-parser';

function scan(code: string) {
  return scanPython(parsePythonCode(code, 'app.py'));
}

function missingAuthFindings(code: string) {
  return scan(code).filter((f) => f.type === 'MISSING_AUTH');
}

// ── Flask routes without auth ───────────────────────────────────────────────

describe('Python MISSING_AUTH — Flask routes without auth guard', () => {
  test('flags Flask POST route that reads request.json without auth', () => {
    const code = `
@app.route('/api/data', methods=['POST'])
def create_data():
    data = request.json
    return jsonify(data)
`;
    expect(missingAuthFindings(code).length).toBeGreaterThan(0);
  });

  test('flags Flask route that reads request.form without auth', () => {
    const code = `
@app.route('/submit', methods=['POST', 'GET'])
def submit():
    name = request.form.get('name')
    return name
`;
    expect(missingAuthFindings(code).length).toBeGreaterThan(0);
  });

  test('flags Flask route that reads request.args without auth', () => {
    const code = `
@app.route('/search')
def search():
    q = request.args.get('q')
    return q
`;
    expect(missingAuthFindings(code).length).toBeGreaterThan(0);
  });

  test('flags blueprint route accessing request.data without auth', () => {
    const code = `
@bp.route('/update', methods=['PUT'])
def update():
    payload = request.data
    return payload
`;
    expect(missingAuthFindings(code).length).toBeGreaterThan(0);
  });
});

// ── FastAPI routes without auth ─────────────────────────────────────────────

describe('Python MISSING_AUTH — FastAPI routes without auth guard', () => {
  test('flags FastAPI POST route accessing request.json without Depends auth', () => {
    const code = `
@router.post('/items')
async def create_item():
    data = await request.json()
    return data
`;
    expect(missingAuthFindings(code).length).toBeGreaterThan(0);
  });

  test('flags FastAPI GET route accessing request.args without auth', () => {
    const code = `
@app.get('/items')
def list_items():
    page = request.args.get('page', 1)
    return page
`;
    expect(missingAuthFindings(code).length).toBeGreaterThan(0);
  });
});

// ── Authenticated routes (should NOT be flagged) ────────────────────────────

describe('Python MISSING_AUTH — authenticated routes (negative cases)', () => {
  test('does not flag route decorated with @login_required', () => {
    const code = `
@app.route('/profile', methods=['GET'])
@login_required
def get_profile():
    data = request.args.get('id')
    return data
`;
    expect(missingAuthFindings(code).length).toBe(0);
  });

  test('does not flag route that calls current_user inside body', () => {
    const code = `
@app.route('/dashboard')
def dashboard():
    user = current_user
    data = request.args.get('tab')
    return data
`;
    expect(missingAuthFindings(code).length).toBe(0);
  });

  test('does not flag FastAPI route with Depends(get_current_user)', () => {
    const code = `
@router.get('/me')
def get_me(current_user=Depends(get_current_user)):
    data = request.args.get('field')
    return current_user
`;
    expect(missingAuthFindings(code).length).toBe(0);
  });

  test('does not flag route that calls jwt_required guard', () => {
    const code = `
@app.route('/secure', methods=['POST'])
@jwt_required
def secure_endpoint():
    data = request.json
    return data
`;
    expect(missingAuthFindings(code).length).toBe(0);
  });

  test('does not flag non-route function accessing request', () => {
    const code = `
def helper():
    data = request.json
    return data
`;
    expect(missingAuthFindings(code).length).toBe(0);
  });

  test('does not flag route that does not access request data', () => {
    const code = `
@app.route('/ping')
def ping():
    return 'pong'
`;
    expect(missingAuthFindings(code).length).toBe(0);
  });
});

// ── Finding properties ──────────────────────────────────────────────────────

describe('Python MISSING_AUTH — finding properties', () => {
  test('finding severity is high', () => {
    const code = `
@app.route('/data', methods=['POST'])
def get_data():
    val = request.json
    return val
`;
    const findings = missingAuthFindings(code);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.severity).toBe('high');
    }
  });

  test('finding includes file reference', () => {
    const result = scanPython(parsePythonCode(`
@app.route('/data', methods=['POST'])
def get_data():
    val = request.json
    return val
`, 'views/api.py'));
    const findings = result.filter((f) => f.type === 'MISSING_AUTH');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.file).toBe('views/api.py');
  });

  test('finding includes confidence', () => {
    const code = `
@app.route('/data', methods=['POST'])
def post_data():
    body = request.json
    return body
`;
    const findings = missingAuthFindings(code);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.confidence).toBeDefined();
    expect(findings[0]!.confidence).toBeGreaterThan(0);
  });
});
