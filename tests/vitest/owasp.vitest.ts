/**
 * Unit tests for OWASP Top 10 2021 classification mapping completeness.
 */

import { describe, test, expect } from 'vitest';
import { FINDING_TO_OWASP, OWASP_CATEGORIES, getOwaspCategory } from '../../src/scanner/owasp';
import { KNOWN_TYPES } from '../../src/scanner/reporter';

describe('OWASP mapping completeness', () => {
  test('every KNOWN_TYPES entry has an OWASP mapping', () => {
    const unmapped: string[] = [];
    for (const type of KNOWN_TYPES) {
      if (!FINDING_TO_OWASP[type]) {
        unmapped.push(type);
      }
    }
    expect(unmapped).toEqual([]);
  });

  test('every FINDING_TO_OWASP entry references a valid OWASP_CATEGORIES key', () => {
    for (const [type, categoryId] of Object.entries(FINDING_TO_OWASP)) {
      expect(
        OWASP_CATEGORIES[categoryId],
        `FINDING_TO_OWASP["${type}"] references "${categoryId}" which is not in OWASP_CATEGORIES`,
      ).toBeDefined();
    }
  });

  test('every FINDING_TO_OWASP key is a recognised KNOWN_TYPES entry', () => {
    const unknownTypes: string[] = [];
    for (const type of Object.keys(FINDING_TO_OWASP)) {
      if (!KNOWN_TYPES.has(type)) {
        unknownTypes.push(type);
      }
    }
    expect(unknownTypes).toEqual([]);
  });
});

describe('getOwaspCategory', () => {
  test('returns correct category for SQL_INJECTION (A03:2021)', () => {
    const cat = getOwaspCategory('SQL_INJECTION');
    expect(cat).toBeDefined();
    expect(cat!.id).toBe('A03:2021');
    expect(cat!.name).toBe('Injection');
  });

  test('returns correct category for WEAK_CRYPTO (A02:2021)', () => {
    const cat = getOwaspCategory('WEAK_CRYPTO');
    expect(cat).toBeDefined();
    expect(cat!.id).toBe('A02:2021');
    expect(cat!.name).toBe('Cryptographic Failures');
  });

  test('returns correct category for OPEN_REDIRECT (A01:2021)', () => {
    const cat = getOwaspCategory('OPEN_REDIRECT');
    expect(cat).toBeDefined();
    expect(cat!.id).toBe('A01:2021');
  });

  test('returns correct category for JWT_NONE_ALGORITHM (A05:2021)', () => {
    const cat = getOwaspCategory('JWT_NONE_ALGORITHM');
    expect(cat).toBeDefined();
    expect(cat!.id).toBe('A05:2021');
  });

  test('returns undefined for unknown finding type', () => {
    expect(getOwaspCategory('DOES_NOT_EXIST')).toBeUndefined();
  });
});
