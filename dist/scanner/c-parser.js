"use strict";
/**
 * C/C++ language support for the AI Code Security Scanner.
 *
 * This module implements a regex-based scan pass for C and C++ files (.c, .cpp,
 * .cc, .cxx, .h, .hpp). It operates on raw source lines with pattern matching —
 * no native compilation or libclang required. Patterns are conservative to
 * minimise false positives in real-world systems code.
 *
 * Covered vulnerability classes:
 *   - BUFFER_OVERFLOW (unsafe string/buffer functions: gets, strcpy, strcat, sprintf, scanf)
 *   - FORMAT_STRING (printf/fprintf family with non-literal format strings)
 *   - COMMAND_INJECTION_C (system() / popen() / exec*() family — user-controlled command execution)
 *   - SECRET_HARDCODED (hardcoded credentials in string literals)
 *   - PATH_TRAVERSAL (fopen/open with user-controlled paths)
 *   - INSECURE_RANDOM (rand() / srand(time()) for security use)
 *   - WEAK_CRYPTO (MD5, SHA1 via common OpenSSL library calls)
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseCFile = parseCFile;
exports.parseCCode = parseCCode;
exports.scanC = scanC;
const fs = __importStar(require("fs"));
function parseCFile(filePath) {
    const code = fs.readFileSync(filePath, 'utf-8');
    return parseCCode(code, filePath);
}
function parseCCode(code, filePath = 'input.c') {
    return { language: 'c', code, lines: code.split('\n'), filePath };
}
const C_PATTERNS = [
    // Buffer overflow — unsafe C string/buffer functions
    {
        type: 'BUFFER_OVERFLOW',
        severity: 'critical',
        pattern: /\bgets\s*\(/,
        message: 'gets() is unconditionally unsafe — it performs no bounds checking and will overflow any ' +
            'fixed-size buffer. Replace with fgets(buf, sizeof(buf), stdin).',
        confidence: 0.98,
    },
    {
        type: 'BUFFER_OVERFLOW',
        severity: 'high',
        pattern: /\bstrcpy\s*\(/,
        message: 'strcpy() does not check the destination buffer size. If the source string exceeds the ' +
            'destination, this causes a buffer overflow. Use strlcpy() or strncpy() with explicit bounds.',
        confidence: 0.96,
    },
    {
        type: 'BUFFER_OVERFLOW',
        severity: 'high',
        pattern: /\bstrcat\s*\(/,
        message: 'strcat() does not check the destination buffer size. Use strlcat() or strncat() with ' +
            'explicit length bounds to prevent buffer overflows.',
        confidence: 0.95,
    },
    {
        type: 'BUFFER_OVERFLOW',
        severity: 'high',
        pattern: /\bsprintf\s*\(/,
        message: 'sprintf() writes to a buffer without a size limit. Use snprintf() with an explicit ' +
            'buffer size argument to prevent buffer overflows.',
        confidence: 0.93,
    },
    {
        type: 'BUFFER_OVERFLOW',
        severity: 'high',
        pattern: /\bscanf\s*\(\s*"[^"]*%s/,
        message: 'scanf() with %s format specifier reads an unbounded string into a buffer. ' +
            'Use scanf("%<N>s", buf) with an explicit width limit, or use fgets().',
        confidence: 0.91,
    },
    {
        type: 'BUFFER_OVERFLOW',
        severity: 'high',
        pattern: /\bvsprintf\s*\(/,
        message: 'vsprintf() writes to a buffer without a size limit. Use vsnprintf() with an explicit size.',
        confidence: 0.94,
    },
    // Format string vulnerabilities
    {
        type: 'FORMAT_STRING',
        severity: 'critical',
        pattern: /\b(?:printf|fprintf|syslog)\s*\(\s*(?!")[^,)]+(?:,|\))/,
        message: 'printf/fprintf called with a non-literal format string as the first argument. If the ' +
            'format string is user-controlled, this allows reading arbitrary memory or code execution. ' +
            'Always use a literal format string: printf("%s", user_input).',
        confidence: 0.85,
    },
    // Command injection via system() and popen() — C/C++-specific type
    {
        type: 'COMMAND_INJECTION_C',
        severity: 'critical',
        pattern: /\bsystem\s*\([^)]*(?:sprintf|strcat|snprintf|argv|input|user|param)/,
        message: 'system() called with what appears to be a dynamically-constructed command string. ' +
            'If any part is user-controlled, this allows arbitrary command injection. ' +
            'Use execve() with a fixed argument list instead.',
        confidence: 0.84,
    },
    {
        type: 'COMMAND_INJECTION_C',
        severity: 'critical',
        pattern: /\bpopen\s*\([^)]*(?:sprintf|strcat|argv|input|user)/,
        message: 'popen() called with a dynamically-constructed command. User-controlled input in shell ' +
            'commands allows command injection. Use execve() with individual arguments.',
        confidence: 0.86,
    },
    {
        type: 'COMMAND_INJECTION_C',
        severity: 'high',
        pattern: /\bexecl\s*\(|execlp\s*\(|execle\s*\(|execv\s*\(|execvp\s*\(|execvpe\s*\(/,
        message: 'exec() family function detected. Ensure the executable path and all arguments are ' +
            'fully controlled by the application and never derived from user input without strict ' +
            'allowlisting, as this could enable arbitrary command execution.',
        confidence: 0.68,
    },
    // Hardcoded secrets
    {
        type: 'SECRET_HARDCODED',
        severity: 'high',
        pattern: /(?:password|passwd|secret|token|api_key|apikey|private_key)\s*=\s*"[^"]{4,}"/i,
        message: 'Potential hardcoded credential in C/C++ source. Secrets must be loaded from environment ' +
            'variables (getenv()) or a configuration file outside the source tree.',
        confidence: 0.84,
    },
    // Path traversal
    {
        type: 'PATH_TRAVERSAL',
        severity: 'high',
        pattern: /\b(?:fopen|open)\s*\([^)]*(?:argv|input|user|param|getenv)/,
        message: 'fopen()/open() called with a user-controlled path. Without path canonicalisation, ' +
            'attackers can traverse the filesystem using ../ sequences. Use realpath() to resolve and ' +
            'validate the path before opening.',
        confidence: 0.80,
    },
    // Insecure random
    {
        type: 'INSECURE_RANDOM',
        severity: 'medium',
        pattern: /\brand\s*\(\s*\)/,
        message: 'rand() is a low-quality pseudo-random number generator and must not be used for ' +
            'security-sensitive values (tokens, session IDs, cryptographic keys). ' +
            'Use getrandom() on Linux or arc4random() on BSD/macOS.',
        confidence: 0.92,
    },
    {
        type: 'INSECURE_RANDOM',
        severity: 'medium',
        pattern: /\bsrand\s*\(\s*time\s*\(/,
        message: 'srand(time(NULL)) seeds the PRNG with a predictable value. An attacker who knows ' +
            'the approximate process start time can predict all subsequent rand() outputs.',
        confidence: 0.90,
    },
    // Weak crypto
    {
        type: 'WEAK_CRYPTO',
        severity: 'high',
        pattern: /\bMD5\s*\(|MD5_Init\s*\(|MD5_Update\s*\(/,
        message: 'MD5 hashing is cryptographically broken and collision-prone. ' +
            'Use SHA-256 (SHA256_Init/SHA256_Update/SHA256_Final) or SHA-3 for security-sensitive hashing.',
        confidence: 0.96,
    },
    {
        type: 'WEAK_CRYPTO',
        severity: 'high',
        pattern: /\bSHA1\s*\(|SHA1_Init\s*\(|SHA_Init\s*\(/,
        message: 'SHA-1 is cryptographically weak and vulnerable to collision attacks. ' +
            'Use SHA-256 or SHA-3 (SHA256, SHA3_256 in OpenSSL) for security-sensitive hashing.',
        confidence: 0.95,
    },
];
/**
 * Scans a parsed C/C++ source for security vulnerabilities using pattern matching.
 * Returns findings in the same Finding format as other language detectors.
 */
function scanC(result) {
    const findings = [];
    result.lines.forEach((line, idx) => {
        const lineNum = idx + 1;
        const trimmed = line.trim();
        // Skip pure comments and preprocessor directives
        if (trimmed.startsWith('//') ||
            trimmed.startsWith('*') ||
            trimmed.startsWith('/*') ||
            trimmed.startsWith('#include') ||
            trimmed.startsWith('#define') ||
            trimmed.startsWith('#pragma'))
            return;
        for (const { type, severity, pattern, message, confidence } of C_PATTERNS) {
            if (pattern.test(line)) {
                findings.push({
                    type,
                    severity,
                    line: lineNum,
                    column: line.search(/\S/),
                    snippet: trimmed.slice(0, 100),
                    message,
                    ...(confidence !== undefined ? { confidence } : {}),
                    file: result.filePath,
                });
            }
        }
    });
    return findings;
}
//# sourceMappingURL=c-parser.js.map