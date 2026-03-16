"use strict";
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
exports.detectUnsafeDeps = detectUnsafeDeps;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
function detectUnsafeDeps(projectDir) {
    const findings = [];
    const pkgPath = path.join(projectDir, 'package.json');
    if (!fs.existsSync(pkgPath))
        return findings;
    let pkg;
    try {
        pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
    }
    catch {
        return findings;
    }
    const allDeps = {
        ...(pkg.dependencies ?? {}),
        ...(pkg.devDependencies ?? {}),
    };
    for (const [name, version] of Object.entries(allDeps)) {
        if (version === 'latest' || version === '*' || version === 'x') {
            findings.push({
                type: 'UNSAFE_DEPENDENCY',
                severity: 'medium',
                line: 1,
                column: 0,
                snippet: `"${name}": "${version}"`,
                message: `Dependency "${name}" pinned to "${version}" — unpinned versions can introduce breaking changes or malicious updates.`,
                file: pkgPath,
            });
        }
    }
    // Check for missing lockfile
    const lockFiles = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'];
    const hasLockfile = lockFiles.some((lf) => fs.existsSync(path.join(projectDir, lf)));
    if (!hasLockfile && Object.keys(allDeps).length > 0) {
        findings.push({
            type: 'UNSAFE_DEPENDENCY',
            severity: 'medium',
            line: 1,
            column: 0,
            snippet: 'No lockfile found',
            message: 'No package lockfile found (package-lock.json / yarn.lock / pnpm-lock.yaml). Dependency versions are not reproducible.',
            file: pkgPath,
        });
    }
    return findings;
}
//# sourceMappingURL=deps.js.map