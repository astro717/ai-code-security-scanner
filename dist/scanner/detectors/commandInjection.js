"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectCommandInjection = detectCommandInjection;
const utils_1 = require("../utils");
/**
 * Detects command injection via spawn()/spawnSync() where the first argument
 * (the command to execute) is a variable or template literal with expressions
 * rather than a static string literal.
 *
 * This is distinct from SHELL_INJECTION (exec/execSync with dynamic strings)
 * because spawn does NOT invoke a shell by default — yet a dynamic command
 * name still allows an attacker to execute arbitrary programs.
 *
 * Examples flagged:
 *   spawn(userCmd, args)
 *   spawn(`${req.body.tool}`, args)
 *   spawnSync(cmd, ['-r', file])
 *   child_process.spawn(commandVar, [])
 */
const SPAWN_FUNCTIONS = new Set(['spawn', 'spawnSync']);
/**
 * Returns true only if the node is a static string literal with no dynamic
 * parts — i.e. the command is fully hardcoded and cannot be influenced by
 * external input.
 */
function isStaticCommand(node) {
    if (node.type === 'Literal' && typeof node.value === 'string') {
        return true;
    }
    // A template literal with zero expressions is still static: `ls`
    if (node.type === 'TemplateLiteral') {
        return node.expressions.length === 0;
    }
    return false;
}
function isSpawnCall(callee) {
    // spawn(...) / spawnSync(...)
    if (callee.type === 'Identifier' && SPAWN_FUNCTIONS.has(callee.name)) {
        return callee.name;
    }
    // child_process.spawn(...) / cp.spawnSync(...) / require('child_process').spawn(...)
    if (callee.type === 'MemberExpression' && !callee.computed) {
        const prop = callee.property;
        if (prop.type === 'Identifier' && SPAWN_FUNCTIONS.has(prop.name)) {
            return prop.name;
        }
    }
    return null;
}
function detectCommandInjection(result) {
    const findings = [];
    const reported = new Set();
    (0, utils_1.walkNode)(result.ast, (node) => {
        if (node.type !== 'CallExpression')
            return;
        const call = node;
        const fnName = isSpawnCall(call.callee);
        if (!fnName)
            return;
        if (call.arguments.length === 0)
            return;
        const firstArg = call.arguments[0];
        if (firstArg.type === 'SpreadElement')
            return;
        // Only flag when the command itself (first arg) is dynamic
        if (!isStaticCommand(firstArg)) {
            const line = node.loc.start.line;
            if (!reported.has(line)) {
                reported.add(line);
                findings.push({
                    type: 'COMMAND_INJECTION',
                    severity: 'high',
                    line,
                    column: node.loc.start.column,
                    snippet: (0, utils_1.getSnippet)(result, line),
                    message: `${fnName}() called with a dynamic command. If the command name originates from ` +
                        `user input, an attacker can execute arbitrary programs. Use a hardcoded command ` +
                        `string and pass only sanitized arguments in the args array.`,
                    confidence: 0.88,
                });
            }
        }
    });
    return findings;
}
//# sourceMappingURL=commandInjection.js.map