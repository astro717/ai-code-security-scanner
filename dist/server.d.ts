import http from 'http';
export declare const app: import("express-serve-static-core").Express;
export declare const INTERNAL_API_TOKEN: string | undefined;
/**
 * Resets the in-memory hit counters for both rate limiters.
 * Exported for test use only — do not call in production code.
 * Vitest loads the server module once per process (module cache is shared
 * across test files), so calling this in beforeAll() guarantees a clean
 * slate for each test suite regardless of execution order.
 */
export declare function resetRateLimiters(): Promise<void>;
export declare const server: http.Server<typeof http.IncomingMessage, typeof http.ServerResponse> | null;
//# sourceMappingURL=server.d.ts.map