import { NONE_KEYWORD, SOURCE_KEYWORDS } from "./vocabulary.js";
const QUOTED_RE = /^'[^']*'$/;
const NONCE_RE = /^'nonce-([A-Za-z0-9+/_-]+=*)'$/i;
const HASH_RE = /^'(sha256|sha384|sha512)-([A-Za-z0-9+/_-]+=*)'$/i;
const SCHEME_ONLY_RE = /^([a-z][a-z0-9+.-]*):$/i;
const HOST_RE = /^(?:([a-z][a-z0-9+.-]*):\/\/)?(\*|(?:\*\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::([0-9]+|\*))?(\/[^\s]*)?$/i;
const REPORT_TO_TOKEN_RE = /^[A-Za-z0-9_-]+$/;
const DIGEST_BYTES = {
    sha256: 32,
    sha384: 48,
    sha512: 64,
};
/**
 * Byte length of a hash-source digest, or null if it isn't decodable. CSP accepts both
 * the base64 and base64url alphabets (even mixed), and padding is optional.
 */
function decodedDigestLength(value) {
    const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
    try {
        return Uint8Array.fromBase64(base64, { lastChunkHandling: "loose" }).byteLength;
    }
    catch {
        return null;
    }
}
export function classifySource(token, directiveName) {
    if (directiveName === "report-uri") {
        return {
            source: { raw: token, kind: "uri" },
            errors: [],
            warnings: [],
        };
    }
    if (directiveName === "report-to") {
        if (REPORT_TO_TOKEN_RE.test(token)) {
            return {
                source: { raw: token, kind: "token" },
                errors: [],
                warnings: [],
            };
        }
        return {
            source: { raw: token, kind: "unknown" },
            errors: [
                {
                    code: "invalid-source-syntax",
                    level: "error",
                    message: `Invalid group name "${token}" in "report-to".`,
                    directive: directiveName,
                    source: token,
                },
            ],
            warnings: [],
        };
    }
    if (token === "*") {
        return {
            source: { raw: token, kind: "host", host: "*" },
            errors: [],
            warnings: [
                {
                    code: "wildcard-source",
                    level: "warning",
                    message: `Wildcard '*' in "${directiveName}" allows any origin.`,
                    directive: directiveName,
                    source: token,
                },
            ],
        };
    }
    if (QUOTED_RE.test(token)) {
        return classifyQuoted(token, directiveName);
    }
    const schemeMatch = SCHEME_ONLY_RE.exec(token);
    if (schemeMatch) {
        return {
            source: {
                raw: token,
                kind: "scheme",
                scheme: schemeMatch[1].toLowerCase(),
            },
            errors: [],
            warnings: [],
        };
    }
    const hostMatch = HOST_RE.exec(token);
    if (hostMatch) {
        return {
            source: buildHostSource(token, hostMatch),
            errors: [],
            warnings: [],
        };
    }
    return {
        source: { raw: token, kind: "unknown" },
        errors: [
            {
                code: "invalid-source-syntax",
                level: "error",
                message: `Invalid source value "${token}" in "${directiveName}".`,
                directive: directiveName,
                source: token,
            },
        ],
        warnings: [],
    };
}
function classifyQuoted(token, directiveName) {
    const lower = token.toLowerCase();
    if (lower.startsWith("'nonce-")) {
        const match = NONCE_RE.exec(token);
        if (match) {
            return {
                source: { raw: token, kind: "nonce", value: match[1] },
                errors: [],
                warnings: [],
            };
        }
        return {
            source: { raw: token, kind: "nonce" },
            errors: [
                {
                    code: "invalid-nonce",
                    level: "error",
                    message: `Malformed nonce "${token}" in "${directiveName}".`,
                    directive: directiveName,
                    source: token,
                },
            ],
            warnings: [],
        };
    }
    if (lower.startsWith("'sha256-") ||
        lower.startsWith("'sha384-") ||
        lower.startsWith("'sha512-")) {
        const match = HASH_RE.exec(token);
        if (match) {
            const algorithm = match[1].toLowerCase();
            const value = match[2];
            const digestBytes = decodedDigestLength(value);
            const expectedBytes = DIGEST_BYTES[algorithm];
            return {
                source: { raw: token, kind: "hash", algorithm, value },
                errors: [],
                warnings: digestBytes === expectedBytes
                    ? []
                    : [
                        {
                            code: "hash-length-mismatch",
                            level: "warning",
                            message: digestBytes === null
                                ? `Hash "${token}" in "${directiveName}" is not valid base64, so it can never match.`
                                : `Hash "${token}" in "${directiveName}" decodes to ${digestBytes} bytes, but a ${algorithm} digest is ${expectedBytes} bytes, so it can never match.`,
                            directive: directiveName,
                            source: token,
                        },
                    ],
            };
        }
        return {
            source: { raw: token, kind: "hash" },
            errors: [
                {
                    code: "invalid-hash",
                    level: "error",
                    message: `Malformed hash "${token}" in "${directiveName}".`,
                    directive: directiveName,
                    source: token,
                },
            ],
            warnings: [],
        };
    }
    if (lower === NONE_KEYWORD) {
        return {
            source: { raw: token, kind: "none", keyword: NONE_KEYWORD },
            errors: [],
            warnings: [],
        };
    }
    if (SOURCE_KEYWORDS.has(lower)) {
        const warnings = [];
        if (lower === "'unsafe-inline'") {
            warnings.push({
                code: "unsafe-inline",
                level: "warning",
                message: `'unsafe-inline' weakens "${directiveName}".`,
                directive: directiveName,
                source: token,
            });
        }
        else if (lower === "'unsafe-eval'") {
            warnings.push({
                code: "unsafe-eval",
                level: "warning",
                message: `'unsafe-eval' weakens "${directiveName}".`,
                directive: directiveName,
                source: token,
            });
        }
        return {
            source: { raw: token, kind: "keyword", keyword: lower },
            errors: [],
            warnings,
        };
    }
    return {
        source: { raw: token, kind: "unknown" },
        errors: [],
        warnings: [
            {
                code: "unknown-source-keyword",
                level: "warning",
                message: `Unknown keyword ${token} in "${directiveName}".`,
                directive: directiveName,
                source: token,
            },
        ],
    };
}
function buildHostSource(token, match) {
    const scheme = match[1];
    const host = match[2];
    const port = match[3];
    const path = match[4];
    const base = { raw: token, kind: "host", host: host.toLowerCase() };
    if (scheme !== undefined) {
        base.scheme = scheme.toLowerCase();
    }
    if (port !== undefined) {
        base.port = port;
    }
    if (path !== undefined) {
        base.path = path;
    }
    return base;
}
