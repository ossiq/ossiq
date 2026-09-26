// Plain require() on purpose: an ESM-only upgrade of chalk or uuid must fail here.
const assert = require("node:assert");
const lib = require("./index.js");

assert.ok(lib.banner("hi").includes("hi"));
assert.strictEqual(lib.stamp(), "2026-01-01");
assert.deepStrictEqual(lib.pick({ a: 1, b: 2 }, ["a"]), { a: 1 });
assert.strictEqual(lib.query({ a: 1 }), "a=1");
assert.ok(lib.newer("2.0.0", "1.0.0"));
assert.match(lib.id(), /^[0-9a-f-]{36}$/);
console.log("ok");
