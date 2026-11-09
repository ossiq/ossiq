// The same checks, written to work with both the CommonJS and the ES module release.
const semver = require('semver');
const loaded = require('escape-string-regexp');
const escapeStringRegexp = loaded.default || loaded;

if (!semver.valid('1.2.3')) throw new Error('semver is broken');
if (escapeStringRegexp('a.b') !== 'a\\.b') throw new Error('escape-string-regexp is broken');
console.log('ok');
