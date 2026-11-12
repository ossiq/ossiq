// escape-string-regexp 4 exports the function itself; 5 is an ES module whose function is `default`.
const semver = require('semver');
const escapeStringRegexp = require('escape-string-regexp');

if (!semver.valid('1.2.3')) throw new Error('semver is broken');
if (escapeStringRegexp('a.b') !== 'a\\.b') throw new Error('escape-string-regexp is broken');
console.log('ok');
