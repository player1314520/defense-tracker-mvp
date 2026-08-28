const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

function read(relativePath) {
  return fs.readFileSync(path.resolve(__dirname, '../..', relativePath), 'utf8');
}

const brief = read('static/js/brief.js');
const agent = read('static/js/agent.js');
const ai = read('static/js/ai.js');
const commandHub = read('static/js/command-hub-v9.js');
const thinktanks = read('static/js/thinktanks.js');
const china = read('static/js/china.js');
const news = read('static/js/news.js');

assert.match(brief, /link:\s*safeExternalUrl\(article\.link\)/);
assert.match(brief, /href="\$\{escHtml\(safeExternalUrl\(r\.article\.link\)\)\}"/);
assert.match(agent, /href="\$\{escHtml\(safeExternalUrl\(ev\.link\)\)\}"/);
assert.match(ai, /const url = article \? safeExternalUrl\(article\.link\) : '#';/);
assert.match(ai, /window\.open\(url, '_blank', 'noopener,noreferrer'\)/);
assert.match(commandHub, /safeExternalUrl\(item\.url\)/);
assert.match(commandHub, /safeExternalUrl\(provenance\.url\)/);
assert.match(thinktanks, /safeExternalUrl\(site\.url\)/);
assert.match(china, /safeExternalUrl\(item\.link\)/);
assert.match(china, /safeExternalUrl\(site\.url\)/);
assert.match(news, /safeExternalUrl\(item\.link\)/);

for (const [name, source] of [
  ['brief.js', brief],
  ['agent.js', agent],
  ['ai.js', ai],
  ['command-hub-v9.js', commandHub],
  ['thinktanks.js', thinktanks],
  ['china.js', china],
  ['news.js', news],
]) {
  assert.doesNotMatch(
    source,
    /href="\$\{escHtml\((?:ev|article|asset|src|r\.article)\.(?:link|url)\)\}"/,
    `${name} must not interpolate an unvalidated source URL into href`,
  );
}

console.log('source URL security contract tests passed');
