// Verifies every published digest set in the repository.
//
// A record's CHECKSUMS.sha256 or SHA256SUMS.txt pins the exact bytes of the files it
// lists. This gate reads every such file, resolves each listed path relative to the
// digest file's own directory, recomputes SHA-256 over the exact bytes, and fails on a
// missing file, a malformed line, or a mismatch. It is wired into npm test so a pinned
// file cannot change without the gate failing.
//
// Node builtins only. No shell, no dependencies.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');

const DIGEST_NAMES = new Set(['CHECKSUMS.sha256', 'SHA256SUMS.txt']);
const SKIP_DIRS = new Set(['node_modules', '.git']);

// 64 hex chars, whitespace, optional '*' binary marker, then a relative path.
const LINE = /^([0-9a-fA-F]{64})[ \t]+\*?(.+)$/;

function findDigestFiles(dir, out) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    throw new Error(`cannot read directory ${dir}: ${err.message}`);
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      findDigestFiles(full, out);
    } else if (entry.isFile() && DIGEST_NAMES.has(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

function relPath(p) {
  return relative(ROOT, p).split(sep).join('/');
}

const digestFiles = findDigestFiles(ROOT, []).sort();

if (digestFiles.length === 0) {
  console.error('digest set FAIL: no CHECKSUMS.sha256 or SHA256SUMS.txt found in the repository');
  process.exit(1);
}

let totalEntries = 0;
let failedSets = 0;

for (const digestFile of digestFiles) {
  const base = dirname(digestFile);
  const shown = relPath(digestFile);
  const failures = [];
  let entries = 0;

  const text = readFileSync(digestFile, 'utf8');
  const lines = text.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const line = raw.trim();
    if (line === '') continue;
    if (line.startsWith('#')) continue;

    const m = LINE.exec(line);
    if (!m) {
      failures.push(`line ${i + 1}: malformed, expected 64 hex digits then a path: ${line}`);
      continue;
    }

    const expected = m[1].toLowerCase();
    let listed = m[2].trim();
    if (listed.startsWith('./')) listed = listed.slice(2);

    entries++;
    const target = resolve(base, listed);

    let bytes;
    try {
      const st = statSync(target);
      if (!st.isFile()) {
        failures.push(`${listed}: not a regular file`);
        continue;
      }
      bytes = readFileSync(target);
    } catch (err) {
      failures.push(`${listed}: missing or unreadable (${err.code || err.message})`);
      continue;
    }

    const actual = createHash('sha256').update(bytes).digest('hex');
    if (actual !== expected) {
      failures.push(`${listed}: digest mismatch, listed ${expected}, computed ${actual}`);
    }
  }

  totalEntries += entries;

  if (failures.length > 0) {
    failedSets++;
    console.error(`digest set FAIL: ${shown}`);
    for (const f of failures) console.error(`  ${f}`);
  } else {
    console.log(`digest set OK: ${shown} (${entries} entries)`);
  }
}

if (failedSets > 0) {
  console.error(`digest integrity FAIL: ${failedSets} of ${digestFiles.length} digest sets failed`);
  process.exit(1);
}

console.log(`digest integrity OK: ${digestFiles.length} digest sets, ${totalEntries} entries`);
process.exit(0);
