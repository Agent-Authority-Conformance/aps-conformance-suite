// Independent adapter for the EMILIA cross-slot composition conformance pack.
// Written from scratch against the published bytes in ../../corpus/. Node
// builtins only: no third-party packages, and no code from the upstream runner.
//
// The pack's runner performs fourteen named join checks per case. Their
// semantics are reimplemented here from the published bundle and the pack's
// mechanism document. Nothing profile-native is evaluated; see SCOPE.md.

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

type Json = any;
type Status = 'pass' | 'fail' | 'not_evaluated' | 'unsupported' | 'indeterminate';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..', '..');
const PACK = resolve(ROOT, 'corpus', 'examples', 'composition', 'cross-slot-conformance-v1');
const OUT = process.env.OUT_DIR ? resolve(process.env.OUT_DIR) : ROOT;

const VOCABULARY: ReadonlySet<Status> = new Set<Status>([
  'pass', 'fail', 'not_evaluated', 'unsupported', 'indeterminate',
]);

// Canonicalization used by the pack: recursive key sort, then compact JSON.
// Object.keys().sort() orders by UTF-16 code unit, which is what the pack's
// declared digest context labels as its serialization.
function sortJson(value: Json): Json {
  if (Array.isArray(value)) return value.map(sortJson);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((k) => [k, sortJson(value[k])]));
  }
  return value;
}

function canonical(value: Json): string {
  return JSON.stringify(sortJson(value));
}

function sha256(value: string | Buffer): string {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function clone(value: Json): Json {
  return JSON.parse(JSON.stringify(value));
}

function check(id: string, status: Status, detail: string): Json {
  return { id, status, detail };
}

// ---- the fourteen join checks ----

function artifactBytes(b: Json): Json {
  const failures: string[] = [];
  for (const [name, entry] of Object.entries(b.slots) as Array<[string, Json]>) {
    const bytes = Buffer.from(entry.artifact.bytes_b64u, 'base64url');
    if (sha256(bytes) !== entry.artifact.sha256) failures.push(name);
  }
  return check('bundle.artifact_bytes', failures.length === 0 ? 'pass' : 'fail',
    failures.length === 0
      ? 'all native artifact bytes match their pinned digests'
      : `artifact digest mismatch: ${failures.join(',')}`);
}

function subjectBytes(b: Json): Json {
  const bytes = Buffer.from(b.subject.action_artifact.bytes_b64u, 'base64url');
  const digestOk = sha256(bytes) === b.subject.action_digest;
  const contentOk = bytes.equals(Buffer.from(canonical(b.subject.action)));
  return check('subject.action_bytes', digestOk && contentOk ? 'pass' : 'fail',
    'supplied action bytes must match both the visible action and pinned digest');
}

function digestContext(b: Json): Json {
  const compatible = (v: Json): string => {
    const copy = clone(v);
    delete copy.representation;
    return canonical(copy);
  };
  const expected = compatible(b.subject.digest_context);
  const bad = Object.values(b.slots).filter(
    (e: Json) => compatible(e.subject.digest_context) !== expected);
  return check('join.digest_context', bad.length === 0 ? 'pass' : 'indeterminate',
    bad.length === 0
      ? 'all slots declare the same digest context'
      : 'at least one slot uses an incompatible profile or action projection');
}

function representation(b: Json): Json {
  const expected = b.subject.digest_context.representation;
  const mismatch = Object.values(b.slots).some(
    (e: Json) => e.subject.digest_context.representation !== expected);
  return check('join.digest_representation', mismatch ? 'fail' : 'pass',
    mismatch ? 'declared digest representations differ' : 'digest representation matches');
}

function crossReferences(b: Json): Json {
  let mismatch = false;
  for (const entry of Object.values(b.slots) as Json[]) {
    const ref = entry.protected_cross_reference;
    const target = b.slots[ref.target_slot];
    if (!target || target.artifact.sha256 !== ref.artifact_digest) mismatch = true;
  }
  return check('join.protected_cross_reference', mismatch ? 'fail' : 'pass',
    mismatch
      ? 'protected cross-reference does not identify supplied target bytes'
      : 'all protected cross-references match supplied target bytes');
}

function additionalBindingContext(b: Json): Json {
  const incomplete = Object.values(b.slots)
    .flatMap((e: Json) => e.additional_bindings)
    .some((x: Json) => typeof x.purpose !== 'string'
      || typeof x.context !== 'string'
      || typeof x.digest !== 'string');
  return check('join.additional_binding_context', incomplete ? 'fail' : 'pass',
    incomplete
      ? 'an additional binding is missing purpose, context, or digest'
      : 'additional bindings carry complete declared context');
}

function bindingSemantics(b: Json): Json {
  const bindings = Object.values(b.slots).flatMap((e: Json) => e.additional_bindings);
  const unmet = b.policy.required_binding_purposes.some((purpose: string) => {
    const matches = bindings.filter((x: Json) => x.purpose === purpose);
    return matches.length === 0 || matches.every((x: Json) => x.understood !== true);
  });
  return {
    ...check('policy.binding_semantics', unmet ? 'unsupported' : 'pass',
      unmet
        ? 'binding is structurally readable but cannot satisfy policy requiring understood semantics'
        : 'every policy-required binding purpose has understood semantics'),
    binding_state: unmet ? 'present_uninterpreted' : 'understood',
  };
}

function fieldBasis(b: Json): Json {
  const missing = Object.values(b.slots).some((e: Json) => Object.values(e.fields).some(
    (f: Json) => typeof f.basis !== 'string' || f.basis.length === 0));
  return check('join.field_basis', missing ? 'indeterminate' : 'pass',
    missing ? 'joined field basis is absent' : 'joined fields declare their bases');
}

function fieldMapping(b: Json, basis: Json): Json {
  if (basis.status !== 'pass') {
    return check('join.field_mapping', 'not_evaluated',
      'field mapping was not evaluated because a joined field lacks a declared basis');
  }
  const bases = [...new Set(Object.values(b.slots).map((e: Json) => e.fields.amount.basis))];
  if (bases.length <= 1) return check('join.field_mapping', 'pass', 'joined amount bases match');
  const mapped = b.mappings.some((m: Json) => {
    const pair = new Set([m.from_basis, m.to_basis]);
    return bases.every((x) => pair.has(x));
  });
  return check('join.field_mapping', mapped ? 'pass' : 'indeterminate',
    mapped ? 'incompatible bases have a pinned mapping' : 'incompatible bases lack a pinned mapping');
}

function resultSeparation(b: Json): Json {
  return check('report.result_separation',
    b.reporting.native_results_separate === true ? 'pass' : 'fail',
    'native slot and cross-slot results must remain separately named');
}

function resultPreservation(b: Json): Json {
  return check('report.result_preservation',
    b.reporting.composition_overrides_native === false ? 'pass' : 'fail',
    'composition must not upgrade, weaken, or overwrite a native result');
}

function exactAction(b: Json): Json {
  const mismatch = Object.values(b.slots).some(
    (e: Json) => e.subject.action_digest !== b.subject.action_digest);
  return check('join.exact_action', mismatch ? 'fail' : 'pass',
    mismatch
      ? 'populated slots do not identify the same exact action'
      : 'all populated slots identify the same exact action');
}

function notEvaluatedPreservation(b: Json): Json {
  const mismatch = Object.entries(b.slots).some(([name, e]: [string, Json]) => (
    e.native_result === 'not_evaluated'
    && b.reporting.reported_native_results[name] !== 'not_evaluated'));
  return check('report.not_evaluated_preservation', mismatch ? 'fail' : 'pass',
    mismatch
      ? 'not_evaluated native result was relabeled as a verifier failure'
      : 'not_evaluated native results remain not_evaluated');
}

function requiredProfiles(b: Json): Json {
  const supported = new Set(b.policy.supported_profiles);
  const unknown = b.policy.required_profiles.filter((p: string) => !supported.has(p));
  return check('policy.required_profile', unknown.length === 0 ? 'pass' : 'unsupported',
    unknown.length === 0
      ? 'all required profiles are supported'
      : `unsupported required profiles: ${unknown.join(',')}`);
}

function terminalStatus(results: Json[]): Status {
  const seen = results.map((r) => r.status as Status);
  for (const candidate of ['fail', 'unsupported', 'indeterminate', 'not_evaluated'] as Status[]) {
    if (seen.includes(candidate)) return candidate;
  }
  return 'pass';
}

// ---- evaluation ----

function evaluateCase(item: Json): Json {
  const bundle = item.input;
  const basis = fieldBasis(bundle);
  const results = [
    artifactBytes(bundle),
    subjectBytes(bundle),
    digestContext(bundle),
    representation(bundle),
    crossReferences(bundle),
    additionalBindingContext(bundle),
    bindingSemantics(bundle),
    basis,
    fieldMapping(bundle, basis),
    resultSeparation(bundle),
    resultPreservation(bundle),
    exactAction(bundle),
    notEvaluatedPreservation(bundle),
    requiredProfiles(bundle),
  ];
  const bad = results.find((r) => !VOCABULARY.has(r.status));
  if (bad) throw new Error(`invalid result vocabulary: ${bad.status}`);
  const primary = results.find((r) => r.status !== 'pass');
  const nativeResults = (Object.entries(bundle.slots) as Array<[string, Json]>).map(
    ([name, e]) => ({
      slot: name,
      profile: e.profile,
      artifact_digest: e.artifact.sha256,
      native_result: e.native_result,
      reported_result: bundle.reporting.reported_native_results[name],
    }));
  return {
    case_id: item.id,
    pair_id: item.pair_id,
    variant: item.variant,
    native_results: nativeResults,
    join_results: results,
    primary_check: primary?.id ?? 'composition.complete',
    terminal: terminalStatus(results),
    binding_state: results.find((r) => r.id === 'policy.binding_semantics')?.binding_state,
    crashed: false,
  };
}

function compare(item: Json, observed: Json): Json {
  const joinObserved = Object.fromEntries(observed.join_results.map((r: Json) => [r.id, r.status]));
  const nativeObserved = Object.fromEntries(
    observed.native_results.map((r: Json) => [r.slot, r.native_result]));
  return {
    id: item.id,
    pair_id: item.pair_id,
    variant: item.variant,
    expected_terminal: item.expected_terminal,
    expected_check: item.expected_check,
    actual_terminal: observed.terminal,
    actual_check: observed.primary_check,
    terminal_match: observed.terminal === item.expected_terminal,
    check_match: observed.primary_check === item.expected_check,
    native_results_match: canonical(nativeObserved) === canonical(item.expected_native_results),
    join_results_match: canonical(joinObserved) === canonical(item.expected_join_results),
    no_crash: observed.crashed === false,
    passed: observed.terminal === item.expected_terminal
      && observed.primary_check === item.expected_check
      && canonical(nativeObserved) === canonical(item.expected_native_results)
      && canonical(joinObserved) === canonical(item.expected_join_results)
      && observed.crashed === false,
  };
}

function main(): void {
  const bundleBytes = readFileSync(resolve(PACK, 'bundle.json'));
  const manifestBytes = readFileSync(resolve(PACK, 'manifest.json'));
  const bundle = JSON.parse(bundleBytes.toString('utf8'));
  const manifest = JSON.parse(manifestBytes.toString('utf8'));

  const evaluated = bundle.cases.map((item: Json) => evaluateCase(item));
  const checks = bundle.cases.map((item: Json, i: number) => compare(item, evaluated[i]));
  const passedAll = checks.every((c: Json) => c.passed);

  const toolchain = `node ${process.version}`;

  // Deterministic run record. Carries no timestamp, so two runs are byte-identical.
  const results = {
    '@version': 'AAC-COMPOSITION-CROSS-SLOT-RUN-v1',
    adapter: 'ts',
    toolchain,
    composition_pin: manifest.composition.revision,
    manifest_digest: sha256(canonical(manifest)),
    bundle_digest: sha256(canonical(bundle)),
    manifest_file_digest: sha256(manifestBytes),
    bundle_file_digest: sha256(bundleBytes),
    case_count: bundle.cases.length,
    passed: passedAll,
    reproduced: checks.filter((c: Json) => c.passed).length,
    checks,
    results: evaluated,
  };
  writeFileSync(resolve(OUT, 'results-ts.json'), `${JSON.stringify(results, null, 1)}\n`);

  // Adapter-neutral canonical record. Both adapters write this file and the
  // bytes must be identical, so it carries no toolchain and no adapter name.
  const canonicalResults = {
    '@version': 'AAC-COMPOSITION-CROSS-SLOT-RESULTS-v1',
    composition_pin: manifest.composition.revision,
    manifest_digest: sha256(canonical(manifest)),
    bundle_digest: sha256(canonical(bundle)),
    case_count: bundle.cases.length,
    reproduced: checks.filter((c: Json) => c.passed).length,
    vocabulary: bundle.result_vocabulary,
    rows: checks.map((c: Json) => ({
      id: c.id,
      variant: c.variant,
      expected_terminal: c.expected_terminal,
      expected_check: c.expected_check,
      observed_terminal: c.actual_terminal,
      observed_check: c.actual_check,
      result: c.passed ? 'reproduced' : 'divergent',
    })),
  };
  writeFileSync(resolve(OUT, 'results.json'), `${JSON.stringify(canonicalResults, null, 1)}\n`);

  // Their external report template, filled. Keys and order exactly as published.
  const adapterDigest = sha256(readFileSync(resolve(HERE, 'run.ts')));
  const report: Json = {
    '@version': 'EP-COMPOSITION-CROSS-SLOT-EXTERNAL-REPORT-v1',
    status: 'AWAITING_INDEPENDENT_RUN',
    implementation: 'Agent Authority Conformance lab adapter (TypeScript)',
    implementation_owner: 'Agent Authority Conformance, LF Decentralized Trust lab',
    implementation_revision: adapterDigest,
    manifest_digest: sha256(canonical(manifest)),
    bundle_digest: sha256(canonical(bundle)),
    report_digest: null,
    per_case_results: checks,
    known_shared_dependencies: [],
    execution_date: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    toolchain,
    signed_by: null,
  };
  report.report_digest = sha256(canonical({ ...report, report_digest: undefined }));
  writeFileSync(resolve(OUT, 'external-report-ts.json'), `${JSON.stringify(report, null, 2)}\n`);

  process.stdout.write(`cases ${bundle.cases.length}, reproduced ${results.reproduced}, passed ${passedAll}\n`);
}

main();
