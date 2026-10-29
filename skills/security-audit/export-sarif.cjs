#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
const TOOL_URI = 'https://github.com/Radexs/security-audit-skill';

function usage() {
  return [
    'Usage:',
    '  node export-sarif.cjs <findings.json> [--output <findings.sarif.json>]',
    '',
    'By default, SARIF is written to stdout. Only confirmed findings are exported.',
  ].join('\n');
}

function parseArgs(argv) {
  let inputPath = null;
  let outputPath = null;

  for (let index = 2; index < argv.length; index += 1) {
    const arg = argv[index];

    if (arg === '--help' || arg === '-h') {
      return { help: true };
    }

    if (arg === '--output' || arg === '-o') {
      const next = argv[index + 1];
      if (!next || next.startsWith('-')) {
        throw new Error('Expected a path after ' + arg + '.');
      }
      outputPath = next;
      index += 1;
      continue;
    }

    if (arg.startsWith('-')) {
      throw new Error('Unknown option: ' + arg);
    }

    if (inputPath) {
      throw new Error('Only one findings file may be supplied.');
    }
    inputPath = arg;
  }

  if (!inputPath) {
    throw new Error(usage());
  }

  return { inputPath, outputPath };
}

function requireText(value, label) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(label + ' must be a non-empty string.');
  }
  return value;
}

function validateConfirmed(record, index) {
  const prefix = 'findings[' + index + ']';
  requireText(record.fingerprint, prefix + '.fingerprint');
  requireText(record.title, prefix + '.title');
  requireText(record.description, prefix + '.description');

  const severity = record.severity && record.severity.overall_severity;
  if (!['informational', 'low', 'medium', 'high', 'critical'].includes(severity)) {
    throw new Error(prefix + '.severity.overall_severity is invalid.');
  }

  if (!Array.isArray(record.trace) || record.trace.length === 0) {
    throw new Error(prefix + '.trace must contain at least one source location.');
  }

  for (const [traceIndex, step] of record.trace.entries()) {
    const tracePrefix = prefix + '.trace[' + traceIndex + ']';
    requireText(step.file, tracePrefix + '.file');
    requireText(step.description, tracePrefix + '.description');
    if (!Number.isInteger(step.line) || step.line < 1) {
      throw new Error(tracePrefix + '.line must be a positive integer.');
    }
  }

  if (!Array.isArray(record.evidence)) {
    throw new Error(prefix + '.evidence must be an array.');
  }

  for (const [evidenceIndex, item] of record.evidence.entries()) {
    const evidencePrefix = prefix + '.evidence[' + evidenceIndex + ']';
    requireText(item.file, evidencePrefix + '.file');
    requireText(item.description, evidencePrefix + '.description');
    if (!Number.isInteger(item.line) || item.line < 1) {
      throw new Error(evidencePrefix + '.line must be a positive integer.');
    }
  }
}

function sarifLevel(severity) {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

function artifactUri(file) {
  const normalized = file.replace(/\\/g, '/').replace(/^\.\//, '');
  return encodeURI(normalized);
}

function physicalLocation(location) {
  return {
    physicalLocation: {
      artifactLocation: { uri: artifactUri(location.file) },
      region: { startLine: location.line },
    },
  };
}

function relatedLocation(id, location, prefix) {
  return {
    id,
    ...physicalLocation(location),
    message: { text: prefix + location.description },
  };
}

function convertToSarif(records) {
  const confirmed = records
    .map((record, index) => ({ record, index }))
    .filter(({ record }) => record.verdict === 'confirmed')
    .sort((left, right) =>
      left.record.fingerprint.localeCompare(right.record.fingerprint),
    );

  const rules = [];
  const ruleIndexes = new Map();
  const results = [];

  for (const { record } of confirmed) {
    const ruleId = record.fingerprint;
    let ruleIndex = ruleIndexes.get(ruleId);

    if (ruleIndex === undefined) {
      ruleIndex = rules.length;
      ruleIndexes.set(ruleId, ruleIndex);
      const severity = record.severity.overall_severity;
      const rule = {
        id: ruleId,
        name: record.title,
        shortDescription: { text: record.title },
        fullDescription: { text: record.description },
        defaultConfiguration: { level: sarifLevel(severity) },
      };
      if (record.remediation && record.remediation.strategy) {
        rule.help = { text: record.remediation.strategy };
      }
      rules.push(rule);
    }

    const trace = record.trace;
    const primary = [...trace].reverse().find((step) => step.kind === 'sink')
      || trace[trace.length - 1];
    const related = [];
    let relatedId = 1;

    for (const step of trace) {
      if (step === primary) continue;
      related.push(relatedLocation(relatedId, step, step.kind + ': '));
      relatedId += 1;
    }

    for (const item of record.evidence) {
      related.push(relatedLocation(relatedId, item, 'Evidence: '));
      relatedId += 1;
    }

    const result = {
      ruleId,
      ruleIndex,
      level: sarifLevel(record.severity.overall_severity),
      message: {
        text: record.title + '\n\n' + record.description,
      },
      locations: [
        {
          ...physicalLocation(primary),
          message: { text: primary.kind + ': ' + primary.description },
        },
      ],
      partialFingerprints: {
        'securityAuditSkill/v1': record.fingerprint,
      },
      properties: {
        rootCause: record.root_cause,
        intendedBehavior: record.intended_behavior,
        likelihood: record.severity.likelihood,
        impact: record.severity.impact,
        confidence: record.confidence,
        conditions: record.conditions,
        remediation: record.remediation,
      },
    };

    if (related.length > 0) {
      result.relatedLocations = related;
    }
    results.push(result);
  }

  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'security-audit-skill',
            informationUri: TOOL_URI,
            rules,
          },
        },
        results,
      },
    ],
  };
}

function main() {
  const args = parseArgs(process.argv);
  if (args.help) {
    process.stdout.write(usage() + '\n');
    return;
  }

  const inputPath = path.resolve(args.inputPath);
  const raw = fs.readFileSync(inputPath, 'utf8');
  let findings;
  try {
    findings = JSON.parse(raw);
  } catch (error) {
    throw new Error('Could not parse ' + args.inputPath + ' as JSON: ' + error.message);
  }

  if (!Array.isArray(findings)) {
    throw new Error('The findings file must contain a JSON array.');
  }

  for (const [index, record] of findings.entries()) {
    if (!record || typeof record !== 'object' || Array.isArray(record)) {
      throw new Error('findings[' + index + '] must be an object.');
    }
    if (!['confirmed', 'needs_validation', 'rejected'].includes(record.verdict)) {
      throw new Error('findings[' + index + '].verdict is not recognized.');
    }
    if (record.verdict === 'confirmed') {
      validateConfirmed(record, index);
    }
  }

  const sarif = convertToSarif(findings);
  const output = JSON.stringify(sarif, null, 2) + '\n';

  if (args.outputPath) {
    const outputPath = path.resolve(args.outputPath);
    if (outputPath === inputPath) {
      throw new Error('Output path must not overwrite the findings file.');
    }
    fs.writeFileSync(outputPath, output, { flag: 'w' });
  } else {
    process.stdout.write(output);
  }

  const skipped = findings.length - sarif.runs[0].results.length;
  process.stderr.write(
    'Exported ' + sarif.runs[0].results.length + ' confirmed finding(s) to SARIF; ' +
    skipped + ' non-confirmed record(s) omitted.\n',
  );
}

try {
  main();
} catch (error) {
  process.stderr.write(error.message + '\n');
  process.exitCode = 1;
}
