#!/usr/bin/env node
import fs from 'node:fs';
import { verifyAuraPackage } from '../src/verify-node.js';
import { formatHumanResult } from '../src/report.js';
import { createRfc3161TimestampQuery, verifyRfc3161Timestamp } from '../src/verify-timestamp-node.js';

function usage() {
  return `Usage:
  aura timestamp-request --manifest <manifest.json> --out <request.tsq>
  aura verify --manifest <manifest.json> --public-key <public-key.pem> [--asset <file>] [--issuer <issuer.json>] [--json]

  Optional detached RFC 3161: --timestamp-response <response.tsr> --tsa-ca <trusted-root.pem>
    [--tsa-untrusted <tsa-chain.pem>] [--timestamp-query <original-request.tsq>]
    The response must cover SHA-256(JCS(full signed manifest)), including its Ed25519 signature.

  --asset is optional. Omit it to verify a catalog claim (a signed catalogue
  declaration with an issuer-declared issuance time, issued without a supplied
  asset file): the signature and issuer are checked, the issuance time is read
  from the signed payload, and asset integrity is reported as N/A.
`;
}

function parseArgs(argv) {
  const args = { json: false };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--json') {
      args.json = true;
      continue;
    }

    if (arg.startsWith('--')) {
      const value = argv[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error(`Missing value for ${arg}`);
      }
      args[arg.slice(2)] = value;
      i += 1;
    }
  }

  return args;
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);

  if (command !== 'verify' && command !== 'timestamp-request') {
    console.error(usage());
    process.exitCode = 2;
    return;
  }

  try {
    const args = parseArgs(rest);
    if (command === 'timestamp-request') {
      if (!args.manifest || !args.out) throw new Error('timestamp-request requires --manifest and --out.');
      const request = createRfc3161TimestampQuery({ manifestPath: args.manifest, requestPath: args.out });
      console.log(JSON.stringify(request, null, 2));
      return;
    }
    if (!args.manifest || !args['public-key']) {
      throw new Error('Missing required --manifest or --public-key argument.');
    }

    const result = await verifyAuraPackage({
      assetBytes: args.asset ? fs.readFileSync(args.asset) : null,
      manifestText: fs.readFileSync(args.manifest, 'utf8'),
      publicKeyPem: fs.readFileSync(args['public-key'], 'utf8'),
      issuerText: args.issuer ? fs.readFileSync(args.issuer, 'utf8') : null,
    });

    const wantsTimestamp = ['timestamp-response', 'tsa-ca', 'tsa-untrusted', 'timestamp-query'].some((key) => args[key]);
    if (wantsTimestamp && (!args['timestamp-response'] || !args['tsa-ca'])) {
      throw new Error('RFC 3161 requires both --timestamp-response and --tsa-ca.');
    }
    result.timestamp = wantsTimestamp ? verifyRfc3161Timestamp({
      manifestPath: args.manifest,
      responsePath: args['timestamp-response'],
      caPath: args['tsa-ca'],
      untrustedPath: args['tsa-untrusted'] || null,
      queryPath: args['timestamp-query'] || null,
    }) : { status: 'not_provided', qualifiedEidas: 'not_assessed' };
    result.auraTimestampedChecks = result.signatureOk && result.status !== 'invalid' && result.timestamp.status === 'verified'
      ? 'technical_checks_passed' : 'not_established';
    if (result.timestamp.status === 'invalid') {
      result.errors.push('RFC 3161 verification failed: ' + result.timestamp.error);
      result.status = 'invalid';
      result.valid = false;
    }

    if (args.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(formatHumanResult(result));
      console.log('');
      console.log('RFC 3161 timestamp: ' + result.timestamp.status);
      if (result.timestamp.genTime) console.log('TSA genTime: ' + result.timestamp.genTime);
      console.log('AURA-Timestamped technical checks: ' + result.auraTimestampedChecks);
      console.log('Qualified eIDAS status: not assessed');
    }

    process.exitCode = result.status === 'valid' ? 0 : result.status === 'warning' ? 1 : 2;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`AURA verification failed: ${message}`);
    process.exitCode = 2;
  }
}

await main();
