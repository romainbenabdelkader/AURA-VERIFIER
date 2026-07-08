#!/usr/bin/env node
import fs from 'node:fs';
import { verifyAuraPackage } from '../src/verify-node.js';
import { formatHumanResult } from '../src/report.js';

function usage() {
  return `Usage:
  aura verify --manifest <manifest.json> --public-key <public-key.pem> [--asset <file>] [--issuer <issuer.json>] [--json]

  --asset is optional. Omit it to verify a catalog claim (a signed, timestamped
  catalogue declaration issued without a supplied asset file): the signature,
  issuer and timestamp are checked, and asset integrity is reported as N/A.
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

  if (command !== 'verify') {
    console.error(usage());
    process.exitCode = 2;
    return;
  }

  try {
    const args = parseArgs(rest);
    if (!args.manifest || !args['public-key']) {
      throw new Error('Missing required --manifest or --public-key argument.');
    }

    const result = await verifyAuraPackage({
      assetBytes: args.asset ? fs.readFileSync(args.asset) : null,
      manifestText: fs.readFileSync(args.manifest, 'utf8'),
      publicKeyPem: fs.readFileSync(args['public-key'], 'utf8'),
      issuerText: args.issuer ? fs.readFileSync(args.issuer, 'utf8') : null,
    });

    if (args.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(formatHumanResult(result));
    }

    process.exitCode = result.status === 'valid' ? 0 : result.status === 'warning' ? 1 : 2;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`AURA verification failed: ${message}`);
    process.exitCode = 2;
  }
}

await main();
