# npm distribution

Package name: `aura-verifier`. Command: `aura`. Node.js 20 or newer is required.
The registry package is not published yet. Its availability must be confirmed
on [npm](https://www.npmjs.com/package/aura-verifier) before announcing it.

## Install a prepared tarball

Download the `npm-package` artifact from a successful GitHub Actions run for
the commit being reviewed. It contains the tarball, its SHA-256 checksum,
package inventory and installation-test results. After checking the checksum:

```sh
npm install --global ./aura-verifier-1.2.2.tgz
aura verify --manifest manifest.json --public-key public-key.pem \
  --asset recording.wav --issuer issuer.json --json
```

The four paths are locally supplied evidence, not files fetched by the tool.
Exit codes remain 0 for valid, 1 for warnings/incomplete checks, and 2 for an
invalid report or input error. A valid report is not proof of ownership or
identity. See [integrator limits](../INTEGRATORS.md).

Once version 1.2.2 is actually published, registry installation will be:

```sh
npm install --global aura-verifier@1.2.2
```

No runtime npm dependencies or installation scripts are required. Optional
RFC 3161 commands require OpenSSL 3.x on PATH; ordinary verification does not.
Installation can contact npm, but local verification does not upload evidence.

For `--tsa-untrusted`, OpenSSL interprets whitespace as a filename separator.
Use a path without spaces, for example a relative path to `tsa.crt` from its
parent directory. Shell quoting alone does not fix this OpenSSL limitation.
Ordinary asset/manifest paths can contain spaces when quoted in the shell.

## Package contents and compatibility

The explicit `files` list in `package.json` includes the CLI, verification
modules, browser interface, documentation and the public fictional timestamp
example. npm also includes the package metadata, README and MIT license.
Development dependencies, regression tests, GitHub workflows and unrelated
working files are excluded. Run repository test/development commands from a
checkout, not from the installed package.

This is the first npm distribution of verifier 1.2.2. Its `bin/`, `src/` and
`web/` files are unchanged from release commit
`08d7c70404bab16e2e3b09bb9e59aefaf6fa5391`. Packaging metadata and documentation
were prepared subsequently. The npm tarball is therefore not the byte-identical
Zenodo archive; preserve the published tag and archive. AURA-STANDARD and the
supported manifest schemas 1.0 and 1.1 are unchanged.

## Reproduce packaging checks

From a repository checkout with Node.js and npm:

```sh
npm test
npm run test:timestamp
npm run test:package
```

The package check packs the repository, installs that tarball into a new
temporary directory with npm offline and installation scripts disabled, and
executes the installed command outside the source checkout. It checks valid
evidence, modified bytes, modified signed declarations, missing evidence and
malformed JSON, plus the installed Node and WebCrypto modules. It compares
installed runtime bytes to the checkout and rejects unexpected package files.

With OpenSSL 3.x, set `AURA_NPM_TEST_TIMESTAMP=1` to check the installed CLI
against the bundled real timestamp response. Set `AURA_NPM_ARTIFACT_DIR=dist`
to retain the tested tarball, inventory, results and checksum. CI performs both
checks on Node.js 20, 22 and 24. No test creates a real timestamp request to a
remote service or publishes to npm.

## First publication

The maintainer needs an npm account, a verified email and the authentication
required by npm. No npm credential belongs in this repository. Confirm the
package name is available and that the intended account will own it.

Publish only the exact tarball produced and tested for the reviewed commit.
After publication, install `aura-verifier@1.2.2` in a new directory, compare
the registry tarball checksum with the tested artifact, rerun the example,
and update the availability notice above and in the README.

There is no automatic publishing workflow in this change. Subsequent releases
can use [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/)
after the npm account and package ownership are established. A later change to
an already published npm package requires a new package version.
