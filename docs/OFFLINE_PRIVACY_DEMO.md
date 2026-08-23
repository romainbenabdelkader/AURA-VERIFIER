# Local And Offline Verification Demonstration

This non-normative demonstration shows that AURA cryptographic verification can
complete with locally supplied evidence and trust material while network access
is blocked.

## Run

Requirements: Node.js 20 or later.

```bash
npm run demo:offline
```

The command:

1. generates an ephemeral Ed25519 key pair in memory;
2. creates and signs an AURA v1.1 test manifest in memory;
3. disables network access through the runtime `fetch` interface;
4. verifies the same local package with the Node and browser verification engines;
5. confirms that no network request occurred;
6. confirms that modified signed content is rejected;
7. confirms that modified asset bytes are rejected.

No private key, manifest, asset or verification event is transmitted or written to
disk by the demonstration.

## Scope

This demonstrates local cryptographic verification behavior in the published
verifier. It does not establish the civil identity or legal authority of the
ephemeral issuer, and it is not a certification of a deployment.

A locally supplied registry snapshot can also be evaluated without a network
request. Its status and revocation information are only as current as the snapshot.

The web interface additionally supports optional remote convenience loading. That
mode is not offline and contacted servers may create ordinary access logs. For a
privacy-sensitive pilot, open the verifier without remote-loading parameters and
supply the asset, manifest, public key and optional issuer metadata as local files.
