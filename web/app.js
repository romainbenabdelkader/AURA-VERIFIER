import { verifyAuraPackageBrowser } from '../src/verify-web.js';

const resultEl = document.querySelector('#result');

async function readText(file) {
  if (!file) return null;
  return file.text();
}

async function readBytes(file) {
  if (!file) return null;
  return file.arrayBuffer();
}

function statusTitle(status) {
  if (status === 'valid') return 'Valid evidence package';
  if (status === 'warning') return 'Verification warning';
  return 'Invalid evidence package';
}

function render(result) {
  resultEl.className = `result status-${result.status}`;
  resultEl.innerHTML = `
    <h2>${statusTitle(result.status)}</h2>
    <p>This verifies integrity, signature and timestamped declaration. It does not adjudicate ownership, authorship, licensing or infringement.</p>
    <div>
      <span class="badge">Signature ${result.signatureOk ? 'valid' : 'invalid'}</span>
      <span class="badge">Asset integrity ${result.assetHashOk ? 'valid' : 'invalid'}</span>
      <span class="badge">Status ${result.status}</span>
    </div>
    <pre>${escapeHtml(JSON.stringify(result, null, 2))}</pre>
  `;
}

function renderError(error) {
  resultEl.className = 'result status-invalid';
  resultEl.innerHTML = `
    <h2>Verification failed</h2>
    <pre>${escapeHtml(error instanceof Error ? error.message : String(error))}</pre>
  `;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

document.querySelector('#verify').addEventListener('click', async () => {
  try {
    const asset = document.querySelector('#asset').files[0];
    const manifest = document.querySelector('#manifest').files[0];
    const publicKey = document.querySelector('#publicKey').files[0];
    const issuer = document.querySelector('#issuer').files[0];

    if (!asset || !manifest || !publicKey) {
      throw new Error('Choose an asset file, a manifest JSON file, and a public key PEM file.');
    }

    render(
      await verifyAuraPackageBrowser({
        assetBytes: await readBytes(asset),
        manifestText: await readText(manifest),
        publicKeyPem: await readText(publicKey),
        issuerText: issuer ? await readText(issuer) : null,
      }),
    );
  } catch (error) {
    renderError(error);
  }
});
