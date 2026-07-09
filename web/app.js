import { verifyAuraPackageBrowser } from '../src/verify-web.js';
import { pemToDer } from '../src/pem.js';
import { sha3_256_hex } from '../src/sha3.js';

const resultEl = document.querySelector('#result');
const bannerEl = document.querySelector('#sourceBanner');

// Convenience state populated by ?uid= / ?manifest=. A local file always
// overrides it. Verification is never run against these directly without the
// user's own key material or a manifest-pinned, digest-checked key.
const loaded = {
  manifestText: null,
  manifestSource: null,
  publicKeyPem: null,
  keySource: null,
};

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

async function readText(file) {
  return file ? file.text() : null;
}

async function readBytes(file) {
  return file ? file.arrayBuffer() : null;
}

// ---- ?uid= convenience loading -------------------------------------------

function getParams() {
  const p = new URLSearchParams(location.search);
  return {
    uid: p.get('uid'),
    manifestUrl: p.get('manifest'),
    src: p.get('src'), // base URL that serves the signed manifest for a uid
  };
}

function manifestUrlFrom({ uid, manifestUrl, src }) {
  if (manifestUrl) return manifestUrl;
  if (uid && src) return src.replace(/\/+$/, '') + '/' + encodeURIComponent(uid);
  return null;
}

// The public key is fetched from the DOI-archived record, never from the issuer's
// own service. Only the Zenodo API `/content` URL sends CORS headers.
function zenodoKeyUrl(doi) {
  const m = String(doi || '').match(/zenodo\.(\d+)/i);
  if (!m) return null;
  return `https://zenodo.org/api/records/${m[1]}/files/public-key.pem/content`;
}

async function fetchText(url) {
  const res = await fetch(url, { headers: { Accept: 'application/json, text/plain, */*' } });
  if (!res.ok) throw new Error(`Fetch failed (${res.status}) for ${url}`);
  return res.text();
}

function renderBanner() {
  if (!loaded.manifestSource) {
    bannerEl.classList.add('hidden');
    return;
  }
  bannerEl.classList.remove('hidden');
  bannerEl.innerHTML = `
    <p class="source-title">Convenience load — verification still runs locally</p>
    <dl class="source-list">
      <dt>Manifest source</dt><dd>${escapeHtml(loaded.manifestSource)}</dd>
      <dt>Public key source</dt><dd>${loaded.keySource ? escapeHtml(loaded.keySource) : 'not resolved — provide a public key PEM below'}</dd>
    </dl>
    <p class="source-note">
      The manifest was fetched from the source above; you can replace it with a local file at any time.
      The public key is taken from its DOI-archived record (never from the issuer's own service) and is
      accepted only if it matches the digest pinned inside the signed manifest.
    </p>
  `;
}

async function autoLoad() {
  const params = getParams();
  const url = manifestUrlFrom(params);
  if (!url) return;

  try {
    loaded.manifestText = await fetchText(url);
    loaded.manifestSource = url;
    renderBanner();
  } catch (error) {
    loaded.manifestSource = url;
    renderBanner();
    renderError(`Could not load manifest from source. ${error instanceof Error ? error.message : String(error)}`);
    return;
  }

  // Try to resolve the pinned, DOI-archived public key (v1.1 manifests).
  try {
    const manifest = JSON.parse(loaded.manifestText);
    const doi = manifest?.reference_anchor?.issuer_key?.public_key_doi;
    const keyUrl = zenodoKeyUrl(doi);
    if (keyUrl) {
      const pem = await fetchText(keyUrl);
      const pinned = manifest?.reference_anchor?.issuer_key?.public_key_digest || null;
      const derSha3 = `sha3-256:${sha3_256_hex(pemToDer(pem))}`;
      if (pinned && pinned !== derSha3) {
        loaded.keySource = `${keyUrl} — REJECTED (digest ${derSha3} ≠ pinned ${pinned})`;
      } else {
        loaded.publicKeyPem = pem;
        loaded.keySource = `${keyUrl}${pinned ? ' (digest-pinned OK)' : ' (no digest pin in manifest)'}`;
      }
    }
  } catch (error) {
    loaded.keySource = `key auto-resolve failed: ${error instanceof Error ? error.message : String(error)}`;
  }

  renderBanner();
  // If we have both a manifest and a trusted key, verify immediately.
  if (loaded.manifestText && loaded.publicKeyPem) {
    runVerification();
  }
}

// ---- verification + rendering --------------------------------------------

function statusTitle(status) {
  if (status === 'valid') return 'Valid';
  if (status === 'warning') return 'Verified with warnings';
  return 'Invalid';
}

function integrityLabel(s) {
  if (s === 'verified') return 'Asset integrity verified';
  if (s === 'mismatch') return 'Asset integrity FAILED';
  if (s === 'not_applicable') return 'Integrity N/A (catalog claim — no asset file)';
  if (s === 'not_checked') return 'Integrity not checked (no asset file supplied)';
  return 'Integrity unknown';
}

function render(result) {
  resultEl.classList.remove('hidden');
  resultEl.className = `result status-${result.status}`;
  resultEl.innerHTML = `
    <h2>${statusTitle(result.status)}</h2>
    <p>This result is computed locally in your browser. It verifies signature, issuer key and
    timestamped declaration; it does not adjudicate ownership, authorship, licensing or infringement.</p>
    <div class="badges">
      <span class="badge">Signature ${result.signatureOk ? 'valid' : 'invalid'}</span>
      <span class="badge">${escapeHtml(integrityLabel(result.integrityStatus))}</span>
      ${result.issuerKeyPinOk === null || result.issuerKeyPinOk === undefined ? '' : `<span class="badge">Key pin ${result.issuerKeyPinOk ? 'OK' : 'FAILED'}</span>`}
      ${result.keyRevoked ? '<span class="badge badge-danger">Key REVOKED</span>' : ''}
      <span class="badge">Evidence: ${escapeHtml(result.evidenceType || 'evidence_package')}</span>
    </div>
    ${result.keyRevoked ? `<p class="revoked-note">This signing key was revoked${result.revocation?.revokedAt ? ` on ${escapeHtml(result.revocation.revokedAt)}` : ''} after <strong>${escapeHtml(result.revocation?.reason || 'revocation')}</strong>${result.revocation?.supersededBy ? `, superseded by <strong>${escapeHtml(result.revocation.supersededBy)}</strong>` : ''}. No signature from a revoked key can be trusted.</p>` : ''}
    <pre>${escapeHtml(JSON.stringify(result, null, 2))}</pre>
  `;
}

function renderError(error) {
  resultEl.classList.remove('hidden');
  resultEl.className = 'result status-invalid';
  resultEl.innerHTML = `
    <h2>Verification failed</h2>
    <pre>${escapeHtml(error instanceof Error ? error.message : String(error))}</pre>
  `;
}

async function runVerification() {
  try {
    const assetFile = document.querySelector('#asset').files[0];
    const manifestFile = document.querySelector('#manifest').files[0];
    const publicKeyFile = document.querySelector('#publicKey').files[0];
    const issuerFile = document.querySelector('#issuer').files[0];

    // Local files always take precedence over the convenience-loaded values.
    const manifestText = manifestFile ? await readText(manifestFile) : loaded.manifestText;
    const publicKeyPem = publicKeyFile ? await readText(publicKeyFile) : loaded.publicKeyPem;

    if (!manifestText) throw new Error('Provide a manifest JSON file (or open a ?uid= link).');
    if (!publicKeyPem) {
      throw new Error(
        'No public key available. Provide a public key PEM, or use a manifest that pins a DOI-archived key.',
      );
    }

    render(
      await verifyAuraPackageBrowser({
        assetBytes: await readBytes(assetFile),
        manifestText,
        publicKeyPem,
        issuerText: issuerFile ? await readText(issuerFile) : null,
      }),
    );
  } catch (error) {
    renderError(error);
  }
}

document.querySelector('#verify').addEventListener('click', runVerification);

autoLoad();
