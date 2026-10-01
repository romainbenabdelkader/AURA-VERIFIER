// Syntax inspection only: never resolves a DOI or attests archived content.
export function inspectArchiveReferences(manifest) {
  const anchor = manifest?.reference_anchor;
  const fields = ['standard.archive_doi', 'verifier.archive_doi', 'issuer_key.public_key_doi'];
  const references = fields.map(field => {
    const [block, key] = field.split('.');
    const value = anchor?.[block]?.[key];
    const doiLike = typeof value === 'string' && /^10\.\d{4,9}\/\S+$/i.test(value);
    return { field: `reference_anchor.${field}`, value: value ?? null,
      syntax: value === undefined ? 'missing' : doiLike ? 'doi_like' : 'not_doi',
      resolution: 'not_checked' };
  });
  return {
    status: 'not_checked',
    references: anchor ? references : [],
    warnings: anchor ? references.filter(r => r.syntax === 'not_doi').map(r =>
      `${r.field} is not a bare DOI. Schema acceptance does not establish a public archive.`) : [],
  };
}
