import { baseSchemas } from './base-schemas.js';

// Implements the assertion keywords present in the two pinned base schemas.
// format is annotation-only, as in JSON Schema 2020-12's default vocabulary.
// This is not a general-purpose JSON Schema engine or an archive resolver.
export function checkBaseSchema(value) {
  const version = value?.aura_version;
  const schema = typeof version === 'string' && Object.hasOwn(baseSchemas, version)
    ? baseSchemas[version] : null;
  if (!schema) return { status: 'not_checked', schemaId: null, errors: [] };
  const errors = [];
  function visit(rule, item, path) {
    if (rule.$ref) {
      const target = rule.$ref.slice(2).split('/').reduce((node, key) => node[key], schema);
      visit(target, item, path);
    }
    if ('const' in rule && item !== rule.const) errors.push(`${path}: must equal ${JSON.stringify(rule.const)}.`);
    const object = item !== null && typeof item === 'object' && !Array.isArray(item);
    if (rule.type) {
      const valid = rule.type === 'object' ? object : rule.type === 'array' ? Array.isArray(item) : typeof item === rule.type;
      if (!valid) { errors.push(`${path}: must be ${rule.type}.`); return; }
    }
    if (typeof item === 'string') {
      if (rule.minLength !== undefined && [...item].length < rule.minLength) errors.push(`${path}: must not be empty.`);
      if (rule.pattern && !new RegExp(rule.pattern).test(item)) errors.push(`${path}: does not match ${rule.pattern}.`);
    }
    if (object) {
      for (const key of rule.required || []) if (!Object.hasOwn(item, key)) errors.push(`${path}.${key}: required field missing.`);
      for (const [key, child] of Object.entries(rule.properties || {})) if (Object.hasOwn(item, key)) visit(child, item[key], `${path}.${key}`);
    }
    if (Array.isArray(item) && rule.items) item.forEach((child, index) => visit(rule.items, child, `${path}[${index}]`));
  }
  visit(schema, value, '$');
  return { status: errors.length ? 'fail' : 'pass', schemaId: schema.$id, errors };
}
