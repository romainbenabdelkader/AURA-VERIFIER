// JSON.parse validates the grammar; scan the original tokens before returning
// its result so duplicate names cannot disappear through last-value-wins parsing.
// Compare decoded names, including escaped spellings, separately in each object.
export function parseUniqueJson(text) {
  if (typeof text !== 'string') throw new TypeError('JSON input must be text.');
  const parsed = JSON.parse(text);
  let offset = 0;
  const whitespace = () => { while (/^[\t\n\r ]$/.test(text[offset] || '')) offset += 1; };
  function stringToken() {
    const start = offset++;
    while (text[offset] !== '"') {
      if (text[offset] === '\\') offset += 2;
      else offset += 1;
    }
    offset += 1;
    return text.slice(start, offset);
  }
  function value() {
    whitespace();
    if (text[offset] === '{') {
      offset += 1;
      whitespace();
      const names = new Set();
      if (text[offset] !== '}') {
        while (true) {
          whitespace();
          const name = JSON.parse(stringToken());
          if (names.has(name)) throw new SyntaxError('Duplicate JSON property name.');
          names.add(name);
          whitespace();
          offset += 1; // colon; grammar already checked by JSON.parse
          value();
          whitespace();
          if (text[offset] !== ',') break;
          offset += 1;
        }
      }
      offset += 1;
    } else if (text[offset] === '[') {
      offset += 1;
      whitespace();
      if (text[offset] !== ']') {
        while (true) {
          value();
          whitespace();
          if (text[offset] !== ',') break;
          offset += 1;
        }
      }
      offset += 1;
    } else if (text[offset] === '"') {
      stringToken();
    } else {
      while (offset < text.length && !/[\t\n\r ,}\]]/.test(text[offset])) offset += 1;
    }
  }
  value();
  return parsed;
}
