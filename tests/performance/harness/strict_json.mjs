import { open } from "node:fs/promises";

export const JSON_LIMITS = Object.freeze({
  maxBytes: 128 * 1024 * 1024,
  maxDepth: 32,
  maxCollectionEntries: 100_000,
  maxTotalValues: 4_000_000,
  maxStringBytes: 65_536,
});

export async function readStrictJson(path, { maxBytes = JSON_LIMITS.maxBytes } = {}) {
  const handle = await open(path, "r");
  try {
    const metadata = await handle.stat();
    if (metadata.size > maxBytes) throw new SyntaxError(`JSON input exceeds ${maxBytes} bytes`);

    const chunks = [];
    let total = 0;
    while (true) {
      const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, maxBytes + 1 - total));
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > maxBytes) throw new SyntaxError(`JSON input exceeds ${maxBytes} bytes`);
      chunks.push(chunk.subarray(0, bytesRead));
    }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, total));
    return parseStrictJson(text, { maxBytes });
  } finally {
    await handle.close();
  }
}

export function parseStrictJson(source, { maxBytes = JSON_LIMITS.maxBytes } = {}) {
  if (typeof source !== "string") throw new SyntaxError("JSON input must be a string");
  if (Buffer.byteLength(source, "utf8") > maxBytes) throw new SyntaxError(`JSON input exceeds ${maxBytes} bytes`);
  new Scanner(source).validate();
  return JSON.parse(source);
}

class Scanner {
  constructor(source) {
    this.source = source;
    this.index = 0;
    this.values = 0;
  }

  validate() {
    this.whitespace();
    this.value(0);
    this.whitespace();
    if (!this.eof()) this.fail("trailing content");
  }

  value(depth) {
    this.values += 1;
    if (this.values > JSON_LIMITS.maxTotalValues) this.fail(`JSON value cardinality exceeds ${JSON_LIMITS.maxTotalValues}`);
    if (depth > JSON_LIMITS.maxDepth) this.fail(`JSON nesting exceeds ${JSON_LIMITS.maxDepth}`);

    switch (this.current()) {
      case "{": return this.object(depth + 1);
      case "[": return this.array(depth + 1);
      case '"': return this.string(false);
      case "t": return this.literal("true");
      case "f": return this.literal("false");
      case "n": return this.literal("null");
      default:
        if (this.current() === "-" || this.isDigit(this.current())) return this.number();
        this.fail("expected JSON value");
    }
  }

  object(depth) {
    this.consume("{");
    this.whitespace();
    if (this.current() === "}") return this.consume("}");
    const keys = new Set();
    let entries = 0;
    while (true) {
      if (this.current() !== '"') this.fail("object key must be a string");
      const key = this.string(true);
      if (keys.has(key)) this.fail("duplicate object key");
      keys.add(key);
      entries += 1;
      if (entries > JSON_LIMITS.maxCollectionEntries) this.fail(`object cardinality exceeds ${JSON_LIMITS.maxCollectionEntries}`);
      this.whitespace();
      this.consume(":");
      this.whitespace();
      this.value(depth);
      this.whitespace();
      if (this.current() === "}") return this.consume("}");
      this.consume(",");
      this.whitespace();
    }
  }

  array(depth) {
    this.consume("[");
    this.whitespace();
    if (this.current() === "]") return this.consume("]");
    let entries = 0;
    while (true) {
      entries += 1;
      if (entries > JSON_LIMITS.maxCollectionEntries) this.fail(`array cardinality exceeds ${JSON_LIMITS.maxCollectionEntries}`);
      this.value(depth);
      this.whitespace();
      if (this.current() === "]") return this.consume("]");
      this.consume(",");
      this.whitespace();
    }
  }

  string(capture) {
    this.consume('"');
    let decoded = "";
    let decodedBytes = 0;
    while (true) {
      if (this.eof()) this.fail("unterminated string");
      const code = this.source.charCodeAt(this.index);
      if (code === 0x22) {
        this.index += 1;
        return capture ? decoded : undefined;
      }
      if (code < 0x20) this.fail("unescaped control character");

      let segment;
      if (code === 0x5c) {
        this.index += 1;
        const escaped = this.current();
        const simple = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
        if (Object.hasOwn(simple, escaped)) {
          segment = simple[escaped];
          this.index += 1;
        } else if (escaped === "u") {
          segment = this.unicodeEscape();
        } else {
          this.fail("invalid string escape");
        }
      } else if (code < 0x80) {
        segment = capture ? this.source[this.index] : "";
        this.index += 1;
        decodedBytes += 1;
        if (decodedBytes > JSON_LIMITS.maxStringBytes) this.fail(`decoded string exceeds ${JSON_LIMITS.maxStringBytes} bytes`);
        if (capture) decoded += segment;
        continue;
      } else if (code >= 0xd800 && code <= 0xdbff) {
        const low = this.source.charCodeAt(this.index + 1);
        if (!(low >= 0xdc00 && low <= 0xdfff)) this.fail("unpaired Unicode surrogate");
        segment = this.source.slice(this.index, this.index + 2);
        this.index += 2;
      } else {
        if (code >= 0xdc00 && code <= 0xdfff) this.fail("unpaired Unicode surrogate");
        segment = this.source[this.index];
        this.index += 1;
      }
      decodedBytes += Buffer.byteLength(segment, "utf8");
      if (decodedBytes > JSON_LIMITS.maxStringBytes) this.fail(`decoded string exceeds ${JSON_LIMITS.maxStringBytes} bytes`);
      if (capture) decoded += segment;
    }
  }

  unicodeEscape() {
    this.consume("u");
    const first = this.hexCodeUnit();
    let codepoint = first;
    if (first >= 0xd800 && first <= 0xdbff) {
      this.consume("\\");
      this.consume("u");
      const second = this.hexCodeUnit();
      if (!(second >= 0xdc00 && second <= 0xdfff)) this.fail("invalid Unicode surrogate pair");
      codepoint = 0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00);
    } else if (first >= 0xdc00 && first <= 0xdfff) {
      this.fail("unpaired Unicode surrogate");
    }
    return String.fromCodePoint(codepoint);
  }

  hexCodeUnit() {
    const digits = this.source.slice(this.index, this.index + 4);
    if (!/^[0-9A-Fa-f]{4}$/.test(digits)) this.fail("invalid Unicode escape");
    this.index += 4;
    return Number.parseInt(digits, 16);
  }

  number() {
    if (this.current() === "-") this.index += 1;
    if (this.current() === "0") {
      this.index += 1;
      if (this.isDigit(this.current())) this.fail("leading zero in number");
    } else {
      if (!/[1-9]/.test(this.current() ?? "")) this.fail("invalid number");
      while (this.isDigit(this.current())) this.index += 1;
    }
    if (this.current() === ".") {
      this.index += 1;
      if (!this.isDigit(this.current())) this.fail("invalid fractional number");
      while (this.isDigit(this.current())) this.index += 1;
    }
    if (this.current() === "e" || this.current() === "E") {
      this.index += 1;
      if (this.current() === "+" || this.current() === "-") this.index += 1;
      if (!this.isDigit(this.current())) this.fail("invalid exponent");
      while (this.isDigit(this.current())) this.index += 1;
    }
  }

  literal(expected) {
    if (this.source.slice(this.index, this.index + expected.length) !== expected) this.fail("invalid literal");
    this.index += expected.length;
  }

  whitespace() {
    while ([" ", "\t", "\n", "\r"].includes(this.current())) this.index += 1;
  }

  consume(expected) {
    if (this.current() !== expected) this.fail(`expected ${JSON.stringify(expected)}`);
    this.index += 1;
  }

  current() { return this.source[this.index]; }
  eof() { return this.index >= this.source.length; }
  isDigit(value) { return value !== undefined && value >= "0" && value <= "9"; }
  fail(message) { throw new SyntaxError(`${message} at character ${this.index}`); }
}
