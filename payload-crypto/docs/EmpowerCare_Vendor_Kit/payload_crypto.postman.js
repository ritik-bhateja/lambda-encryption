// Postman script for any API behind payload_crypto: encrypts the request,
// decrypts the reply.
//
// Put this SAME script in the request's Pre-request AND Post-response tabs.
// It checks which one is running.
//
// Headers tab: X-Vendor-Id: {{vendor_id}}. The script seals for that vendor.
// Collection variables:
//   vendor_id        e.g. ACME. Fills the X-Vendor-Id header
//   vendor_key_hex   that vendor's AES-256 key, 64 hex chars (from Secrets Manager)
//   vendor_key_id    optional, defaults to <vendor_id>-v1 (bump after a rotation)
//
// Pre-request: the Body tab holds plain JSON. It is sealed into
// {"request_key": "label.iv.ciphertext.tag"}: AES-256-GCM with the vendor key,
// the base64url label as AAD, label = {v, alg, kid, cid, pth, mtd, iat, jti}.
// GET/HEAD/DELETE with an empty body are sent without one.
//
// Post-response: {response_key, response_value} is opened: unwrap the one-time
// DEK from response_key, decrypt response_value with it (response_key as AAD),
// raw inflate, JSON. Shown in the Visualize tab.
//
// Postman's sandbox has crypto-js (AES, no GCM) and no zlib, so GCM and inflate
// are implemented below. The GCM tag is always checked before anything is used.
//
// WARNING: vendor_key_hex seals and opens everything for that vendor. Do not
// share or export the collection with the key in it.

const _var = name => ((typeof pm !== 'undefined' && pm.variables.get(name)) || '').trim();
const VENDOR_KEY_HEX = _var('vendor_key_hex') || 'PASTE_64_HEX_CHAR_KEY_HERE';
const VENDOR_HEADER = 'X-Vendor-Id';
// The vendor is whatever the X-Vendor-Id header in the Headers tab says
// ({{vendor_id}} by default). The variable is the fallback if the header is removed.
const _headerVendor = () => {
  if (typeof pm === 'undefined') return '';
  const h = pm.request.headers.find(x => x.key && x.key.toLowerCase() === VENDOR_HEADER.toLowerCase() && !x.disabled);
  return h ? pm.variables.replaceIn(h.value || '').trim() : '';
};
const CLIENT_REF = _headerVendor() || _var('vendor_id') || 'HELLO_VENDOR';
const KEY_ID = _var('vendor_key_id') || (CLIENT_REF + '-v1');
const MAX_PLAINTEXT_BYTES = 10 * 1024 * 1024;

const cryptoJs = require('crypto-js');   // Postman already has a global CryptoJS

// ---------------------------------------------------------------- bytes ----

function hexToBytes(hex) {
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error('VENDOR_KEY_HEX must be 64 hex characters');
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function b64uToBytes(text) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const clean = String(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const out = new Uint8Array(Math.floor(clean.length * 3 / 4));
  let buf = 0, bits = 0, o = 0;
  for (let i = 0; i < clean.length; i++) {
    const v = alphabet.indexOf(clean[i]);
    if (v < 0) throw new Error('bad base64url character');
    buf = (buf << 6) | v; bits += 6;
    if (bits >= 8) { bits -= 8; out[o++] = (buf >> bits) & 0xff; }
  }
  return out.subarray(0, o);
}

function utf8Decode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 8192) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192));
  }
  return decodeURIComponent(escape(s));
}

function asciiBytes(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0x7f;
  return out;
}

// Big-endian 32-bit words, as AES and GHASH use them.
function toWords(bytes, off) {
  const w = [0, 0, 0, 0];
  for (let i = 0; i < 16; i++) {
    const b = off + i < bytes.length ? bytes[off + i] : 0;
    w[i >> 2] |= b << (24 - (i & 3) * 8);
  }
  return w.map(x => x >>> 0);
}

function wordsToBytes(w) {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = (w[i >> 2] >>> (24 - (i & 3) * 8)) & 0xff;
  return out;
}

// ------------------------------------------------------------ AES-GCM ----

function gfMul(x, y) {
  const z = [0, 0, 0, 0];
  const v = y.slice();
  for (let i = 0; i < 128; i++) {
    if ((x[i >> 5] >>> (31 - (i & 31))) & 1) {
      z[0] ^= v[0]; z[1] ^= v[1]; z[2] ^= v[2]; z[3] ^= v[3];
    }
    const lsb = v[3] & 1;
    v[3] = (v[3] >>> 1) | ((v[2] & 1) << 31);
    v[2] = (v[2] >>> 1) | ((v[1] & 1) << 31);
    v[1] = (v[1] >>> 1) | ((v[0] & 1) << 31);
    v[0] = v[0] >>> 1;
    if (lsb) v[0] ^= 0xe1000000;
  }
  return z.map(n => n >>> 0);
}

function ghash(h, aad, ct) {
  let x = [0, 0, 0, 0];
  const absorb = data => {
    for (let off = 0; off < data.length; off += 16) {
      const b = toWords(data, off);
      x = gfMul([x[0] ^ b[0], x[1] ^ b[1], x[2] ^ b[2], x[3] ^ b[3]], h);
    }
  };
  absorb(aad);
  absorb(ct);
  const lens = [0, (aad.length * 8) >>> 0, 0, (ct.length * 8) >>> 0];
  return gfMul([x[0] ^ lens[0], x[1] ^ lens[1], x[2] ^ lens[2], x[3] ^ lens[3]], h);
}

// AES-256-GCM decrypt with a 12-byte IV and 16-byte tag. Throws on a bad tag.
function gcmDecrypt(key, iv, ct, tag, aad) {
  if (iv.length !== 12 || tag.length !== 16) throw new Error('bad GCM iv or tag length');
  const words = [];
  for (let i = 0; i < 32; i += 4) words.push(((key[i] << 24) | (key[i + 1] << 16) | (key[i + 2] << 8) | key[i + 3]) >>> 0);
  const aes = cryptoJs.algo.AES.createEncryptor(cryptoJs.lib.WordArray.create(words, 32));
  const enc = block => { const b = block.slice(); aes.encryptBlock(b, 0); return b.map(n => n >>> 0); };

  const h = enc([0, 0, 0, 0]);
  const ivw = toWords(iv, 0);
  const j0 = [ivw[0], ivw[1], ivw[2], 1];

  // Check the tag first. Nothing is decrypted if it is wrong.
  const s = ghash(h, aad, ct);
  const ek = enc(j0);
  const expected = wordsToBytes([ek[0] ^ s[0], ek[1] ^ s[1], ek[2] ^ s[2], ek[3] ^ s[3]]);
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= expected[i] ^ tag[i];
  if (diff !== 0) throw new Error('GCM tag mismatch: wrong key or tampered reply');

  const out = new Uint8Array(ct.length);
  for (let off = 0, n = 0; off < ct.length; off += 16, n++) {
    const ks = wordsToBytes(enc([j0[0], j0[1], j0[2], (j0[3] + 1 + n) >>> 0]));
    for (let i = 0; i < 16 && off + i < ct.length; i++) out[off + i] = ct[off + i] ^ ks[i];
  }
  return out;
}

// ---------------------------------------------------- raw inflate (RFC 1951) ----

function inflateRaw(src) {
  let pos = 0, bitBuf = 0, bitCnt = 0;
  const out = [];
  const bits = n => {
    while (bitCnt < n) {
      if (pos >= src.length) throw new Error('inflate: out of input');
      bitBuf |= src[pos++] << bitCnt; bitCnt += 8;
    }
    const v = bitBuf & ((1 << n) - 1);
    bitBuf >>>= n; bitCnt -= n;
    return v;
  };
  const build = lengths => {
    const count = new Array(16).fill(0), offs = new Array(16).fill(0), symbol = [];
    lengths.forEach(l => count[l]++);
    count[0] = 0;
    for (let l = 1; l < 15; l++) offs[l + 1] = offs[l] + count[l];
    lengths.forEach((l, sym) => { if (l) symbol[offs[l]++] = sym; });
    return { count, symbol };
  };
  const decode = t => {
    let code = 0, first = 0, index = 0;
    for (let l = 1; l <= 15; l++) {
      code |= bits(1);
      const c = t.count[l];
      if (code - c < first) return t.symbol[index + (code - first)];
      index += c; first += c; first <<= 1; code <<= 1;
    }
    throw new Error('inflate: bad code');
  };
  const LBASE = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258];
  const LEXT = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0];
  const DBASE = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577];
  const DEXT = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];

  const codes = (lenT, distT) => {
    for (;;) {
      let sym = decode(lenT);
      if (sym < 256) { out.push(sym); }
      else if (sym === 256) { return; }
      else {
        sym -= 257;
        if (sym >= 29) throw new Error('inflate: bad length symbol');
        const len = LBASE[sym] + bits(LEXT[sym]);
        const ds = decode(distT);
        if (ds >= 30) throw new Error('inflate: bad distance symbol');
        const dist = DBASE[ds] + bits(DEXT[ds]);
        if (dist > out.length) throw new Error('inflate: distance too far');
        for (let i = 0; i < len; i++) out.push(out[out.length - dist]);
      }
      if (out.length > MAX_PLAINTEXT_BYTES) throw new Error('reply over 10 MB');
    }
  };

  let last;
  do {
    last = bits(1);
    const type = bits(2);
    if (type === 0) {
      bitBuf = 0; bitCnt = 0;
      if (pos + 4 > src.length) throw new Error('inflate: bad stored block');
      const len = src[pos] | (src[pos + 1] << 8);
      const nlen = src[pos + 2] | (src[pos + 3] << 8);
      if (len !== (~nlen & 0xffff)) throw new Error('inflate: stored length mismatch');
      pos += 4;
      if (pos + len > src.length) throw new Error('inflate: out of input');
      for (let i = 0; i < len; i++) out.push(src[pos++]);
    } else if (type === 1) {
      const l = [];
      for (let i = 0; i < 288; i++) l.push(i < 144 ? 8 : i < 256 ? 9 : i < 280 ? 7 : 8);
      codes(build(l), build(new Array(30).fill(5)));
    } else if (type === 2) {
      const nlen = bits(5) + 257, ndist = bits(5) + 1, ncode = bits(4) + 4;
      const ORDER = [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15];
      const cl = new Array(19).fill(0);
      for (let i = 0; i < ncode; i++) cl[ORDER[i]] = bits(3);
      const clT = build(cl);
      const lengths = [];
      while (lengths.length < nlen + ndist) {
        const sym = decode(clT);
        if (sym < 16) { lengths.push(sym); continue; }
        let val = 0, rep;
        if (sym === 16) {
          if (!lengths.length) throw new Error('inflate: repeat with no previous length');
          val = lengths[lengths.length - 1]; rep = 3 + bits(2);
        } else if (sym === 17) { rep = 3 + bits(3); }
        else { rep = 11 + bits(7); }
        if (lengths.length + rep > nlen + ndist) throw new Error('inflate: too many lengths');
        for (let i = 0; i < rep; i++) lengths.push(val);
      }
      codes(build(lengths.slice(0, nlen)), build(lengths.slice(nlen)));
    } else {
      throw new Error('inflate: bad block type');
    }
  } while (!last);
  return Uint8Array.from(out);
}

// ------------------------------------------------------------- open reply ----

function openReply(responseKey, responseValue, keyHex) {
  const key = hexToBytes(keyHex);
  const label = JSON.parse(utf8Decode(b64uToBytes(responseKey)));
  if (label.cid !== CLIENT_REF) throw new Error('reply is for ' + label.cid + ', not ' + CLIENT_REF);

  // 1. unwrap the one-time DEK with the shared key (no AAD)
  const dek = gcmDecrypt(key, b64uToBytes(label.wiv), b64uToBytes(label.edek),
                         b64uToBytes(label.wtag), new Uint8Array(0));
  if (dek.length !== 32) throw new Error('DEK is not 32 bytes');

  // 2. decrypt response_value with the DEK, response_key as the AAD
  const blob = b64uToBytes(responseValue);
  if (blob.length < 28) throw new Error('response_value too short');
  const packed = gcmDecrypt(dek, blob.subarray(0, 12), blob.subarray(12, blob.length - 16),
                            blob.subarray(blob.length - 16), asciiBytes(responseKey));

  // 3. inflate and parse
  return { label, reply: JSON.parse(utf8Decode(inflateRaw(packed))) };
}


// ------------------------------------------------------- encrypt helpers ----

function bytesToB64u(bytes) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let out = '', buf = 0, bits = 0;
  for (let i = 0; i < bytes.length; i++) {
    buf = (buf << 8) | bytes[i]; bits += 8;
    while (bits >= 6) { bits -= 6; out += alphabet[(buf >> bits) & 63]; }
    buf &= (1 << bits) - 1;
  }
  if (bits > 0) out += alphabet[(buf << (6 - bits)) & 63];
  return out;
}

function utf8Encode(text) {
  const s = unescape(encodeURIComponent(text));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function randomBytes(n) {
  // crypto.getRandomValues when the sandbox has it, crypto-js otherwise. The GCM
  // iv only has to be unique per key; 96 random bits is plenty for testing.
  const out = new Uint8Array(n);
  if (typeof crypto !== 'undefined' && crypto && crypto.getRandomValues) {
    crypto.getRandomValues(out);
    return out;
  }
  const wa = cryptoJs.lib.WordArray.random(n);
  for (let i = 0; i < n; i++) out[i] = (wa.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  return out;
}

function toHex(bytes) {
  return Array.from(bytes, b => (b < 16 ? '0' : '') + b.toString(16)).join('');
}

// AES-256-GCM encrypt with a 12-byte IV. Returns { ct, tag }.
function gcmEncrypt(key, iv, pt, aad) {
  const words = [];
  for (let i = 0; i < 32; i += 4) words.push(((key[i] << 24) | (key[i + 1] << 16) | (key[i + 2] << 8) | key[i + 3]) >>> 0);
  const aes = cryptoJs.algo.AES.createEncryptor(cryptoJs.lib.WordArray.create(words, 32));
  const enc = block => { const b = block.slice(); aes.encryptBlock(b, 0); return b.map(n => n >>> 0); };
  const h = enc([0, 0, 0, 0]);
  const ivw = toWords(iv, 0);
  const j0 = [ivw[0], ivw[1], ivw[2], 1];
  const ct = new Uint8Array(pt.length);
  for (let off = 0, n = 0; off < pt.length; off += 16, n++) {
    const ks = wordsToBytes(enc([j0[0], j0[1], j0[2], (j0[3] + 1 + n) >>> 0]));
    for (let i = 0; i < 16 && off + i < pt.length; i++) ct[off + i] = pt[off + i] ^ ks[i];
  }
  const s = ghash(h, aad, ct);
  const ek = enc(j0);
  return { ct, tag: wordsToBytes([ek[0] ^ s[0], ek[1] ^ s[1], ek[2] ^ s[2], ek[3] ^ s[3]]) };
}

// ----------------------------------------------------------- seal request ----

function sealRequest(payload, keyHex, path, method) {
  const key = hexToBytes(keyHex);
  const label = {
    alg: 'A256GCM', cid: CLIENT_REF, iat: Math.floor(Date.now() / 1000),
    jti: toHex(randomBytes(16)), kid: KEY_ID, mtd: method, pth: path, v: 1,
  };
  const labelSeg = bytesToB64u(utf8Encode(JSON.stringify(label)));
  const iv = randomBytes(12);
  const { ct, tag } = gcmEncrypt(key, iv, utf8Encode(JSON.stringify(payload)), asciiBytes(labelSeg));
  return { request_key: [labelSeg, bytesToB64u(iv), bytesToB64u(ct), bytesToB64u(tag)].join('.') };
}

// ----------------------------------------------------------------- Postman ----

// The API path the label must carry, from the URL with {{variables}} resolved.
// Before the request is sent, pm.request.url may still be "{{hello_url}}".
function requestPath() {
  const url = pm.variables.replaceIn(pm.request.url.toString());
  const m = url.match(/^[a-z]+:\/\/[^\/?#]+([^?#]*)/i);
  const path = m ? m[1] : url.replace(/[?#].*$/, '');
  return '/' + path.replace(/^\/+/, '');
}

if (typeof pm !== 'undefined' && pm.info.eventName === 'prerequest') {
  if (!_headerVendor()) {
    // Header missing or empty in the Headers tab: add it so the server can pick the key.
    pm.request.headers.upsert({ key: VENDOR_HEADER, value: CLIENT_REF });
  }
  const raw = pm.variables.replaceIn((pm.request.body && pm.request.body.raw) || '').trim();
  const path = requestPath();
  if (!raw && ['GET', 'HEAD', 'DELETE', 'OPTIONS'].includes(pm.request.method)) {
    pm.collectionVariables.set('plain_request', '');
    console.log('no body to seal for', pm.request.method, path, '(reply is still encrypted)');
  } else {
    let payload;
    try { payload = JSON.parse(raw || '{}'); } catch (e) { throw new Error('Body must be plain JSON before sealing: ' + e.message); }
    const sealed = sealRequest(payload, VENDOR_KEY_HEX, path, pm.request.method);
    pm.request.body.update(JSON.stringify(sealed));
    pm.request.headers.upsert({ key: 'Content-Type', value: 'application/json' });
    pm.collectionVariables.set('plain_request', JSON.stringify(payload));
    console.log('sealed request for', CLIENT_REF, pm.request.method, path, ':', JSON.stringify(payload));
  }
} else if (typeof pm !== 'undefined' && pm.info.eventName === 'test') {
  const body = pm.response.json();
  if (pm.response.code !== 200) {
    pm.test('200 OK (got ' + pm.response.code + ' ' + (body.error || '') + ': ' + (body.message || '') + ')', () => {
      pm.response.to.have.status(200);
    });
  } else {
    pm.test('200 OK', () => pm.response.to.have.status(200));
    pm.test('reply is only response_key + response_value', () => {
      pm.expect(Object.keys(body).sort()).to.eql(['response_key', 'response_value']);
    });
    let opened;
    try {
      opened = openReply(body.response_key, body.response_value, VENDOR_KEY_HEX);
    } catch (e) {
      pm.test('reply decrypts', () => { throw e; });
    }
    if (opened) {
      pm.test('reply decrypts', () => pm.expect(opened.reply).to.not.be.undefined);
      pm.test('reply label matches the request', () => {
        pm.expect(opened.label.pth).to.eql(requestPath());
        pm.expect(opened.label.mtd).to.eql(pm.request.method);
      });
      pm.collectionVariables.set('decrypted_reply', JSON.stringify(opened.reply));
      console.log('decrypted reply:', JSON.stringify(opened.reply, null, 2));
      pm.visualizer.set(
        '<h3>Request you sent (before sealing)</h3><pre style="font-size:13px">{{req}}</pre>' +
        '<h3>Decrypted reply</h3><pre style="font-size:14px">{{json}}</pre>' +
        '<p style="color:#666">kek_id {{kid}}, iat {{iat}}, jti {{jti}}</p>',
        { req: pm.collectionVariables.get('plain_request') ? JSON.stringify(JSON.parse(pm.collectionVariables.get('plain_request')), null, 2) : '(no body)',
          json: JSON.stringify(opened.reply, null, 2), kid: opened.label.kek_id,
          iat: new Date(opened.label.iat * 1000).toISOString(), jti: opened.label.jti }
      );
    }
  }
} else if (typeof module !== 'undefined') {
  module.exports = { sealRequest, openReply, gcmEncrypt, gcmDecrypt, inflateRaw };
}
