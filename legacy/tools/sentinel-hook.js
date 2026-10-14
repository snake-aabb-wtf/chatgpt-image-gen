/* ============================================================================
 * sentinel-hook.js —— ChatGPT Sentinel 校验材料提取 / XOR 解密脚本
 * ----------------------------------------------------------------------------
 * 作用：在真实浏览器里把 Sentinel 的校验字段抓出来，并把「XOR 混淆」的
 *       t / turnstile 字段**解密成明文**，同时直接还原出 XOR 密钥本身。
 *
 * 适用：chatgpt.com（对话链路 chat-requirements）
 *       auth.openai.com（登录链路 openai-sentinel-token）
 *
 * 用法（30 秒版）
 *   1) F12 → Console（若提示 "allow pasting"，按提示先输入 allow pasting 回车）
 *   2) 把本文件全文粘进去回车 —— 会打印 [sentinel-hook] 已安装
 *   3) 触发一次校验：输入框发一条消息（对话链路），或走一次登录（登录链路）
 *   4) Console 自动打印：抓到的字段 → 解出的明文 → XOR 密钥
 *   5) 汇总：在 Console 执行  copy(SentinelXOR.report())
 *
 * 什么都没抓到时
 *   · 对话链路：确认第 3 步真的发出了请求；若 SDK 跑在 iframe 内，请在
 *     Console 左上角的 context 下拉框切到 sentinel 相关 frame 再贴一次
 *   · 登录链路：SDK 运行在 sentinel.openai.com 的 iframe 内，请把 Console 的
 *     执行上下文切到 frame.html（sentinel.openai.com）后再贴一次
 *
 * 手动 / 离线模式
 *   SentinelXOR.crackToConsole('<t 或 turnstile 的值>')
 *   SentinelXOR.crackWithKeys('<blob>', { 'cookie:xxx': '值' })
 *   SentinelXOR.decodePayload('<p 或 proof-token 的值>')   // 解出 25 字段指纹数组
 *
 * 安全：只读取当前页面的 cookie / storage 作为**候选密钥**做本地试解，
 *       不发起任何网络请求；密钥与明文只打印在你自己的 Console。
 * ==========================================================================*/
(function (root) {
  'use strict';

  /* 在任何 hook 安装之前，先抓住原始函数，供内部逻辑使用，
     避免"自己 hook 自己"污染配对监听。 */
  var ORIG_ATOB = root.atob;
  var ORIG_FCC = String.fromCharCode;

  var VERSION = '1.1';
  var TAG = '[sentinel-hook]';
  var state = {
    installed: false,
    blobs: new Map(),      // name -> value（待解密的 XOR blob）
    envelopes: new Map(),  // name -> value（gAAAAA 载荷封装）
    solved: [],            // 解密成功记录
    keys: new Map(),       // 已恢复的密钥
    log: []
  };

  /* ------------------------------------------------------------------ *
   * 基础工具（内部一律走 ORIG_*，不触发自己的 hook）
   * ------------------------------------------------------------------ */
  function say() {
    var a = Array.prototype.slice.call(arguments);
    state.log.push(a.join(' '));
    try { console.log.apply(console, [TAG].concat(a)); } catch (e) {}
  }
  function warn() {
    var a = Array.prototype.slice.call(arguments);
    state.log.push('[WARN] ' + a.join(' '));
    try { console.warn.apply(console, [TAG].concat(a)); } catch (e) {}
  }

  function b64ToBytes(str) {
    var s = String(str).trim();
    if (s.slice(-2) === '~S') s = s.slice(0, -2);          // Sentinel 的 "已解出" 后缀
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    s += new Array(((4 - (s.length % 4)) % 4) + 1).join('=');
    var bin = ORIG_ATOB(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i) & 0xff;
    return out;
  }

  function bytesToLatin1(u8) {
    var s = '';
    for (var i = 0; i < u8.length; i++) s += ORIG_FCC(u8[i]);
    return s;
  }

  function b64ToLatin1(b64) { return bytesToLatin1(b64ToBytes(b64)); }

  // 与 SDK 内部实现完全一致：String.fromCharCode(a.charCodeAt(i) ^ key.charCodeAt(i % key.length))
  function xorLatin1(str, key) {
    var out = '';
    for (var i = 0; i < str.length; i++) {
      out += ORIG_FCC(str.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    }
    return out;
  }

  function tryJson(s) {
    try {
      var v = JSON.parse(s);
      return (v && typeof v === 'object') ? v : null;
    } catch (e) { return null; }
  }

  function looksLikeBlob(v) {
    if (typeof v !== 'string') return false;
    if (v.length < 60) return false;
    return /^[A-Za-z0-9+/_=-]+~?S?$/.test(v);
  }

  function utf8Decode(bytes) {
    try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
    catch (e) { return null; }
  }

  /* ------------------------------------------------------------------ *
   * 1) 候选密钥采集：cookie / localStorage / sessionStorage
   * ------------------------------------------------------------------ */
  function parseCookieString(cs) {
    var out = {};
    String(cs || '').split(';').forEach(function (p) {
      var i = p.indexOf('=');
      if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
    });
    return out;
  }

  function dumpStore(store) {
    var out = {};
    try {
      if (!store) return out;
      for (var i = 0; i < store.length; i++) {
        var k = store.key(i);
        out[k] = store.getItem(k);
      }
    } catch (e) {}
    return out;
  }

  function collectCandidates() {
    var cand = new Map();
    var ck = parseCookieString((function () { try { return document.cookie; } catch (e) { return ''; } })());
    Object.keys(ck).forEach(function (k) { cand.set('cookie:' + k, ck[k]); });
    var ls = dumpStore((function () { try { return root.localStorage; } catch (e) { return null; } })());
    Object.keys(ls).forEach(function (k) { cand.set('localStorage:' + k, ls[k]); });
    var ss = dumpStore((function () { try { return root.sessionStorage; } catch (e) { return null; } })());
    Object.keys(ss).forEach(function (k) { cand.set('sessionStorage:' + k, ss[k]); });
    try { cand.set('navigator.userAgent', root.navigator.userAgent); } catch (e) {}
    var clean = new Map();
    cand.forEach(function (v, k) {
      if (v !== undefined && v !== null && String(v) !== '') clean.set(k, String(v));
    });
    return clean;
  }

  /* ------------------------------------------------------------------ *
   * 2) 解密：a) 候选密钥  b) 单字节  c) 已知前缀推导
   * ------------------------------------------------------------------ */
  function isTextish(code) {
    // 保留给未来的宽松判定使用（当前"已知前缀推导"走严格 ASCII 约束）
    return (code >= 0x20 && code !== 0x7f) || code === 9 || code === 10 || code === 13;
  }

  function crackWithCandidates(ct, candidates) {
    var hit = null;
    candidates.forEach(function (v, k) {
      if (hit) return;
      var pt = xorLatin1(ct, v);
      if (tryJson(pt)) hit = { key: v, source: k, plaintext: pt };
    });
    return hit;
  }

  function crackSingleByte(ct) {
    for (var b = 0; b < 256; b++) {
      var key = ORIG_FCC(b);
      var pt = xorLatin1(ct, key);
      if (tryJson(pt)) {
        return { key: key, source: 'brute:单字节(0x' + (b < 16 ? '0' : '') + b.toString(16) + ')', plaintext: pt };
      }
    }
    return null;
  }

  // 假设明文是 JSON（以 {" / [{ / [" / {"t 开头），按列求密钥并校验。
  // 约束：明文各字符必须落在可打印 ASCII(0x20~0x7e) —— 该约束下"错误的密钥长度"
  // 几乎必然导致某一列无解，从而避免误报；正确的长度则每列收敛到唯一解。
  var ASCII_MIN = 0x20, ASCII_MAX = 0x7e;
  function asciiOk(code) { return code >= ASCII_MIN && code <= ASCII_MAX; }

  function combineCols(cols, cap) {
    var out = [];
    var buf = new Array(cols.length);
    (function rec(i) {
      if (out.length >= cap) return;
      if (i === cols.length) {
        var s = '';
        for (var q = 0; q < buf.length; q++) s += ORIG_FCC(buf[q]);
        out.push(s);
        return;
      }
      var list = cols[i];
      for (var k = 0; k < list.length; k++) {
        buf[i] = list[k];
        rec(i + 1);
        if (out.length >= cap) return;
      }
    })(0);
    return out;
  }

  function crackKnownPrefix(ct) {
    var heads = ['{"', '[{', '["', '{"t', '{"c', '{"s'];
    for (var h = 0; h < heads.length; h++) {
      var head = heads[h];
      for (var L = 2; L <= 64 && L <= ct.length; L++) {
        var cols = new Array(L);
        for (var j = 0; j < L; j++) cols[j] = null;
        for (var t = 0; t < head.length && t < L; t++) cols[t] = [ct.charCodeAt(t) ^ head.charCodeAt(t)];
        var ok = true;
        for (var col = 0; col < L && ok; col++) {
          var allowed = cols[col];
          for (var i = col; i < ct.length; i += L) {
            var c = ct.charCodeAt(i);
            if (allowed === null) {
              allowed = [];
              for (var v = ASCII_MIN; v <= ASCII_MAX; v++) allowed.push(c ^ v);
            } else {
              var next = [];
              for (var a = 0; a < allowed.length; a++) if (asciiOk(c ^ allowed[a])) next.push(allowed[a]);
              allowed = next;
            }
            if (allowed.length === 0) { ok = false; break; }
          }
          if (!ok) break;
          cols[col] = allowed;
        }
        if (!ok) continue;
        var keys = combineCols(cols, 20000);
        for (var ki = 0; ki < keys.length; ki++) {
          var pt = xorLatin1(ct, keys[ki]);
          if (tryJson(pt)) {
            return {
              key: keys[ki],
              source: 'derive:已知前缀推导(L=' + L + (keys.length > 1 ? ', 组合 ' + keys.length : '') + ')',
              plaintext: pt
            };
          }
        }
      }
    }
    return null;
  }

  function crack(blob, candidates) {
    var ct;
    try { ct = b64ToLatin1(blob); } catch (e) { return null; }
    var cands = candidates || collectCandidates();
    var r = crackWithCandidates(ct, cands) || crackSingleByte(ct) || crackKnownPrefix(ct);
    if (r) r.blobLength = ct.length;
    return r;
  }

  function recordSolution(name, blobOrCt, r) {
    if (!r) return false;
    if (state.solved.some(function (x) { return x.name === name && x.key === r.key; })) return true;
    state.keys.set(r.key, r.source);
    state.solved.push({ name: name, key: r.key, keySource: r.source, blobLength: r.blobLength, plaintext: r.plaintext });
    say('✅ 解密成功  ' + name);
    say('   XOR 密钥    : ' + JSON.stringify(r.key) + '  (长度 ' + r.key.length + ')  来源: ' + r.source);
    say('   blob 长度   : ' + r.blobLength + ' 字节');
    say('   明文(前 800) : ' + String(r.plaintext).slice(0, 800));
    var j = tryJson(r.plaintext);
    if (j) { try { console.log(TAG + ' 明文已解析为 JSON：', j); } catch (e) {} }
    return true;
  }

  /* ------------------------------------------------------------------ *
   * 3) 两种 gAAAAA 开头的串要分开处理：
   *    形态 A（Fernet）  ：整串就是一个 base64，解码后首字节 0x80
   *                        —— c / token / prepare_token，服务端不透明令牌
   *    形态 B（Sentinel）：7 字符**字面前缀**(gAAAAAB/gAAAAAC) + 一份独立 base64
   *                        —— 解码后是 JSON，即 25 字段指纹数组
   * ------------------------------------------------------------------ */
  function bytesToHex(u8) {
    var s = '';
    for (var i = 0; i < u8.length; i++) s += (u8[i] < 16 ? '0' : '') + u8[i].toString(16);
    return s;
  }

  function decodePayload(token) {
    if (typeof token !== 'string') return null;
    var s = token, solved = false;
    if (s.slice(-2) === '~S') { solved = true; s = s.slice(0, -2); }

    // 形态 A：整串 base64（长度需为 4 的倍数；注意 Fernet 常用 base64url 字母表，含 - 与 _）
    if (s.length % 4 === 0 && /^[A-Za-z0-9+/_-]+={0,2}$/.test(s)) {
      try {
        var whole = b64ToBytes(s);
        if (whole.length > 40 && whole[0] === 0x80) {
          // Fernet: 0x80 | 4 字节 0x00000000 | 4 字节大端时间戳 | 16B IV | 密文 | 32B HMAC
          var ts = 0;
          for (var bi = 1; bi <= 8; bi++) ts = ts * 256 + whole[bi];   // < 2^53，精确
          return {
            prefix: null, solved: solved, bytes: whole.length, kind: 'fernet',
            version: '0x' + whole[0].toString(16),
            timestamp: ts,
            timestampIso: (ts > 1000000000 ? new Date(ts * 1000).toISOString() : null),
            ivHex: bytesToHex(whole.slice(9, 25)),
            hmacHex: bytesToHex(whole.slice(whole.length - 32)),
            note: '服务端 Fernet 不透明令牌（0x80 | 4B 0 | 4B 大端时间戳 | 16B IV | 密文 | 32B HMAC）；客户端只能缓存与回传，无法解析'
          };
        }
      } catch (e) {}
    }

    // 形态 B：7 字符前缀 + 独立 base64(UTF-8 JSON)
    var prefix = s.slice(0, 7), body = s.slice(7), bytes;
    try { bytes = b64ToBytes(body); }
    catch (e) { return { prefix: prefix, solved: solved, kind: 'unknown', error: 'base64 解码失败: ' + e.message }; }
    var text = utf8Decode(bytes);
    if (text === null) {
      return {
        prefix: prefix, solved: solved, bytes: bytes.length, kind: 'binary',
        headHex: bytesToHex(bytes.slice(0, 12)),
        note: '去掉 7 字符后不是 UTF-8 JSON，也不是 0x80 开头的 Fernet（未识别形态）'
      };
    }
    var arr = tryJson(text);
    if (!arr || !Array.isArray(arr)) {
      return { prefix: prefix, solved: solved, bytes: bytes.length, kind: 'unknown', head: String(text).slice(0, 120) };
    }
    return { prefix: prefix, solved: solved, kind: 'sentinel-payload', count: arr.length, fields: arr, raw: text };
  }

  function reportPayload(name, token) {
    var d = decodePayload(token);
    if (!d) return;
    if (d.kind === 'sentinel-payload') {
      say('📦 ' + name + ' —— Sentinel 载荷（前缀 ' + JSON.stringify(d.prefix) + '，solved=' + d.solved + '，' + d.count + ' 字段）');
      d.fields.forEach(function (v, i) {
        say('     [' + (i < 10 ? ' ' : '') + i + '] ' + JSON.stringify(v));
      });
    } else if (d.kind === 'fernet') {
      say('🔒 ' + name + ' —— ' + d.note);
      say('     版本=' + d.version + '  内嵌时间戳=' + d.timestamp + (d.timestampIso ? ' (' + d.timestampIso + ')' : '') +
          '  字节数=' + d.bytes + '  IV=' + d.ivHex + '…');
    } else {
      say('❓ ' + name + ' —— ' + (d.note || JSON.stringify(d)));
    }
  }

  /* ------------------------------------------------------------------ *
   * 4) 网络嗅探（fetch + XHR）
   * ------------------------------------------------------------------ */
  function headersToObject(h) {
    var out = {};
    try {
      if (!h) return out;
      if (typeof Headers !== 'undefined' && h instanceof Headers) {
        h.forEach(function (v, k) { out[String(k).toLowerCase()] = v; });
      } else if (Array.isArray(h)) {
        h.forEach(function (p) { if (p && p.length >= 2) out[String(p[0]).toLowerCase()] = p[1]; });
      } else if (typeof h === 'object') {
        Object.keys(h).forEach(function (k) { out[String(k).toLowerCase()] = h[k]; });
      }
    } catch (e) {}
    return out;
  }

  function shortUrl(u) {
    try { return String(u).replace(/^https?:\/\/[^/]+/, '').slice(0, 70); } catch (e) { return String(u); }
  }

  function handleMaterial(url, headers, body) {
    Object.keys(headers || {}).forEach(function (name) {
      if (name.indexOf('openai-sentinel') !== 0) return;
      var val = headers[name];
      if (typeof val !== 'string') return;

      if (name === 'openai-sentinel-token') {                       // 登录链路：{p,t,c,id,flow}
        var j = tryJson(val);
        if (!j) { warn('openai-sentinel-token 不是 JSON，前 80 字符：' + val.slice(0, 80)); return; }
        say('🎯 抓到 openai-sentinel-token（登录链路）字段：' + Object.keys(j).join(', '));
        if (j.p) { state.envelopes.set('header.p', j.p); reportPayload('openai-sentinel-token.p', j.p); }
        if (j.t) { state.blobs.set('header.t', j.t); tryCrackNow('openai-sentinel-token.t', j.t); }
        if (j.c) { state.envelopes.set('header.c', j.c); reportPayload('openai-sentinel-token.c', j.c); }
        return;
      }
      if (/proof-token$/.test(name)) {
        state.envelopes.set(name, val); reportPayload(name, val);
      } else if (/turnstile-token$/.test(name)) {
        state.blobs.set(name, val); tryCrackNow(name, val);
      } else if (/chat-requirements-token$/.test(name)) {
        state.envelopes.set(name, val); reportPayload(name, val);
      } else {
        say('ℹ️ 抓到其它 sentinel 头 ' + name + '（长度 ' + val.length + '）');
      }
    });

    if (typeof body === 'string' && body.length > 20 && body.charAt(0) === '{') {
      var jb = tryJson(body);
      if (!jb) return;
      if (jb.p) { state.envelopes.set('body.p', jb.p); reportPayload('请求体 p (' + shortUrl(url) + ')', jb.p); }
      if (jb.proofofwork) { state.envelopes.set('body.proofofwork', jb.proofofwork); reportPayload('请求体 proofofwork', jb.proofofwork); }
      if (jb.prepare_token) { state.envelopes.set('body.prepare_token', jb.prepare_token); reportPayload('请求体 prepare_token', jb.prepare_token); }
      if (jb.turnstile) { state.blobs.set('body.turnstile', jb.turnstile); tryCrackNow('请求体 turnstile (' + shortUrl(url) + ')', jb.turnstile); }
    }
  }

  function tryCrackNow(name, blob) {
    if (!looksLikeBlob(blob)) return;
    var r = crack(blob);
    if (recordSolution(name, blob, r)) return;
    say('⏳ 暂未解出 ' + name + '（长度 ' + blob.length + '）：候选密钥 ' + collectCandidates().size +
        ' 个 + 单字节 256 个 + 已知前缀推导均未命中。可等 SDK 跑完再执行 SentinelXOR.retry()');
  }

  function installNetworkHooks() {
    try {
      if (root.fetch && !root.fetch.__sentinelHooked) {
        var origFetch = root.fetch;
        var wrapped = function (input, init) {
          try {
            var url = (typeof input === 'string') ? input : (input && input.url) || '';
            var headers = (init && init.headers) || (input && input.headers) || null;
            var body = (init && init.body) || null;
            handleMaterial(url, headersToObject(headers), typeof body === 'string' ? body : null);
          } catch (e) { warn('fetch hook 异常: ' + e.message); }
          return origFetch.apply(this, arguments);
        };
        wrapped.__sentinelHooked = true;
        root.fetch = wrapped;
      }
    } catch (e) { warn('无法挂钩 fetch: ' + e.message); }

    try {
      if (root.XMLHttpRequest && !root.XMLHttpRequest.prototype.__sentinelHooked) {
        var P = root.XMLHttpRequest.prototype;
        var origOpen = P.open, origSet = P.setRequestHeader, origSend = P.send;
        P.open = function (m, u) { this.__su = u; this.__sh = {}; return origOpen.apply(this, arguments); };
        P.setRequestHeader = function (k, v) {
          try { if (this.__sh) this.__sh[String(k).toLowerCase()] = v; } catch (e) {}
          return origSet.apply(this, arguments);
        };
        P.send = function (b) {
          try { handleMaterial(this.__su || '', this.__sh || {}, typeof b === 'string' ? b : null); } catch (e) {}
          return origSend.apply(this, arguments);
        };
        P.__sentinelHooked = true;
      }
    } catch (e) { warn('无法挂钩 XHR: ' + e.message); }
  }

  /* ------------------------------------------------------------------ *
   * 5) 配对式密钥恢复（最可靠，不依赖任何候选列表）
   *    SDK 的解密形如 JSON.parse(xor(atob(v), key))，xor 内部逐字符调用
   *    String.fromCharCode(ct.charCodeAt(i) ^ key.charCodeAt(i % L))。
   *    同时截获 atob 输出与随后 fromCharCode 的单参调用，即可得
   *        key[i % L] = ct[i] ^ out[i]
   *    再取最小周期即得密钥；最后用 JSON.parse 校验，避免误报。
   * ------------------------------------------------------------------ */
  var pairing = { ct: null, chars: [] };

  function recoverKeyFromPair(ct, out) {
    var n = Math.min(ct.length, out.length);
    if (n < 32) return null;
    var k = new Array(n);
    for (var i = 0; i < n; i++) k[i] = ct.charCodeAt(i) ^ (out[i] & 0xffff);
    var L = -1;
    for (var l = 1; l <= Math.min(128, n); l++) {
      var ok = true;
      for (var j = l; j < n; j++) { if (k[j] !== k[j % l]) { ok = false; break; } }
      if (ok) { L = l; break; }
    }
    if (L < 0) return null;
    var key = '';
    for (var q = 0; q < L; q++) key += ORIG_FCC(k[q]);
    var pt = '';
    for (var p = 0; p < n; p++) pt += ORIG_FCC(out[p] & 0xffff);
    if (!tryJson(pt)) return null;
    return { key: key, source: 'pair(atob ⊕ fromCharCode) 直接还原', plaintext: pt, blobLength: n };
  }

  function installPairingHooks() {
    try {
      if (!root.atob.__sentinelHooked) {
        var wAtob = function (s) {
          var out = ORIG_ATOB.apply(this, arguments);
          try {
            if (typeof out === 'string' && out.length >= 60) pairing = { ct: out, chars: [] };
          } catch (e) {}
          return out;
        };
        wAtob.__sentinelHooked = true;
        root.atob = wAtob;
      }
    } catch (e) { warn('无法挂钩 atob: ' + e.message); }

    try {
      if (!ORIG_FCC.__sentinelHooked) {
        var wFCC = function () {
          try {
            if (pairing.ct && arguments.length === 1) {
              pairing.chars.push(arguments[0]);
              if (pairing.chars.length >= pairing.ct.length) {
                var ct = pairing.ct, chars = pairing.chars;
                pairing = { ct: null, chars: [] };
                var r = recoverKeyFromPair(ct, chars);
                if (r) {
                  var cands = collectCandidates();
                  cands.forEach(function (v, k) { if (v === r.key) r.source = 'pair 还原，且命中 ' + k; });
                  if (!state.keys.has(r.key)) {
                    say('🔑 配对还原出 XOR 密钥：' + JSON.stringify(r.key) + '  （' + r.source + '）');
                  }
                  state.keys.set(r.key, r.source);
                  recordSolution('pair:' + ct.length + 'B', ct, r);
                  return ORIG_FCC.apply(this, arguments);
                }
              }
            }
          } catch (e) {}
          return ORIG_FCC.apply(this, arguments);
        };
        wFCC.__sentinelHooked = true;
        String.fromCharCode = wFCC;
      }
    } catch (e) { warn('无法挂钩 String.fromCharCode: ' + e.message); }
  }

  /* ------------------------------------------------------------------ *
   * 对外 API
   * ------------------------------------------------------------------ */
  function retry() {
    var before = state.solved.length;
    state.blobs.forEach(function (v, k) {
      if (state.solved.some(function (s) { return s.name === k; })) return;
      recordSolution(k, v, crack(v));
    });
    say('retry 完成：新解出 ' + (state.solved.length - before) + ' 个；待解 blob ' + state.blobs.size + ' 个');
    return state.solved.slice();
  }

  function report() {
    return JSON.stringify({
      version: VERSION,
      url: (function () { try { return location.href; } catch (e) { return null; } })(),
      generatedAt: new Date().toISOString(),
      solved: state.solved,
      recoveredKeys: Array.from(state.keys.entries()).map(function (e) { return { key: e[0], source: e[1] }; }),
      capturedBlobs: Array.from(state.blobs.keys()),
      capturedEnvelopes: Array.from(state.envelopes.keys()),
      log: state.log
    }, null, 2);
  }

  function install() {
    if (state.installed) { say('已安装（v' + VERSION + '）'); return api; }
    state.installed = true;
    installPairingHooks();
    installNetworkHooks();
    say('已安装 v' + VERSION + '。现在触发一次校验：');
    say('  · 对话链路：输入框发一条消息（先跑 chat-requirements prepare/finalize）');
    say('  · 登录链路：走一次登录（auth.openai.com 侧发 /sentinel/req 与 password/verify）');
    say('触发后自动打印明文与 XOR 密钥；汇总用 SentinelXOR.report()');
    try { console.log(TAG + ' 当前上下文的 cookie 候选密钥：', Array.from(collectCandidates().keys())); } catch (e) {}
    return api;
  }

  var api = {
    version: VERSION,
    install: install,
    retry: retry,
    report: report,
    collectCandidates: collectCandidates,
    decodePayload: decodePayload,
    xorLatin1: xorLatin1,
    b64ToLatin1: b64ToLatin1,
    crack: crack,
    recoverKeyFromPair: recoverKeyFromPair,
    crackToConsole: function (blob) {
      var r = crack(blob);
      if (!r) {
        warn('未解出。候选密钥 ' + collectCandidates().size + ' 个均失败；可试 SentinelXOR.crackWithKeys(blob, {...}) 手动指定');
        return null;
      }
      console.log(TAG, '解开：', r);
      return r;
    },
    crackWithKeys: function (blob, keysObj) {
      var m = new Map();
      Object.keys(keysObj || {}).forEach(function (k) { m.set(k, keysObj[k]); });
      var ct = b64ToLatin1(blob);
      var r = crackWithCandidates(ct, m) || crackSingleByte(ct) || crackKnownPrefix(ct);
      if (r) { r.blobLength = ct.length; console.log(TAG, '解开：', r); } else { warn('未解出'); }
      return r;
    },
    state: state
  };

  root.SentinelXOR = api;
  say('已加载 v' + VERSION);
  try { install(); } catch (e) { warn('自动安装失败，请手动执行 SentinelXOR.install()：' + e.message); }

  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
