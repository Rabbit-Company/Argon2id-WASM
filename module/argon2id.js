// src/argon2id_wasm.js
function getUint8Memory0() {
  if (cachedUint8Memory0 === null || cachedUint8Memory0.byteLength === 0) {
    cachedUint8Memory0 = new Uint8Array(wasm.memory.buffer);
  }
  return cachedUint8Memory0;
}
function getStringFromWasm0(ptr, len) {
  ptr = ptr >>> 0;
  return cachedTextDecoder.decode(getUint8Memory0().subarray(ptr, ptr + len));
}
function addHeapObject(obj) {
  if (heap_next === heap.length)
    heap.push(heap.length + 1);
  const idx = heap_next;
  heap_next = heap[idx];
  heap[idx] = obj;
  return idx;
}
function passStringToWasm0(arg, malloc, realloc) {
  if (realloc === undefined) {
    const buf = cachedTextEncoder.encode(arg);
    const ptr2 = malloc(buf.length, 1) >>> 0;
    getUint8Memory0().subarray(ptr2, ptr2 + buf.length).set(buf);
    WASM_VECTOR_LEN = buf.length;
    return ptr2;
  }
  let len = arg.length;
  let ptr = malloc(len, 1) >>> 0;
  const mem = getUint8Memory0();
  let offset = 0;
  for (;offset < len; offset++) {
    const code = arg.charCodeAt(offset);
    if (code > 127)
      break;
    mem[ptr + offset] = code;
  }
  if (offset !== len) {
    if (offset !== 0) {
      arg = arg.slice(offset);
    }
    ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
    const view = getUint8Memory0().subarray(ptr + offset, ptr + len);
    const ret = encodeString(arg, view);
    offset += ret.written;
  }
  WASM_VECTOR_LEN = offset;
  return ptr;
}
function getInt32Memory0() {
  if (cachedInt32Memory0 === null || cachedInt32Memory0.byteLength === 0) {
    cachedInt32Memory0 = new Int32Array(wasm.memory.buffer);
  }
  return cachedInt32Memory0;
}
function getObject(idx) {
  return heap[idx];
}
function dropObject(idx) {
  if (idx < 132)
    return;
  heap[idx] = heap_next;
  heap_next = idx;
}
function takeObject(idx) {
  const ret = getObject(idx);
  dropObject(idx);
  return ret;
}
function argon2id_hash(message, salt, parallelism, memory, iterations, length) {
  let deferred4_0;
  let deferred4_1;
  try {
    const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
    const ptr0 = passStringToWasm0(message, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(salt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    wasm.argon2id_hash(retptr, ptr0, len0, ptr1, len1, parallelism, memory, iterations, length);
    var r0 = getInt32Memory0()[retptr / 4 + 0];
    var r1 = getInt32Memory0()[retptr / 4 + 1];
    var r2 = getInt32Memory0()[retptr / 4 + 2];
    var r3 = getInt32Memory0()[retptr / 4 + 3];
    var ptr3 = r0;
    var len3 = r1;
    if (r3) {
      ptr3 = 0;
      len3 = 0;
      throw takeObject(r2);
    }
    deferred4_0 = ptr3;
    deferred4_1 = len3;
    return getStringFromWasm0(ptr3, len3);
  } finally {
    wasm.__wbindgen_add_to_stack_pointer(16);
    wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
  }
}
async function __wbg_load(module, imports) {
  if (typeof Response === "function" && module instanceof Response) {
    if (typeof WebAssembly.instantiateStreaming === "function") {
      try {
        return await WebAssembly.instantiateStreaming(module, imports);
      } catch (e) {
        if (module.headers.get("Content-Type") != "application/wasm") {
          console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);
        } else {
          throw e;
        }
      }
    }
    const bytes = await module.arrayBuffer();
    return await WebAssembly.instantiate(bytes, imports);
  } else {
    const instance = await WebAssembly.instantiate(module, imports);
    if (instance instanceof WebAssembly.Instance) {
      return { instance, module };
    } else {
      return instance;
    }
  }
}
function __wbg_get_imports() {
  const imports = {};
  imports.wbg = {};
  imports.wbg.__wbindgen_string_new = function(arg0, arg1) {
    const ret = getStringFromWasm0(arg0, arg1);
    return addHeapObject(ret);
  };
  return imports;
}
function __wbg_init_memory(imports, maybe_memory) {
}
function __wbg_finalize_init(instance, module) {
  wasm = instance.exports;
  __wbg_init.__wbindgen_wasm_module = module;
  cachedInt32Memory0 = null;
  cachedUint8Memory0 = null;
  return wasm;
}
async function __wbg_init(input) {
  if (wasm !== undefined)
    return wasm;
  if (typeof input === "undefined") {
    input = new URL("argon2id_wasm_bg.wasm", import.meta.url);
  }
  const imports = __wbg_get_imports();
  if (typeof input === "string" || typeof Request === "function" && input instanceof Request || typeof URL === "function" && input instanceof URL) {
    input = fetch(input);
  }
  __wbg_init_memory(imports);
  const { instance, module } = await __wbg_load(await input, imports);
  return __wbg_finalize_init(instance, module);
}
var wasm;
var cachedTextDecoder = typeof TextDecoder !== "undefined" ? new TextDecoder("utf-8", { ignoreBOM: true, fatal: true }) : { decode: () => {
  throw Error("TextDecoder not available");
} };
if (typeof TextDecoder !== "undefined") {
  cachedTextDecoder.decode();
}
var cachedUint8Memory0 = null;
var heap = new Array(128).fill(undefined);
heap.push(undefined, null, true, false);
var heap_next = heap.length;
var WASM_VECTOR_LEN = 0;
var cachedTextEncoder = typeof TextEncoder !== "undefined" ? new TextEncoder("utf-8") : { encode: () => {
  throw Error("TextEncoder not available");
} };
var encodeString = typeof cachedTextEncoder.encodeInto === "function" ? function(arg, view) {
  return cachedTextEncoder.encodeInto(arg, view);
} : function(arg, view) {
  const buf = cachedTextEncoder.encode(arg);
  view.set(buf);
  return {
    read: arg.length,
    written: buf.length
  };
};
var cachedInt32Memory0 = null;
var argon2id_wasm_default = __wbg_init;

// src/argon2id.ts
var Argon2id;
((Argon2id) => {
  function hexToBase64(hexstring) {
    return btoa((hexstring.match(/\w{2}/g) || []).map(function(a) {
      return String.fromCharCode(parseInt(a, 16));
    }).join(""));
  }
  Argon2id.hexToBase64 = hexToBase64;
  function base64ToHex(str) {
    const raw = atob(str);
    let result = "";
    for (let i = 0;i < raw.length; i++) {
      const hex = raw.charCodeAt(i).toString(16);
      result += hex.length === 2 ? hex : "0" + hex;
    }
    return result.toUpperCase();
  }
  Argon2id.base64ToHex = base64ToHex;
  function randRange(min, max) {
    var range = max - min;
    var requestBytes = Math.ceil(Math.log2(range) / 8);
    if (!requestBytes)
      return min;
    var maxNum = Math.pow(256, requestBytes);
    var ar = new Uint8Array(requestBytes);
    while (true) {
      window.crypto.getRandomValues(ar);
      var val = 0;
      for (var i = 0;i < requestBytes; i++)
        val = (val << 8) + ar[i];
      if (val < maxNum - maxNum % range)
        return min + val % range;
    }
  }
  Argon2id.randRange = randRange;
  function randomSalt() {
    let length = 16;
    let lcase = "abcdefghijklmnopqrstuvwxyz";
    let ucase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let numb = "1234567890";
    let salt = [];
    for (let i = 0;i < length; i++)
      salt.push(lcase.charAt(randRange(0, lcase.length)));
    for (let i = 0;i < length / 2; i++)
      salt[randRange(0, salt.length)] = ucase.charAt(randRange(0, ucase.length));
    for (let i = 0;i < length / 2; i++)
      salt[randRange(0, salt.length)] = numb.charAt(randRange(0, numb.length));
    return salt.join("");
  }
  Argon2id.randomSalt = randomSalt;
  Argon2id.hash = (message, salt = Argon2id.randomSalt(), p = 4, m = 16, t = 3, l = 32) => new Promise((res, rej) => {
    if (m <= 20)
      m = Math.pow(2, m);
    if (window.Worker) {
      const Argon2idWorker = new Worker("argon2id_worker.js", { type: "module" });
      Argon2idWorker.onmessage = ({ data }) => {
        Argon2idWorker.terminate();
        if (data.error)
          rej(data.error);
        res(data.output);
      };
      Argon2idWorker.postMessage([message, salt, p, m, t, l]);
    } else {
      argon2id_wasm_default().then(() => {
        res(argon2id_hash(message, salt, p, m, t, l));
      }).catch((err) => {
        rej(err);
      });
    }
  });
  Argon2id.hashEncoded = (message, salt = Argon2id.randomSalt(), p = 4, m = 16, t = 3, l = 32) => new Promise((res, rej) => {
    if (m <= 20)
      m = Math.pow(2, m);
    Argon2id.hash(message, salt, p, m, t, l).then((output) => {
      res(`\$argon2id\$v=19\$m=${m},t=${t},p=${p}\$${btoa(salt).replaceAll("=", "")}\$${hexToBase64(output).replaceAll("=", "")}`);
    }).catch((err) => {
      rej(err);
    });
  });
  function hashDecode(hashEncoded2) {
    let digest = hashEncoded2.split("$")[5];
    return base64ToHex(digest).toLowerCase();
  }
  Argon2id.hashDecode = hashDecode;
  Argon2id.verify = (hashEncoded2, message) => new Promise((res, rej) => {
    let hea = hashEncoded2.split("$");
    if (hea.length != 6)
      rej("invalid hash");
    if (hea[1] != "argon2id")
      rej("unsupported algorithm");
    if (hea[2] != "v=19")
      rej("unsupported version");
    let hpa = hea[3].split(",");
    if (hpa.length != 3)
      rej("invalid hash");
    let m = parseInt(hpa[0].split("=")[1], 10);
    let t = parseInt(hpa[1].split("=")[1], 10);
    let p = parseInt(hpa[2].split("=")[1], 10);
    let salt = atob(hea[4]);
    let digest = Argon2id.hashDecode(hashEncoded2);
    Argon2id.hash(message, salt, p, m, t, digest.length / 2).then((output) => {
      res(output === digest);
    }).catch((err) => {
      rej(err);
    });
  });
})(Argon2id ||= {});
var argon2id_default = Argon2id;
export {
  argon2id_default as default
};