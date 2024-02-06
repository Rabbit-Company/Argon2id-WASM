var getUint8Memory0=function(){if(cachedUint8Memory0===null||cachedUint8Memory0.byteLength===0)cachedUint8Memory0=new Uint8Array(wasm.memory.buffer);return cachedUint8Memory0},getStringFromWasm0=function(ptr,len){return ptr=ptr>>>0,cachedTextDecoder.decode(getUint8Memory0().subarray(ptr,ptr+len))},addHeapObject=function(obj){if(heap_next===heap.length)heap.push(heap.length+1);const idx=heap_next;return heap_next=heap[idx],heap[idx]=obj,idx},passStringToWasm0=function(arg,malloc,realloc){if(realloc===void 0){const buf=cachedTextEncoder.encode(arg),ptr2=malloc(buf.length,1)>>>0;return getUint8Memory0().subarray(ptr2,ptr2+buf.length).set(buf),WASM_VECTOR_LEN=buf.length,ptr2}let len=arg.length,ptr=malloc(len,1)>>>0;const mem=getUint8Memory0();let offset=0;for(;offset<len;offset++){const code=arg.charCodeAt(offset);if(code>127)break;mem[ptr+offset]=code}if(offset!==len){if(offset!==0)arg=arg.slice(offset);ptr=realloc(ptr,len,len=offset+arg.length*3,1)>>>0;const view=getUint8Memory0().subarray(ptr+offset,ptr+len),ret=encodeString(arg,view);offset+=ret.written}return WASM_VECTOR_LEN=offset,ptr},getInt32Memory0=function(){if(cachedInt32Memory0===null||cachedInt32Memory0.byteLength===0)cachedInt32Memory0=new Int32Array(wasm.memory.buffer);return cachedInt32Memory0},getObject=function(idx){return heap[idx]},dropObject=function(idx){if(idx<132)return;heap[idx]=heap_next,heap_next=idx},takeObject=function(idx){const ret=getObject(idx);return dropObject(idx),ret};function argon2id_hash(message,salt,parallelism,memory,iterations,length){let deferred4_0,deferred4_1;try{const retptr=wasm.__wbindgen_add_to_stack_pointer(-16),ptr0=passStringToWasm0(message,wasm.__wbindgen_malloc,wasm.__wbindgen_realloc),len0=WASM_VECTOR_LEN,ptr1=passStringToWasm0(salt,wasm.__wbindgen_malloc,wasm.__wbindgen_realloc),len1=WASM_VECTOR_LEN;wasm.argon2id_hash(retptr,ptr0,len0,ptr1,len1,parallelism,memory,iterations,length);var r0=getInt32Memory0()[retptr/4+0],r1=getInt32Memory0()[retptr/4+1],r2=getInt32Memory0()[retptr/4+2],r3=getInt32Memory0()[retptr/4+3],ptr3=r0,len3=r1;if(r3)throw ptr3=0,len3=0,takeObject(r2);return deferred4_0=ptr3,deferred4_1=len3,getStringFromWasm0(ptr3,len3)}finally{wasm.__wbindgen_add_to_stack_pointer(16),wasm.__wbindgen_free(deferred4_0,deferred4_1,1)}}async function __wbg_load(module,imports){if(typeof Response==="function"&&module instanceof Response){if(typeof WebAssembly.instantiateStreaming==="function")try{return await WebAssembly.instantiateStreaming(module,imports)}catch(e){if(module.headers.get("Content-Type")!="application/wasm")console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n",e);else throw e}const bytes=await module.arrayBuffer();return await WebAssembly.instantiate(bytes,imports)}else{const instance=await WebAssembly.instantiate(module,imports);if(instance instanceof WebAssembly.Instance)return{instance,module};else return instance}}var __wbg_get_imports=function(){const imports={};return imports.wbg={},imports.wbg.__wbindgen_string_new=function(arg0,arg1){const ret=getStringFromWasm0(arg0,arg1);return addHeapObject(ret)},imports},__wbg_init_memory=function(imports,maybe_memory){},__wbg_finalize_init=function(instance,module){return wasm=instance.exports,__wbg_init.__wbindgen_wasm_module=module,cachedInt32Memory0=null,cachedUint8Memory0=null,wasm};async function __wbg_init(input){if(wasm!==void 0)return wasm;if(typeof input==="undefined")input=new URL("argon2id_wasm_bg.wasm",import.meta.url);const imports=__wbg_get_imports();if(typeof input==="string"||typeof Request==="function"&&input instanceof Request||typeof URL==="function"&&input instanceof URL)input=fetch(input);__wbg_init_memory(imports);const{instance,module}=await __wbg_load(await input,imports);return __wbg_finalize_init(instance,module)}var wasm,cachedTextDecoder=typeof TextDecoder!=="undefined"?new TextDecoder("utf-8",{ignoreBOM:!0,fatal:!0}):{decode:()=>{throw Error("TextDecoder not available")}};if(typeof TextDecoder!=="undefined")cachedTextDecoder.decode();var cachedUint8Memory0=null,heap=new Array(128).fill(void 0);heap.push(void 0,null,!0,!1);var heap_next=heap.length,WASM_VECTOR_LEN=0,cachedTextEncoder=typeof TextEncoder!=="undefined"?new TextEncoder("utf-8"):{encode:()=>{throw Error("TextEncoder not available")}},encodeString=typeof cachedTextEncoder.encodeInto==="function"?function(arg,view){return cachedTextEncoder.encodeInto(arg,view)}:function(arg,view){const buf=cachedTextEncoder.encode(arg);return view.set(buf),{read:arg.length,written:buf.length}},cachedInt32Memory0=null;var argon2id_wasm_default=__wbg_init;onmessage=(e)=>{argon2id_wasm_default().then(()=>{postMessage({output:argon2id_hash(e.data[0],e.data[1],e.data[2],e.data[3],e.data[4],e.data[5])})}).catch((error)=>{postMessage({error})})};
