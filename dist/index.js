function U(){if(M===null||M.byteLength===0)M=new Uint8Array(Y.memory.buffer);return M}function x(I,H){return I=I>>>0,w.decode(U().subarray(I,I+H))}function d(I){if(O===P.length)P.push(P.length+1);const H=O;return O=P[H],P[H]=I,H}function u(I,H,D){if(D===void 0){const X=W.encode(I),L=H(X.length,1)>>>0;return U().subarray(L,L+X.length).set(X),A=X.length,L}let G=I.length,J=H(G,1)>>>0;const k=U();let K=0;for(;K<G;K++){const X=I.charCodeAt(K);if(X>127)break;k[J+K]=X}if(K!==G){if(K!==0)I=I.slice(K);J=D(J,G,G=K+I.length*3,1)>>>0;const X=U().subarray(J+K,J+G),L=p(I,X);K+=L.written}return A=K,J}function R(){if(N===null||N.byteLength===0)N=new Int32Array(Y.memory.buffer);return N}function g(I){return P[I]}function o(I){if(I<132)return;P[I]=O,O=I}function m(I){const H=g(I);return o(I),H}function c(I,H,D,G,J,k){let K,X;try{const Q=Y.__wbindgen_add_to_stack_pointer(-16),v=u(I,Y.__wbindgen_malloc,Y.__wbindgen_realloc),Z=A,z=u(H,Y.__wbindgen_malloc,Y.__wbindgen_realloc),b=A;Y.argon2id_hash(Q,v,Z,z,b,D,G,J,k);var L=R()[Q/4+0],$=R()[Q/4+1],F=R()[Q/4+2],E=R()[Q/4+3],B=L,T=$;if(E)throw B=0,T=0,m(F);return K=B,X=T,x(B,T)}finally{Y.__wbindgen_add_to_stack_pointer(16),Y.__wbindgen_free(K,X,1)}}async function t(I,H){if(typeof Response==="function"&&I instanceof Response){if(typeof WebAssembly.instantiateStreaming==="function")try{return await WebAssembly.instantiateStreaming(I,H)}catch(G){if(I.headers.get("Content-Type")!="application/wasm")console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n",G);else throw G}const D=await I.arrayBuffer();return await WebAssembly.instantiate(D,H)}else{const D=await WebAssembly.instantiate(I,H);if(D instanceof WebAssembly.Instance)return{instance:D,module:I};else return D}}function s(){const I={};return I.wbg={},I.wbg.__wbindgen_string_new=function(H,D){const G=x(H,D);return d(G)},I}function i(I,H){}function a(I,H){return Y=I.exports,l.__wbindgen_wasm_module=H,N=null,M=null,Y}async function l(I){if(Y!==void 0)return Y;if(typeof I==="undefined")I=new URL("argon2id_wasm_bg.wasm",import.meta.url);const H=s();if(typeof I==="string"||typeof Request==="function"&&I instanceof Request||typeof URL==="function"&&I instanceof URL)I=fetch(I);i(H);const{instance:D,module:G}=await t(await I,H);return a(D,G)}var Y,w=typeof TextDecoder!=="undefined"?new TextDecoder("utf-8",{ignoreBOM:!0,fatal:!0}):{decode:()=>{throw Error("TextDecoder not available")}};if(typeof TextDecoder!=="undefined")w.decode();var M=null,P=new Array(128).fill(void 0);P.push(void 0,null,!0,!1);var O=P.length,A=0,W=typeof TextEncoder!=="undefined"?new TextEncoder("utf-8"):{encode:()=>{throw Error("TextEncoder not available")}},p=typeof W.encodeInto==="function"?function(I,H){return W.encodeInto(I,H)}:function(I,H){const D=W.encode(I);return H.set(D),{read:I.length,written:D.length}},N=null;var n=l;var q;((V)=>{function I(L){return btoa((L.match(/\w{2}/g)||[]).map(function($){return String.fromCharCode(parseInt($,16))}).join(""))}V.hexToBase64=I;function H(L){const $=atob(L);let F="";for(let E=0;E<$.length;E++){const B=$.charCodeAt(E).toString(16);F+=B.length===2?B:"0"+B}return F.toUpperCase()}V.base64ToHex=H;function D(L,$){var F=$-L,E=Math.ceil(Math.log2(F)/8);if(!E)return L;var B=Math.pow(256,E),T=new Uint8Array(E);while(!0){window.crypto.getRandomValues(T);var Q=0;for(var v=0;v<E;v++)Q=(Q<<8)+T[v];if(Q<B-B%F)return L+Q%F}}V.randRange=D;function G(){let L=16,$="abcdefghijklmnopqrstuvwxyz",F="ABCDEFGHIJKLMNOPQRSTUVWXYZ",E="1234567890",B=[];for(let T=0;T<L;T++)B.push($.charAt(D(0,$.length)));for(let T=0;T<L/2;T++)B[D(0,B.length)]=F.charAt(D(0,F.length));for(let T=0;T<L/2;T++)B[D(0,B.length)]=E.charAt(D(0,E.length));return B.join("")}V.randomSalt=G,V.hash=(L,$=q.randomSalt(),F=4,E=16,B=3,T=32)=>new Promise((Q,v)=>{if(E<=20)E=Math.pow(2,E);if(window.Worker){const Z=new Worker("argon2id_worker.js",{type:"module"});Z.onmessage=({data:z})=>{if(Z.terminate(),z.error)v(z.error);Q(z.output)},Z.postMessage([L,$,F,E,B,T])}else n().then(()=>{Q(c(L,$,F,E,B,T))}).catch((Z)=>{v(Z)})}),V.hashEncoded=(L,$=q.randomSalt(),F=4,E=16,B=3,T=32)=>new Promise((Q,v)=>{if(E<=20)E=Math.pow(2,E);V.hash(L,$,F,E,B,T).then((Z)=>{Q(`\$argon2id\$v=19\$m=${E},t=${B},p=${F}\$${btoa($).replaceAll("=","")}\$${I(Z).replaceAll("=","")}`)}).catch((Z)=>{v(Z)})});function K(L){let $=L.split("$")[5];return H($).toLowerCase()}V.hashDecode=K,V.verify=(L,$)=>new Promise((F,E)=>{let B=L.split("$");if(B.length!=6)E("invalid hash");if(B[1]!="argon2id")E("unsupported algorithm");if(B[2]!="v=19")E("unsupported version");let T=B[3].split(",");if(T.length!=3)E("invalid hash");let Q=parseInt(T[0].split("=")[1],10),v=parseInt(T[1].split("=")[1],10),Z=parseInt(T[2].split("=")[1],10),z=atob(B[4]),b=q.hashDecode(L);q.hash($,z,Z,Q,v,b.length/2).then((j)=>{F(j===b)}).catch((j)=>{E(j)})})})(q||={});var S=q;function h(I){return Date.now()-I}var _=document.getElementById("salt"),e=document.getElementById("message"),r=document.getElementById("message2"),II=document.getElementById("p"),HI=document.getElementById("m"),LI=document.getElementById("t"),EI=document.getElementById("l"),BI=document.getElementById("hashEncoded"),f=document.getElementById("hash"),C=document.getElementById("perf"),y=document.getElementById("validate");_.value=S.randomSalt();document.getElementById("hashForm")?.addEventListener("submit",(I)=>{if(I.preventDefault(),!f||!C)return;let H=e.value,D=_.value,G=parseInt(II.value,10),J=parseInt(HI.value,10),k=parseInt(LI.value,10),K=parseInt(EI.value,10),X=Date.now();S.hashEncoded(H,D,G,J,k,K).then((L)=>{let $=S.hashDecode(L),F=h(X);f.innerHTML="<b>Hash:</b> "+$+"<br/><b>Hash Encoded:</b> "+L,C.innerHTML="Hashing the message took <b>"+F+"ms</b>."}).catch((L)=>{f.innerHTML=`Hashing failed because of <b>${L}</b>`,C.innerHTML=""})});document.getElementById("verifyForm")?.addEventListener("submit",(I)=>{if(I.preventDefault(),!C||!y)return;let H=r.value,D=BI.value,G=Date.now();S.verify(D,H).then((J)=>{let k=h(G);if(J)y.innerHTML="The message <b>DOES</b> match the supplied hash.";if(!J)y.innerHTML="The message does <b>NOT</b> match the supplied hash.";C.innerHTML="Verifying the message took <b>"+k+"ms</b>."}).catch((J)=>{y.innerHTML=`Validation failed because of <b>${J}</b>`,C.innerHTML=""})});