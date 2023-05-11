import init, {argon2id_hash} from "./argon2id_wasm.js";

onmessage = (e) => {
	init().then(() => {
		postMessage({ output: argon2id_hash(e.data[0], e.data[1], e.data[2], e.data[3], e.data[4], e.data[5]) });
	}).catch(error =>{
		postMessage({error})
	});
}