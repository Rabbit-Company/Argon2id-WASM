import init, {argon2id_hash} from "./argon2id_wasm.js";

export default class Argon2id{

	static hexToBase64(hexstring) {
		return btoa(hexstring.match(/\w{2}/g).map(function(a) {
			return String.fromCharCode(parseInt(a, 16));
		}).join(""));
	}

	static base64ToHex(str) {
		const raw = atob(str);
		let result = '';
		for (let i = 0; i < raw.length; i++) {
			const hex = raw.charCodeAt(i).toString(16);
			result += (hex.length === 2 ? hex : '0' + hex);
		}
		return result.toUpperCase();
	}

	static randRange(min, max) {
		var range = max - min;
		var requestBytes = Math.ceil(Math.log2(range) / 8);
		if (!requestBytes) return min;

		var maxNum = Math.pow(256, requestBytes);
		var ar = new Uint8Array(requestBytes);

		while (true) {
			window.crypto.getRandomValues(ar);
			var val = 0;
			for (var i = 0;i < requestBytes;i++) val = (val << 8) + ar[i];
			if (val < maxNum - maxNum % range) return min + (val % range);
		}
	}

	static randomSalt(){
		let length = 16;
		let lcase = "abcdefghijklmnopqrstuvwxyz";
		let ucase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		let numb = "1234567890";

		let salt = "";
		for (let i = 0; i < length; i++) salt += lcase.charAt(this.randRange(0, lcase.length));
		salt = salt.split("");
		for (let i = 0; i < length/2; i++) salt[this.randRange(0, salt.length)] = ucase.charAt(this.randRange(0, ucase.length));
		for (let i = 0; i < length/2; i++) salt[this.randRange(0, salt.length)] = numb.charAt(this.randRange(0, numb.length));
		return salt.join("");
	}

	static hash = (message, salt = Argon2id.randomSalt(), p=4, m=16, t=3, l=32) => new Promise((res, rej) => {
		if(m <= 20) m = Math.pow(2, m);

		if(window.Worker){
			const Argon2idWorker = new Worker("Argon2idWorker.js", { type: 'module' });

			Argon2idWorker.onmessage = ({data}) => {
				Argon2idWorker.terminate();
				if(data.error) rej(data.error);
				res(data.output);
			}

			Argon2idWorker.postMessage([message, salt, p, m, t, l]);
		}else{
			init().then(() => {
				res(argon2id_hash(message, salt, p, m, t, l));
			}).catch(err => {
				rej(err);
			});
		}
	});

	static hashEncoded = (message, salt = Argon2id.randomSalt(), p=4, m=16, t=3, l=32) => new Promise((res, rej) => {
		if(m <= 20) m = Math.pow(2, m);
		this.hash(message, salt, p, m, t, l).then(output => {
			res(`$argon2id$v=19$m=${m},t=${t},p=${p}$${btoa(salt).replaceAll("=", "")}$${this.hexToBase64(output).replaceAll("=", "")}`);
		}).catch(err => {
			rej(err);
		});
	});

	static hashDecode(hashEncoded){
		let digest = hashEncoded.split('$')[5];
		return this.base64ToHex(digest).toLowerCase();
	}

	static verify = (hashEncoded, message) => new Promise((res, rej) => {
		let hea = hashEncoded.split('$');
		if(hea.length != 6) rej("invalid hash");
		if(hea[1] != "argon2id") rej("unsupported algorithm");
		if(hea[2] != "v=19") rej("unsupported version");

		let hpa = hea[3].split(',');
		if(hpa.length != 3) rej("invalid hash");

		let m = hpa[0].split('=')[1];
		let t = hpa[1].split('=')[1];
		let p = hpa[2].split('=')[1];
		let salt = atob(hea[4]);
		let digest = Argon2id.hashDecode(hashEncoded);

		Argon2id.hash(message, salt, p, m, t, digest.length/2).then(output => {
			res(output === digest);
		}).catch(err => {
			rej(err);
		});
	});
}