import init, { argon2id_hash } from "./argon2id_wasm.js";

/**
 * Namespace for Argon2id hashing operations, providing functions for hashing messages, encoding and decoding hashes,
 * and generating random salts.
 *
 * This namespace utilizes the Argon2id algorithm, a memory-hard password hashing scheme that is resistant to GPU attacks
 * and optimized for secure password storage. It also includes utility functions for encoding and decoding hexadecimal
 * and base64 strings.
 */
namespace Argon2id {
	/**
	 * Converts a hexadecimal string to its equivalent base64 encoded string.
	 *
	 * This function takes a string of hexadecimal characters and converts each pair of hex digits
	 * into a corresponding ASCII character, then encodes the result in base64.
	 *
	 * @param {string} hexstring - The input string in hexadecimal format.
	 * @returns {string} The resulting string encoded in base64.
	 */
	export function hexToBase64(hexstring: string): string {
		return btoa(
			(hexstring.match(/\w{2}/g) || [])
				.map(function (a) {
					return String.fromCharCode(parseInt(a, 16));
				})
				.join("")
		);
	}

	/**
	 * Converts a base64 encoded string back to its hexadecimal representation.
	 *
	 * This function decodes a base64 string to its original binary form and then converts
	 * each byte to a two-character hexadecimal string.
	 *
	 * @param {string} str - The input string in base64 format.
	 * @returns {string} The resulting string in hexadecimal format.
	 */
	export function base64ToHex(str: string): string {
		const raw = atob(str);
		let result = "";
		for (let i = 0; i < raw.length; i++) {
			const hex = raw.charCodeAt(i).toString(16);
			result += hex.length === 2 ? hex : "0" + hex;
		}
		return result.toUpperCase();
	}

	/**
	 * Generates a random integer within a specified range [min, max).
	 *
	 * This function uses cryptographic randomness to ensure that the result is unpredictable
	 * and secure, suitable for generating cryptographic salts or keys.
	 *
	 * @param {number} min - The minimum value of the range (inclusive).
	 * @param {number} max - The maximum value of the range (exclusive).
	 * @returns {number} A securely generated random integer within the specified range.
	 */
	export function randRange(min: number, max: number): number {
		var range = max - min;
		var requestBytes = Math.ceil(Math.log2(range) / 8);
		if (!requestBytes) return min;

		var maxNum = Math.pow(256, requestBytes);
		var ar = new Uint8Array(requestBytes);

		while (true) {
			window.crypto.getRandomValues(ar);
			var val = 0;
			for (var i = 0; i < requestBytes; i++) val = (val << 8) + ar[i];
			if (val < maxNum - (maxNum % range)) return min + (val % range);
		}
	}

	/**
	 * Generates a random salt string for use in cryptographic hashing.
	 *
	 * The salt is composed of lowercase letters, uppercase letters, and digits, ensuring a high
	 * level of entropy and security. This function is typically used to generate salts for password hashing.
	 *
	 * @returns {string} A 16-character random salt string.
	 */
	export function randomSalt(): string {
		let length = 16;
		let lcase = "abcdefghijklmnopqrstuvwxyz";
		let ucase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		let numb = "1234567890";

		let salt: string[] = [];
		for (let i = 0; i < length; i++) salt.push(lcase.charAt(randRange(0, lcase.length)));
		for (let i = 0; i < length / 2; i++) salt[randRange(0, salt.length)] = ucase.charAt(randRange(0, ucase.length));
		for (let i = 0; i < length / 2; i++) salt[randRange(0, salt.length)] = numb.charAt(randRange(0, numb.length));
		return salt.join("");
	}

	/**
	 * Hashes a given message using the Argon2id algorithm with specified parameters.
	 *
	 * This function uses either a Web Worker for hashing if supported, or falls back to a
	 * synchronous method using WebAssembly. The resulting hash is returned as a hexadecimal string.
	 *
	 * @param {string} message - The input message to hash.
	 * @param {string} [salt=Argon2id.randomSalt()] - The salt to use for hashing. Defaults to a randomly generated salt.
	 * @param {number} [p=4] - The degree of parallelism (number of threads).
	 * @param {number} [m=16] - The memory cost in kilobytes. If m ≤ 20, it is treated as a power of two.
	 * @param {number} [t=3] - The number of iterations (time cost).
	 * @param {number} [l=32] - The desired length of the resulting hash in bytes.
	 * @returns {Promise<string>} A promise that resolves to the hash of the message in hexadecimal format.
	 */
	export const hash = (message: string, salt: string = Argon2id.randomSalt(), p: number = 4, m: number = 16, t: number = 3, l: number = 32): Promise<string> =>
		new Promise((res, rej) => {
			if (m <= 20) m = Math.pow(2, m);

			if (window.Worker) {
				const Argon2idWorker = new Worker("argon2id_worker.js", { type: "module" });

				Argon2idWorker.onmessage = ({ data }) => {
					Argon2idWorker.terminate();
					if (data.error) rej(data.error);
					res(data.output);
				};

				Argon2idWorker.postMessage([message, salt, p, m, t, l]);
			} else {
				init()
					.then(() => {
						res(argon2id_hash(message, salt, p, m, t, l));
					})
					.catch((err) => {
						rej(err);
					});
			}
		});

	/**
	 * Hashes a message using the Argon2id algorithm and encodes it in a specific format.
	 *
	 * The resulting string follows the format:
	 * `$argon2id$v=19$m=<memory>,t=<iterations>,p=<parallelism>$<salt>$<hash>`,
	 * where the hash is encoded in base64.
	 *
	 * @param {string} message - The input message to hash.
	 * @param {string} [salt=Argon2id.randomSalt()] - The salt to use for hashing. Defaults to a randomly generated salt.
	 * @param {number} [p=4] - The degree of parallelism (number of threads).
	 * @param {number} [m=16] - The memory cost in kilobytes.
	 * @param {number} [t=3] - The number of iterations (time cost).
	 * @param {number} [l=32] - The desired length of the resulting hash in bytes.
	 * @returns {Promise<string>} A promise that resolves to the encoded hash string.
	 */
	export const hashEncoded = (message: string, salt = Argon2id.randomSalt(), p = 4, m = 16, t = 3, l = 32): Promise<string> =>
		new Promise((res, rej) => {
			if (m <= 20) m = Math.pow(2, m);
			hash(message, salt, p, m, t, l)
				.then((output) => {
					res(`$argon2id$v=19$m=${m},t=${t},p=${p}$${btoa(salt).replaceAll("=", "")}$${hexToBase64(output).replaceAll("=", "")}`);
				})
				.catch((err) => {
					rej(err);
				});
		});

	/**
	 * Extracts the hexadecimal digest from an encoded Argon2id hash string.
	 *
	 * This function decodes the base64 encoded digest part of the encoded hash string, converting
	 * it back to its original hexadecimal form.
	 *
	 * @param {string} hashEncoded - The encoded hash string to decode.
	 * @returns {string} The extracted hexadecimal digest.
	 */
	export function hashDecode(hashEncoded: string): string {
		let digest = hashEncoded.split("$")[5];
		return base64ToHex(digest).toLowerCase();
	}

	/**
	 * Verifies whether a given message matches a specified Argon2id hash.
	 *
	 * The function compares the hash of the input message with the provided encoded hash string,
	 * returning true if they match, and false otherwise.
	 *
	 * @param {string} hashEncoded - The encoded hash string to verify against.
	 * @param {string} message - The message to verify.
	 * @returns {Promise<boolean>} A promise that resolves to a boolean indicating whether the message matches the hash.
	 */
	export const verify = (hashEncoded: string, message: string): Promise<boolean> =>
		new Promise((res, rej) => {
			let hea = hashEncoded.split("$");
			if (hea.length != 6) rej("invalid hash");
			if (hea[1] != "argon2id") rej("unsupported algorithm");
			if (hea[2] != "v=19") rej("unsupported version");

			let hpa = hea[3].split(",");
			if (hpa.length != 3) rej("invalid hash");

			let m = parseInt(hpa[0].split("=")[1], 10);
			let t = parseInt(hpa[1].split("=")[1], 10);
			let p = parseInt(hpa[2].split("=")[1], 10);
			let salt = atob(hea[4]);
			let digest = Argon2id.hashDecode(hashEncoded);

			Argon2id.hash(message, salt, p, m, t, digest.length / 2)
				.then((output) => {
					res(output === digest);
				})
				.catch((err) => {
					rej(err);
				});
		});
}

export default Argon2id;
