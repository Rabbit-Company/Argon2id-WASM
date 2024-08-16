/**
 * Namespace for Argon2id hashing operations, providing functions for hashing messages, encoding and decoding hashes,
 * and generating random salts.
 *
 * This namespace utilizes the Argon2id algorithm, a memory-hard password hashing scheme that is resistant to GPU attacks
 * and optimized for secure password storage. It also includes utility functions for encoding and decoding hexadecimal
 * and base64 strings.
 */
declare namespace Argon2id {
	/**
	 * Converts a hexadecimal string to its equivalent base64 encoded string.
	 *
	 * This function takes a string of hexadecimal characters and converts each pair of hex digits
	 * into a corresponding ASCII character, then encodes the result in base64.
	 *
	 * @param {string} hexstring - The input string in hexadecimal format.
	 * @returns {string} The resulting string encoded in base64.
	 */
	function hexToBase64(hexstring: string): string;
	/**
	 * Converts a base64 encoded string back to its hexadecimal representation.
	 *
	 * This function decodes a base64 string to its original binary form and then converts
	 * each byte to a two-character hexadecimal string.
	 *
	 * @param {string} str - The input string in base64 format.
	 * @returns {string} The resulting string in hexadecimal format.
	 */
	function base64ToHex(str: string): string;
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
	function randRange(min: number, max: number): number;
	/**
	 * Generates a random salt string for use in cryptographic hashing.
	 *
	 * The salt is composed of lowercase letters, uppercase letters, and digits, ensuring a high
	 * level of entropy and security. This function is typically used to generate salts for password hashing.
	 *
	 * @returns {string} A 16-character random salt string.
	 */
	function randomSalt(): string;
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
	const hash: (message: string, salt?: string, p?: number, m?: number, t?: number, l?: number) => Promise<string>;
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
	const hashEncoded: (message: string, salt?: string, p?: number, m?: number, t?: number, l?: number) => Promise<string>;
	/**
	 * Extracts the hexadecimal digest from an encoded Argon2id hash string.
	 *
	 * This function decodes the base64 encoded digest part of the encoded hash string, converting
	 * it back to its original hexadecimal form.
	 *
	 * @param {string} hashEncoded - The encoded hash string to decode.
	 * @returns {string} The extracted hexadecimal digest.
	 */
	function hashDecode(hashEncoded: string): string;
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
	const verify: (hashEncoded: string, message: string) => Promise<boolean>;
}

export {
	Argon2id as default,
};

export {};
