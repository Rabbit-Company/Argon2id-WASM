/**
 * Class representing Argon2id hashing operations.
*/
export default class Argon2id {
	/**
	 * Converts a hexadecimal string to a base64 string.
	 * @param {string} hexstring - The input hexadecimal string.
	 * @returns {string} The resulting base64 string.
	*/
	static hexToBase64(hexstring: string): string;
	/**
	 * Converts a base64 string to a hexadecimal string.
	 * @param {string} str - The input base64 string.
	 * @returns {string} The resulting hexadecimal string.
	*/
	static base64ToHex(str: string): string;
	/**
	 * Generates a random number within a specified range.
	 * @param {number} min - The minimum value of the range.
	 * @param {number} max - The maximum value of the range.
	 * @returns {number} The generated random number.
	*/
	static randRange(min: number, max: number): number;
	/**
	 * Generates a random salt string.
	 * @returns {string} The generated random salt string.
	*/
	static randomSalt(): string;
	/**
	 * Hashes a message using Argon2id.
	 * @param {string} message - The message to be hashed.
	 * @param {string} [salt] - The salt for hashing (default is a random salt).
	 * @param {number} [p=4] - The parallelism factor.
	 * @param {number} [m=16] - The memory cost in kilobytes.
	 * @param {number} [t=3] - The number of iterations.
	 * @param {number} [l=32] - The hash length in bytes.
	 * @returns {Promise<string>} A promise that resolves to the hashed message.
	*/
	static hash: (message: string, salt?: string, p?: number, m?: number, t?: number, l?: number) => Promise<string>;
	/**
	 * Hashes a message and encodes it in a specific format.
	 * @param {string} message - The message to be hashed.
	 * @param {string} [salt] - The salt for hashing (default is a random salt).
	 * @param {number} [p=4] - The parallelism factor.
	 * @param {number} [m=16] - The memory cost in kilobytes.
	 * @param {number} [t=3] - The number of iterations.
	 * @param {number} [l=32] - The hash length in bytes.
	 * @returns {Promise<string>} A promise that resolves to the encoded hashed message.
	*/
	static hashEncoded: (message: string, salt?: string, p?: number, m?: number, t?: number, l?: number) => Promise<string>;
	/**
	 * Decodes a hash encoded in a specific format and retrieves the hexadecimal digest.
	 * @param {string} hashEncoded - The encoded hash string.
	 * @returns {string} The hexadecimal digest.
	*/
	static hashDecode(hashEncoded: string): string;
	/**
	 * Verifies if a message matches a given hash encoded in a specific format.
	 * @param {string} hashEncoded - The encoded hash string to be verified against.
	 * @param {string} message - The message to be verified.
	 * @returns {Promise<boolean>} A promise that resolves to a boolean indicating the verification result.
	*/
	static verify: (hashEncoded: string, message: string) => Promise<boolean>;
}

export {};
