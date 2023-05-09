use wasm_bindgen::prelude::*;

use argon2::{Version, Algorithm, Argon2, Params};

pub fn to_hex(bytes: &[u8]) -> String {
	bytes.iter()
		.map(|n| format!("{:02x}", n))
		.collect::<Vec<String>>()
		.join("")
}

#[wasm_bindgen]
pub fn argon2id_hash(message: String, salt: String, iterations: u32, memory: u32, parallelism: u32, length: usize) -> Result<String, JsValue>{

	let argon2id: Argon2 = Argon2::new(
		Algorithm::Argon2id,
		Version::V0x13,
		Params::new(memory, iterations, parallelism, Some(length)).map_err(|e| e.to_string())?
	);

	let mut out: Vec<u8> = vec![0;length];

	argon2id
		.hash_password_into(message.as_bytes(), salt.as_bytes(), &mut out)
		.map_err(|e| e.to_string())?;

	Ok(to_hex(&out))
}