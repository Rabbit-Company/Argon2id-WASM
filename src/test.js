import Argon2id from './Argon2id.js';

/*

  Parameters:
  1. Message (String)
  2. Salt (String) <>
	3. Parallelism Factor (Int) <4> (Min = 1)
	4. Memory Cost (Int) <16> (Min = 32)
  5. Iterations (Int) <3> (Min = 1)
  6. Length (Int) <32> (Min = 1)

*/

// Generate hash from the provided message
// If you don't provide salt, it will be auto generated
Argon2id.hash("message").then(hash => {
	console.log("Hash: " + hash);
}).catch(err => {
	console.log("Error: " + err);
});

// Generate Encoded hash from the provided message
// Both hash and hashEncoded functions accept the same parameters
Argon2id.hashEncoded("message").then(hashEncoded => {
	console.log("Encoded Hash: " + hashEncoded);
}).catch(err => {
	console.log("Error: " + err);
});

// To get hash from hashEncoded function you can use function called hashDecode
Argon2id.hashDecode("$argon2id$v=19$m=32,t=2,p=3$MjZZaFJwRjZ2N3pyUzU2ag$EzMK1uIBhPZQV8XPsjTOnw");

// Generate hash from the provided message and salt
Argon2id.hash("message", "3yBtO1brz26g074n").then(hash => {
	console.log("Hash: " + hash);
}).catch(err => {
	console.log("Error: " + err);
});

// To generate random secure salt use randomSalt function
Argon2id.hashEncoded("message", Argon2id.randomSalt()).then(hashEncoded => {
	console.log("Encoded Hash: " + hashEncoded);
}).catch(err => {
	console.log("Error: " + err);
});

// Generate hash from the provided message, salt, iterations, memory cost, parallelism factor and hash length
Argon2id.hashEncoded("message", Argon2id.randomSalt(), 2, 16, 3, 32).then(hashEncoded => {
	console.log("Encoded Hash: " + hashEncoded);
}).catch(err => {
	console.log("Error: " + err);
});

// To validate the message you can use verify function.
// This function accept hashEncoded and message.
Argon2id.verify("$argon2id$v=19$m=32,t=2,p=3$MjZZaFJwRjZ2N3pyUzU2ag$EzMK1uIBhPZQV8XPsjTOnw", "test").then(match => {
	if(match) console.log("Message is valid.");
	if(!match) console.log("Message is not valid.");
}).catch(err => {
	console.log("Error: " + err);
});