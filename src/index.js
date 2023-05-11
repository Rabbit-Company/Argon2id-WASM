import Argon2id from './Argon2id.js';

document.getElementById('salt').value = Argon2id.randomSalt();

document.getElementById('hashForm').addEventListener('submit', (e) => {
	e.preventDefault();

	let message = document.getElementById('message').value;
	let salt = document.getElementById('salt').value;
	let p = document.getElementById('p').value;
	let m = document.getElementById('m').value;
	let i = document.getElementById('i').value;
	let l = document.getElementById('l').value;

	let timerStart = Date.now();
	Argon2id.hashEncoded(message, salt, i, m, p, l).then(hashEncoded => {
		let hashHex = Argon2id.hashDecode(hashEncoded);
		let timerEnd = calcT(timerStart);
		document.getElementById('hash').innerHTML = "<b>Hash:</b> " + hashHex + "<br/><b>Hash Encoded:</b> " + hashEncoded;
		document.getElementById('perf').innerHTML = "Hashing the message took <b>" + timerEnd + "ms</b>.";
	}).catch(err => {
		document.getElementById('hash').innerHTML = `Hashing failed because of <b>${err}</b>`;
		document.getElementById('perf').innerHTML = "";
	});
});

document.getElementById('verifyForm').addEventListener('submit', (e) => {
	e.preventDefault();

	let message = document.getElementById('message2').value;
	let hashEncoded = document.getElementById('hashEncoded').value;

	let timerStart = Date.now();

	Argon2id.verify(hashEncoded, message).then(match => {
		let timerEnd = calcT(timerStart);
		if(match) document.getElementById('validate').innerHTML = "The message <b>DOES</b> match the supplied hash.";
		if(!match) document.getElementById('validate').innerHTML = "The message does <b>NOT</b> match the supplied hash.";

		document.getElementById('perf').innerHTML = "Verifying the message took <b>" + timerEnd + "ms</b>.";
	}).catch(err => {
		document.getElementById('validate').innerHTML = `Validation failed because of <b>${err}</b>`;
		document.getElementById('perf').innerHTML = "";
	});
});

function calcT(timer){
	return Date.now() - timer;
}