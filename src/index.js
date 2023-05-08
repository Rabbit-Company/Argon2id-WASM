import Argon2id from './Argon2id.js';

document.getElementById('salt').value = Argon2id.randomSalt();

document.getElementById('start').addEventListener('click', () => {

	let message = document.getElementById('message').value;
	let salt = document.getElementById('salt').value;
	let p = document.getElementById('p').value;
	let m = document.getElementById('m').value;
	let i = document.getElementById('i').value;
	let l = document.getElementById('l').value;

	let timerStart = Date.now();
	let hashEncoded = Argon2id.hashEncoded(message, salt, i, m, p, l);
	let hashHex = Argon2id.hashDecode(hashEncoded);
	let timerEnd = calcT(timerStart);
	document.getElementById('hash').innerHTML = "<b>Hash:</b> " + hashHex + "<br/><b>Hash Encoded:</b> " + hashEncoded;
	document.getElementById('perf').innerHTML = "Hashing the message took <b>" + timerEnd + "ms</b>.";
});

document.getElementById('verify').addEventListener('click', () => {
	let message = document.getElementById('message2').value;
	let hashEncoded = document.getElementById('hashEncoded').value;

	let timerStart = Date.now();
	let match = Argon2id.verify(hashEncoded, message);

	let timerEnd = calcT(timerStart);
	if(match) document.getElementById('validate').innerHTML = "The message <b>DOES</b> match the supplied hash.";
	if(!match) document.getElementById('validate').innerHTML = "The message does <b>NOT</b> match the supplied hash.";

	document.getElementById('perf').innerHTML = "Verifying the message took <b>" + timerEnd + "ms</b>.";
});

function calcT(timer){
	return Date.now() - timer;
}