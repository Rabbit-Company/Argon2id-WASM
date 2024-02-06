import Argon2id from './argon2id.js';

const saltInput = document.getElementById('salt') as HTMLInputElement;
const messageInput = document.getElementById('message') as HTMLInputElement;
const message2Input = document.getElementById('message2') as HTMLInputElement;
const parallelismInput = document.getElementById('p') as HTMLInputElement;
const memoryInput = document.getElementById('m') as HTMLInputElement;
const iterationsInput = document.getElementById('t') as HTMLInputElement;
const lengthInput = document.getElementById('l') as HTMLInputElement;
const hashEncodedInput = document.getElementById('hashEncoded') as HTMLInputElement;

const hashElement = document.getElementById('hash');
const perfElement = document.getElementById('perf');
const validateElement = document.getElementById('validate');

saltInput.value = Argon2id.randomSalt();

document.getElementById('hashForm')?.addEventListener('submit', (e) => {
	e.preventDefault();
	if(!hashElement || !perfElement) return;

	let message = messageInput.value;
	let salt = saltInput.value;
	let p = parseInt(parallelismInput.value, 10);
	let m = parseInt(memoryInput.value, 10);
	let t = parseInt(iterationsInput.value, 10);
	let l = parseInt(lengthInput.value, 10);

	let timerStart = Date.now();
	Argon2id.hashEncoded(message, salt, p, m, t, l).then(hashEncoded => {
		let hashHex = Argon2id.hashDecode(hashEncoded);
		let timerEnd = calcT(timerStart);
		hashElement.innerHTML = "<b>Hash:</b> " + hashHex + "<br/><b>Hash Encoded:</b> " + hashEncoded;
		perfElement.innerHTML = "Hashing the message took <b>" + timerEnd + "ms</b>.";
	}).catch(err => {
		hashElement.innerHTML = `Hashing failed because of <b>${err}</b>`;
		perfElement.innerHTML = "";
	});
});

document.getElementById('verifyForm')?.addEventListener('submit', (e) => {
	e.preventDefault();
	if(!perfElement || !validateElement) return;

	let message = message2Input.value;
	let hashEncoded = hashEncodedInput.value;

	let timerStart = Date.now();

	Argon2id.verify(hashEncoded, message).then(match => {
		let timerEnd = calcT(timerStart);
		if(match) validateElement.innerHTML = "The message <b>DOES</b> match the supplied hash.";
		if(!match) validateElement.innerHTML = "The message does <b>NOT</b> match the supplied hash.";

		perfElement.innerHTML = "Verifying the message took <b>" + timerEnd + "ms</b>.";
	}).catch(err => {
		validateElement.innerHTML = `Validation failed because of <b>${err}</b>`;
		perfElement.innerHTML = "";
	});
});

function calcT(timer: number){
	return Date.now() - timer;
}