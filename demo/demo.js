const { generateKeyPair, Voter, Verifier } = require("../dist/index.js");

async function demo() {
    const { publicKey, privateKey } = await generateKeyPair();
    const bits = 7;
    const voter = new Voter(bits, publicKey);
    const verifier = new Verifier(publicKey);

    const numberToEncrypt = 30;
    console.log("Original Number:", numberToEncrypt);
    let time = Date.now();
    const proofs = voter.encryptNumber(numberToEncrypt);
    console.log("Encrypt took:", (Date.now() - time) / 1000, "seconds");
    time = Date.now();
    const valid = verifier.verifyNumber(proofs);
    console.log("Verify took:", (Date.now() - time) / 1000, "seconds");
    console.log("Proofs valid:", valid);
    let result = publicKey.encrypt(0);
    for (let i = 0; i < proofs.length; i++) {
        const multiplier = 2 ** i;
        result = publicKey.addition(result, publicKey.multiply(proofs[i].c, multiplier));
    }
    const decrypted = privateKey.decrypt(result);
    console.log("Original Number decrypted:", decrypted);
}

demo();
