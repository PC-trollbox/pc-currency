const crypto = require("crypto");
let minedCounter = 0;

function sha256(str) {
    const buffer = Buffer.from(str, "utf8");
    return crypto.createHash("sha256").update(buffer).digest("hex");
}

function verify(data, target, nonce) {
    const hash = sha256(data + nonce);
    return hash.substring(0, target.length) === target;
}

function mine(data, target) {
    let nonce = 0;
    while (!verify(data, target, nonce)) nonce++;
    minedCounter++;  
    return nonce;
}

module.exports = { verify, mine };