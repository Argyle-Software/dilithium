import * as dilithium from "pqc_dilithium";

const generateKeyButton = document.getElementById("generatekey");
const signButton = document.getElementById("sign");
const verifyButton = document.getElementById("verify");
const clearButton = document.getElementById("clear");

const pubKeyBox = document.getElementById("pubkeybox");
const pubKeyBox2 = document.getElementById("pubkeybox2");
const privKeyBox = document.getElementById("privkeybox");
const msgBox1 = document.getElementById("msgbox1");
const signBox1 = document.getElementById("signbox1");
const msgBox2 = document.getElementById("msgbox2");
const signBox2 = document.getElementById("signbox2");
const resultBox = document.getElementById("result");

document.getElementById('pkbytes').innerHTML = dilithium.Params.publicKeyBytes;
document.getElementById('skbytes').innerHTML = dilithium.Params.secretKeyBytes;
document.getElementById('sbytes').innerHTML = dilithium.Params.signBytes;

let keys = undefined

generateKeyButton.addEventListener("click", event => {
    keys = dilithium.keypair();
    const pubKey = keys.pubkey;
    const privKey = keys.secret;

    pubKeyBox.value = toHexString(pubKey);
    privKeyBox.value = toHexString(privKey);

    pubKeyBox2.value = pubKeyBox.value;
});

signButton.addEventListener("click", event => {
    const msg = new TextEncoder().encode(msgBox1.value)
    let sign = keys.sign(msg)
    signBox1.value = toHexString(sign)
    msgBox2.value = msgBox1.value
    signBox2.value = toHexString(sign)
})

verifyButton.addEventListener('click', (event)=>{
    const msg = new TextEncoder().encode(msgBox2.value)

    let result = dilithium.verify(hexToBytes(signBox2.value), msg, hexToBytes(pubKeyBox2.value))
    resultBox.value = result
})

clearButton.addEventListener('click', (event)=>{
    var elements = document.getElementsByTagName("input");
    for (var i=0; i < elements.length; i++) {
        elements[i].value = "";
    }
})

function toHexString(bytes) {
    for (var hex = [], i = 0; i < bytes.length; i++) {
        var current = bytes[i] < 0 ? bytes[i] + 256 : bytes[i];
        hex.push((current >>> 4).toString(16));
        hex.push((current & 0xF).toString(16));
    }
    return hex.join("");
}

function hexToBytes(hex) {
    for (var bytes = [], c = 0; c < hex.length; c += 2)
    bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}