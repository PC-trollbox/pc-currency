try {
    imagination
} catch {
    imagination = {};
}
if (!imagination.gui) imagination.gui = {};

/**
 * Promisified FileReader.
 * @param {File} file File from HTML form
 * @returns {String} Contents of HTML form
 */
imagination.gui.AsyncFileReader = function AsyncFileReader(file) {
    return new Promise(function(resolve) {
        let reader = new FileReader();
        reader.readAsText(file);
        reader.onload = async function(event) {
            resolve(event.target.result);
        }
    });
}

/**
 * Imagination Auth GUI
 * @param {Array} fileEls An array of two file elements. FIRST IS A PUBLIC KEY, SECOND IS A PRIVATE ONE.
 * @param {Function} startLogonProcess A function to start logon process to show an overlay or something.
 * @param {Function} prompt An async or normal function that requests the input of a person.
 * @param {Function} endLogonProcess A function which ends logon process. May have an error in the argument.
 * @param {Storage} storage Key storage.
 * @returns don't matter
 */
imagination.gui.imaginationAuthGUI = async function(fileEls = [], startLogonProcess = new Function(), prompt = (()=>"42"), endLogonProcess = new Function(), storage = localStorage) {
    startLogonProcess();
    if (!isSecureContext) return endLogonProcess("Data needs to be transferred securely (over HTTPS or localhost) to allow authentication.");
    if (!imagination.encryption) return endLogonProcess("Encryption toolkit was not found. Make sure the page loaded through.");
    let pubkey_data = storage.getItem("pubk");
    let privkey_data = storage.getItem("privk");
    if (fileEls.length >= 2) {
        try {
            pubkey_data = await imagination.gui.AsyncFileReader(fileEls[0]);
            privkey_data = await imagination.gui.AsyncFileReader(fileEls[1]);
        } catch {}
    }
    if (!privkey_data || !pubkey_data) return endLogonProcess("Required a public and a private key to be supplied. Check for both files to be valid.");
    storage.setItem("pubk", pubkey_data);
    storage.setItem("privk", privkey_data);
    let result = await fetch("/imagination/getEncryptedSecret?pubkey=" + encodeURIComponent(pubkey_data));
    if (!result.ok) return endLogonProcess("Authentication failed: " + result.statusText + "\n" + await result.text())
    if (privkey_data.startsWith("encrypted:")) {
        let password = await prompt("Enter your passphrase, then press Enter:");
        try {
            privkey_data = await imagination.encryption.decryptAES(JSON.parse(privkey_data.replace("encrypted:", "")), password);
        } catch (e) {
            return endLogonProcess("Key decryption failed:\n" + e.toString());
        }
    }
    let keyp = await imagination.encryption.importKeyPair(pubkey_data, privkey_data);
    try {
        let token = await imagination.encryption.decryptRSA(await result.text(), keyp.privateKey);
        document.cookie = "token=" + encodeURIComponent(token);
        location.reload();
    } catch (e) {
        return endLogonProcess("Decryption failed:\n" + e.toString());
    }
    endLogonProcess();
}

imagination.gui.isKeySaved = function(storage = localStorage) {
    return !!storage.getItem("pubk") && !!storage.getItem("privk");
}

/**
 * Imagination saved encryptions
 * @param {Array} fileEls An array of two file elements. FIRST IS A PUBLIC KEY, SECOND IS A PRIVATE ONE.
 * @param {Function} startLogonProcess A function to start registration process to show an overlay or something.
 * @param {Function} prompt An async or normal function that requests the input of a person.
 * @param {Function} confirm An async or normal function that requests the input of a person, which is returnes as a boolean yes/no.
 * @param {Function} endLogonProcess A function which ends encryption process. May have an error in the argument.
 * @param {Storage} storage Key storage.
 * @returns don't matter
 */
imagination.gui.imaginationSavedEncrypt = async function(fileEls = [], startLogonProcess = new Function(), prompt = (()=>"42"), confirm = (()=>true), endLogonProcess = new Function(), storage = localStorage) {
    startLogonProcess();
    if (!isSecureContext) return endLogonProcess("Data needs to be transferred securely (over HTTPS or localhost) to allow authentication.");
    if (!imagination.encryption) return endLogonProcess("Encryption toolkit was not found. Make sure the page loaded through.");
    let pubkey_data = storage.getItem("pubk");
    let privkey_data = storage.getItem("privk");
    if (fileEls.length >= 2) {
        try {
            pubkey_data = await AsyncFileReader(fileEls[0]);
            privkey_data = await AsyncFileReader(fileEls[1]);
        } catch {}
    }
    if (!privkey_data || !pubkey_data) return endLogonProcess("Required a public and a private key to be supplied. Check for both files to be valid.");
    storage.setItem("pubk", pubkey_data);
    storage.setItem("privk", privkey_data);
    
    let encryptMark = privkey_data.startsWith("encrypted:");
    if (encryptMark) {
        if (confirm("The key is already encrypted. Would you like to decrypt the key?")) {
            let password = prompt("Enter your passphrase, then press Enter:");
            try {
                storage.setItem("privk", await imagination.encryption.decryptAES(JSON.parse(privkey_data.replace("encrypted:", "")), password));
            } catch (e) {
                return endLogonProcess("Seems like your passphrase was not correct. Try again later.\n\n-----BEGIN TECHNICAL INFO-----\n" +  + e.toString() + "\n-----END TECHNICAL INFO-----");
            }
        }
    } else {
        let password = prompt("Enter a new passphrase, then press Enter:");
        try {
            storage.setItem("privk", "encrypted:" + JSON.stringify(await imagination.encryption.encryptAES(privkey_data, password)));
        } catch (e) {
            return endLogonProcess("Something went from. See technical information.\n" + e.toString());
        }
    }
    endLogonProcess();
}

/**
 * Imagination key generation frontend.
 * @param {Function} startLogonProcess A function to start registration process to show an overlay or something.
 * @param {Function} endLogonProcess A function which ends registration process. May have an error in the argument.
 * @param {Storage} storage Key storage.
 * @returns {Object} with PEM-encoded keys
 */
imagination.gui.imaginationPubkeyFrontend = async function(startLogonProcess = new Function(), endLogonProcess = new Function(), storage = localStorage) {
    startLogonProcess();
    if (!isSecureContext) return endLogonProcess("Data needs to be transferred securely (over HTTPS or localhost) to allow authentication.");
    if (!imagination.encryption) return endLogonProcess("Encryption toolkit was not found. Make sure the page loaded through.");
    let newkeypair = await imagination.encryption.generateKeyPair();
    newkeypair = await imagination.encryption.exportKeyPair(newkeypair);
    storage.setItem('privk', newkeypair.privateKeyPem);
    storage.setItem('pubk', newkeypair.publicKeyPem);
    endLogonProcess();
    return newkeypair;
}

/**
 * Donwloads keys from the storage.
 * @param {Array} fileEls An array of two file elements. FIRST IS A PUBLIC KEY, SECOND IS A PRIVATE ONE.
 * @param {Function} prompt An async or normal function that requests the input of a person.
 * @param {Boolean} decrypt Whether to decrypt the private key or not.
 * @param {Storage} storage Key storage.
 * @returns {Object} with PEM-encoded keys
 */
imagination.gui.backupKeys = async function(fileEls = [], prompt = (()=>"42"), decrypt = false, storage = localStorage) {
    let pubkey_data = storage.getItem("pubk");
    let privkey_data = storage.getItem("privk");
    if (fileEls.length >= 2) {
        try {
            pubkey_data = await AsyncFileReader(fileEls[0]);
            privkey_data = await AsyncFileReader(fileEls[1]);
        } catch {}
    }
    if (!privkey_data || !pubkey_data) return "KEY_NOT_FOUND";
    storage.setItem("pubk", pubkey_data);
    storage.setItem("privk", privkey_data);

    if (privkey_data.startsWith("encrypted:") && decrypt) {
        let password = await prompt("Enter your passphrase, then press Enter:");
        try {
            privkey_data = await imagination.encryption.decryptAES(JSON.parse(privkey_data.replace("encrypted:", "")), password);
        } catch (e) {}
    }
    
    let blob = new Blob([privkey_data], { type: 'text/plain' });
    let url = URL.createObjectURL(blob);
    let link = document.createElement('a');
    link.href = url;
    link.download = 'KEEP_SECRET.key';
    link.click();
    URL.revokeObjectURL(url);

    blob = new Blob([pubkey_data], { type: 'text/plain' });
    url = URL.createObjectURL(blob);
    link = document.createElement('a');
    link.href = url;
    link.download = 'SEND_TO_SERVER.key';
    link.click();
    URL.revokeObjectURL(url);
}