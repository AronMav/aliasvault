/**
 * Custom error class for crypto availability issues
 */
class CryptoNotAvailableError extends Error {
    constructor(message) {
        super(message);
        this.name = 'CryptoNotAvailableError';
        // Prevent stack trace from being captured
        this.stack = '';
    }
}

/**
 * Check if crypto API is available and throw user-friendly error if not.
 */
function checkCryptoAvailable() {
    if (!window.crypto || !window.crypto.subtle) {
        const error = new CryptoNotAvailableError("Cryptographic operations are not available. Please ensure you are accessing AliasVault over HTTPS, as this is required for security features to work properly.");
        console.error(error.message);
        throw error;
    }
}

/**
 * Convert a Uint8Array to a base64 string.
 *
 * @param {Uint8Array} bytes - The bytes to encode.
 * @returns {string} The base64-encoded string.
 */
function bytesToBase64(bytes) {
    if (typeof bytes.toBase64 === 'function') {
        return bytes.toBase64();
    }

    const CHUNK_SIZE = 0x8000;
    let binary = '';
    for (let offset = 0; offset < bytes.length; offset += CHUNK_SIZE) {
        binary += String.fromCharCode.apply(null, bytes.subarray(offset, offset + CHUNK_SIZE));
    }
    return btoa(binary);
}

/**
 * Decode a base64 string to a Uint8Array.
 *
 * @param {string} base64 - The base64 string to decode.
 * @returns {Uint8Array} The decoded bytes.
 */
function base64ToBytes(base64) {
    if (typeof Uint8Array.fromBase64 === 'function') {
        return Uint8Array.fromBase64(base64);
    }
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

/**
 * AES (symmetric) encryption and decryption functions.
 * @type {{encrypt: (function(*, *): Promise<string>), encryptBytesToBase64: (function(Uint8Array, string): Promise<string>), decrypt: (function(*, *): Promise<string>), decryptBytes: (function(*, *): Promise<Uint8Array>), encryptBytes: (function(Uint8Array, Uint8Array): Promise<Uint8Array>), decryptBytesRaw: (function(Uint8Array, Uint8Array): Promise<Uint8Array>)}}
 */
window.cryptoInterop = {
    encrypt: async function (plaintext, base64Key) {
        checkCryptoAvailable();

        const key = await window.crypto.subtle.importKey(
            "raw",
            base64ToBytes(base64Key),
            {
                name: "AES-GCM",
                length: 256,
            },
            false,
            ["encrypt"]
        );

        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encoder = new TextEncoder();
        const encoded = encoder.encode(plaintext);

        const ciphertext = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            encoded
        );

        const combined = new Uint8Array(iv.length + ciphertext.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(ciphertext), iv.length);

        return bytesToBase64(combined);
    },
    /**
     * Encrypts already-encoded bytes using AES-256-GCM and returns base64 of nonce + ciphertext.
     *
     * Identical in construction and output to encrypt(), but takes the plaintext as bytes.
     * encrypt() runs TextEncoder.encode() on a string, so passing the UTF-8 bytes of that same
     * string here produces byte-identical ciphertext - the vault format does not change.
     *
     * The reason this exists: passing a large plaintext as a string forces Blazor to serialize
     * it as a JSON interop argument, and the escape buffer for a ~100 MB string exhausts the
     * 32-bit browser heap. Byte arrays are marshalled directly instead.
     *
     * @param {Uint8Array} plainBytes - The plaintext bytes to encrypt
     * @param {string} base64Key - The 32-byte encryption key, base64 encoded
     * @returns {Promise<string>} Base64 of nonce + ciphertext + tag
     */
    encryptBytesToBase64: async function (plainBytes, base64Key) {
        checkCryptoAvailable();

        const key = await window.crypto.subtle.importKey(
            "raw",
            base64ToBytes(base64Key),
            {
                name: "AES-GCM",
                length: 256,
            },
            false,
            ["encrypt"]
        );

        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            plainBytes
        );

        const combined = new Uint8Array(iv.length + ciphertext.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(ciphertext), iv.length);

        return bytesToBase64(combined);
    },
    decrypt: async function (base64Ciphertext, base64Key) {
        checkCryptoAvailable();

        const key = await window.crypto.subtle.importKey(
            "raw",
            base64ToBytes(base64Key),
            {
                name: "AES-GCM",
                length: 256,
            },
            false,
            ["decrypt"]
        );

        const ivAndCiphertext = base64ToBytes(base64Ciphertext);
        const iv = ivAndCiphertext.subarray(0, 12);
        const ciphertext = ivAndCiphertext.subarray(12);

        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            ciphertext
        );

        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    },
    decryptBytes: async function (base64Ciphertext, base64Key) {
        checkCryptoAvailable();

        const key = await window.crypto.subtle.importKey(
            "raw",
            base64ToBytes(base64Key),
            {
                name: "AES-GCM",
                length: 256,
            },
            false,
            ["decrypt"]
        );

        const ivAndCiphertext = base64ToBytes(base64Ciphertext);
        const iv = ivAndCiphertext.subarray(0, 12);
        const ciphertext = ivAndCiphertext.subarray(12);

        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            ciphertext
        );

        return new Uint8Array(decrypted);
    },
    /**
     * Encrypts byte array using AES-256-GCM
     * @param {Uint8Array} plainBytes - The bytes to encrypt
     * @param {Uint8Array} keyBytes - The 32-byte encryption key
     * @returns {Promise<Uint8Array>} The encrypted data (nonce + ciphertext + tag)
     */
    encryptBytes: async function(plainBytes, keyBytes) {
        checkCryptoAvailable();

        const key = await window.crypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );

        const nonce = window.crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce },
            key,
            plainBytes
        );

        const ciphertextArray = new Uint8Array(ciphertext);
        const result = new Uint8Array(12 + ciphertextArray.length);
        result.set(nonce, 0);
        result.set(ciphertextArray, 12);

        return result;
    },
    /**
     * Decrypts byte array using AES-256-GCM
     * @param {Uint8Array} encryptedBytes - The encrypted data (nonce + ciphertext + tag)
     * @param {Uint8Array} keyBytes - The 32-byte encryption key
     * @returns {Promise<Uint8Array>} The decrypted data
     */
    decryptBytesRaw: async function(encryptedBytes, keyBytes) {
        checkCryptoAvailable();

        const key = await window.crypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );

        const nonce = encryptedBytes.slice(0, 12);
        const ciphertextWithTag = encryptedBytes.slice(12);

        const plaintext = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce },
            key,
            ciphertextWithTag
        );

        return new Uint8Array(plaintext);
    },
    /**
     * Generates random salt
     * @param {number} length - The length of the salt in bytes
     * @returns {Uint8Array} The random salt
     */
    generateSalt: function(length) {
        checkCryptoAvailable();
        return window.crypto.getRandomValues(new Uint8Array(length));
    }
};

/**
 * RSA (asymmetric) encryption and decryption functions.
 * @type {{decryptWithPrivateKey: (function(string, string): Promise<string>), encryptWithPublicKey: (function(string, string): Promise<string>), generateRsaKeyPair: (function(): Promise<{privateKey: string, publicKey: string}>)}}
 */
window.rsaInterop = {
    /**
     * Generates a new RSA key pair.
     * @returns {Promise<{publicKey: string, privateKey: string}>} A promise that resolves to an object containing the public and private keys as JWK strings.
     */
    generateRsaKeyPair : async function() {
        checkCryptoAvailable();

        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
            true,
            ["encrypt", "decrypt"]
        );

        const publicKey = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
        const privateKey = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);

        return {
            publicKey: JSON.stringify(publicKey),
            privateKey: JSON.stringify(privateKey)
        };
    },
    /**
     * Encrypts a plaintext string using an RSA public key.
     * @param {string} plaintext - The plaintext to encrypt.
     * @param {string} publicKey - The public key in JWK format.
     * @returns {Promise<string>} A promise that resolves to the encrypted data as a base64-encoded string.
     */
    encryptWithPublicKey : async function(plaintext, publicKey) {
        checkCryptoAvailable();

        const publicKeyObj = await window.crypto.subtle.importKey(
            "jwk",
            JSON.parse(publicKey),
            {
                name: "RSA-OAEP",
                hash: "SHA-256",
            },
            false,
            ["encrypt"]
        );

        const encodedPlaintext = new TextEncoder().encode(plaintext);
        const cipherBuffer = await window.crypto.subtle.encrypt(
            {
                name: "RSA-OAEP"
            },
            publicKeyObj,
            encodedPlaintext
        );

        return bytesToBase64(new Uint8Array(cipherBuffer));
    },
    /**
     * Decrypts a ciphertext string using an RSA private key.
     * @param {string} ciphertext - The base64-encoded ciphertext to decrypt.
     * @param {string} privateKey - The private key in JWK format.
     * @returns {Promise<string>} A promise that resolves to the decrypted data as a base64 string.
     */
    decryptWithPrivateKey: async function(ciphertext, privateKey) {
        checkCryptoAvailable();

        try {
            // Parse the private key
            let parsedPrivateKey = JSON.parse(privateKey);

            // Import the private key
            let privateKeyObj = await window.crypto.subtle.importKey(
                "jwk",
                parsedPrivateKey,
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256",
                },
                true,
                ["decrypt"]
            );

            // Decode the base64 ciphertext
            let cipherBuffer = base64ToBytes(ciphertext);

            // Decrypt the ciphertext
            let plaintextBuffer = await window.crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256",
                },
                privateKeyObj,
                cipherBuffer
            );

            // Convert to base64 string instead of returning Uint8Array to avoid Blazor serialization issues, see https://github.com/dotnet/aspnetcore/issues/59837
            const decryptedBytes = new Uint8Array(plaintextBuffer);
            return bytesToBase64(decryptedBytes);
        } catch (error) {
            throw new Error(`Failed to decrypt: ${error.message}`);
        }
    }
};

/**
 * Uploads the encrypted vault to the server entirely from JavaScript.
 *
 * Why: the .NET (Blazor WASM) save path JSON-serializes the vault object (with
 * the ~64MB base64 ciphertext as a string property) inside PostAsJsonAsync,
 * which exhausts the 32-bit browser heap on vault-sized blobs - the POST never
 * leaves the tab, observed as the tab freezing and the mutation being lost.
 * The browser extension uploads the same blob with a plain JS fetch without
 * any problems, so we do the same here.
 *
 * Protocol: .NET pushes the ALREADY encrypted base64 in small chunks
 * (appendChunk, one interop call each so no giant string is ever marshalled),
 * then calls upload() which assembles the JSON body as a Blob (streamed by the
 * browser, no giant JS string either) and POSTs it with a native fetch.
 */

/**
 * Chunked encrypt+upload protocol (v2).
 *
 * Why v2: even the v1 protocol (chunks of ALREADY-encrypted base64) required the
 * .NET side to hold the full ~64MB ciphertext string (128MB as UTF-16 in the mono
 * heap) between SymmetricEncryptFromBytes and the chunk loop, and the mono heap
 * is non-compacting - the second save after a big import died with OOM there.
 * v2 pushes the PLAINTEXT base64 chunks and lets JS do encrypt+assemble+POST,
 * so the ciphertext only ever exists in the JS heap (which handles the same
 * 36MB vault fine in the browser extension).
 *
 * Note: cryptoInterop.encrypt(plainBase64, key) treats the plaintext as a string
 * and UTF-8 encodes it - identical bytes to encryptBytesToBase64(utf8bytes),
 * so the stored vault format is unchanged.
 */
window.vaultUploadInterop = {
    _chunks: [],

    /**
     * Client identifier sent as X-AliasVault-Client on the native fetch POSTs.
     * Set by setClientName() (called from .NET with the same "web-{version}"
     * value the managed HttpClient default headers carry) so vault revisions
     * uploaded through the JS path are attributed to this client in the
     * server DB instead of being stored with a NULL client. Falls back to
     * 'web-unknown' when never set (e.g. stale cached JS bundle).
     */
    clientName: 'web-unknown',

    /** Set the client name used in the X-AliasVault-Client header. */
    setClientName: function (name) {
        if (typeof name === 'string' && name.length > 0) {
            this.clientName = name;
        }
    },

    /** Reset the pending chunk buffer. */
    beginUpload: function () {
        this._chunks = [];
    },

    /** Append one base64 chunk of the encrypted vault. */
    appendChunk: function (chunk) {
        this._chunks.push(chunk);
    },

    /**
     * Assemble the JSON body from the buffered chunks and POST it.
     * @param {Object} meta - vault metadata WITHOUT the Blob field (small, JSON-serialized by interop)
     * @param {string} accessToken - Bearer token for the API
     * @returns {Promise<{status: number, body: string}>} HTTP status and response body text (status 0 = network/JS error)
     */
    upload: async function (meta, accessToken, uploadUrl) {
        // Base64 alphabet (A-Za-z0-9+/=) needs no JSON escaping, so the chunks
        // can be embedded into the JSON text directly as Blob parts.
        const metaNoBlob = Object.assign({}, meta);
        delete metaNoBlob.Blob;
        const metaJson = JSON.stringify(metaNoBlob);

        const parts = [metaJson.slice(0, -1) + ',"Blob":"'];
        for (const chunk of this._chunks) {
            parts.push(chunk);
        }
        parts.push('"}');
        this._chunks = [];

        const body = new Blob(parts, { type: 'application/json' });

        try {
            const response = await fetch(uploadUrl || '/api/v1/Vault', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + accessToken,
                    'X-AliasVault-Client': window.vaultUploadInterop.clientName,
                },
                body: body,
            });
            const text = await response.text();
            return { status: response.status, body: text };
        } catch (e) {
            return { status: 0, body: 'JS fetch error: ' + (e && e.message ? e.message : String(e)) };
        }
    },

    // ---- v2: encrypt-and-upload (plaintext chunks in, one POST out) ----
    _plainChunks: [],

    /** Reset the pending plaintext chunk buffer (v2 protocol). */
    beginEncryptUpload: function () {
        this._plainChunks = [];
    },

    /**
     * Append one PLAINTEXT base64 chunk of the exported vault as a Uint8Array
     * (v2 protocol). byte[] from .NET marshals to Uint8Array - no string copy.
     */
    appendPlainChunk: function (chunk) {
        this._plainChunks.push(chunk);
    },

    /**
     * Concatenate the buffered plaintext chunks, AES-encrypt them, assemble the
     * JSON body as a Blob and POST it - all inside the JS heap. Neither the
     * plaintext nor the ciphertext is ever surfaced to the .NET heap as a
     * vault-sized string.
     * @param {Object} meta - vault metadata WITHOUT the Blob field (small, JSON-serialized by interop)
     * @param {string} base64Key - base64 AES key (same key the .NET path uses)
     * @param {string} accessToken - Bearer token for the API
     * @param {string} uploadUrl - absolute API URL for the POST (e.g. "http://host:port/api/v1/Vault").
     * Relative fallback kept only for stale callers.
     * @returns {Promise<{status: number, body: string}>} HTTP status and response body text (status 0 = network/JS error, -1 via exception = interop missing)
     */
    encryptAndUpload: async function (meta, base64Key, accessToken, uploadUrl) {
        this._chunks = [];
        const chunks = this._plainChunks;
        this._plainChunks = [];
        try {
            let total = 0;
            for (const c of chunks) {
                total += c.length;
            }
            const merged = new Uint8Array(total);
            let offset = 0;
            for (const c of chunks) {
                merged.set(c, offset);
                offset += c.length;
            }

            const cipherBase64 = await window.cryptoInterop.encryptBytesToBase64(merged, base64Key);

            const metaNoBlob = Object.assign({}, meta);
            delete metaNoBlob.Blob;
            delete metaNoBlob.blob;
            const metaJson = JSON.stringify(metaNoBlob);

            // Base64 needs no JSON escaping, so embed the ciphertext directly.
            const parts = [metaJson.slice(0, -1) + ',"Blob":"', cipherBase64, '"}'];
            const body = new Blob(parts, { type: 'application/json' });

            const response = await fetch(uploadUrl || '/api/v1/Vault', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + accessToken,
                    'X-AliasVault-Client': window.vaultUploadInterop.clientName,
                },
                body: body,
            });
            const text = await response.text();
            return { status: response.status, body: text };
        } catch (e) {
            return { status: 0, body: 'JS encrypt/upload error: ' + (e && e.message ? e.message : String(e)) };
        }
    }
};
