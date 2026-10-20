## Authenticated encryption with associated data (AEAD):
## `ChaCha20Poly1305` (RFC 8439) and `Aes256Gcm`.

import "sodium";

## The size in bytes of an AEAD key.
export const KEY_SIZE: ulong = 32;
## The size in bytes of an AEAD nonce.
export const NONCE_SIZE: ulong = 12;
## The size in bytes of the authentication tag on each ciphertext.
export const TAG_SIZE: ulong = 16;

## ChaCha20-Poly1305 (the IETF variant of RFC 8439): encrypts and
## authenticates with a 32-byte key.
##
## `seal` picks a fresh random nonce for each message and puts it in front
## of the ciphertext, and `open` reads it back, so the usual calls need no
## nonce handling. Random 12-byte nonces are safe for about 2^32 messages
## under one key; use a new key before that. `seal_with_nonce` and
## `open_with_nonce` take the nonce from the caller, for protocols that
## fix it; never use a nonce twice with one key.
##
## The associated data is authenticated but not encrypted: `open` fails
## unless it is given the same bytes `seal` was.
##
## @example
##     import crypto;
##
##     main(): int {
##         var key = crypto.ChaCha20Poly1305.generate_key();
##         var cipher = crypto.ChaCha20Poly1305.from_key(key).value();
##         var sealed = cipher.seal("attack at dawn".bytes());
##         var opened = cipher.open(sealed).value();
##         print(opened.count);   # 14
##         return 0;
##     }
export struct ChaCha20Poly1305 {
    var _key: u8[];

    ## Makes a cipher that seals and opens with `key`; `from_key` returns
    ## an error instead of panicking.
    ##
    ## @param key the key, `KEY_SIZE` bytes, which the cipher copies
    ## @panics if `key` is not `KEY_SIZE` bytes
    construct(key: u8[]) {
        assert(key.count == KEY_SIZE, $"a ChaCha20-Poly1305 key is {KEY_SIZE} bytes, not {key.count}");
        _key = key.copy();
    }

    ## Returns a new random key.
    ##
    ## @returns `KEY_SIZE` random bytes
    static generate_key(): u8[] {
        return random_bytes(KEY_SIZE);
    }

    ## Makes a cipher that seals and opens with `key`.
    ##
    ## @param key the key, `KEY_SIZE` bytes
    ## @returns the cipher, or an error when `key` is not `KEY_SIZE` bytes
    static from_key(key: u8[]): Result<ChaCha20Poly1305> {
        if (key.count != KEY_SIZE) {
            return Result<ChaCha20Poly1305>.err(Error($"a ChaCha20-Poly1305 key is {KEY_SIZE} bytes, not {key.count}"));
        }
        return Result<ChaCha20Poly1305>.ok(ChaCha20Poly1305(key));
    }

    ## Encrypts and authenticates `plaintext` under a fresh random nonce.
    ##
    ## @param plaintext the message
    ## @returns the nonce (`NONCE_SIZE` bytes), then the ciphertext, then
    ##   the tag (`TAG_SIZE` bytes)
    seal(plaintext: u8[]): u8[] {
        return seal(plaintext, Array<u8>());
    }

    ## Encrypts and authenticates `plaintext`, and authenticates
    ## `associated_data`, under a fresh random nonce.
    ##
    ## @param plaintext the message
    ## @param associated_data bytes `open` must be given too, such as a
    ##   header; they are not encrypted or included in the result
    ## @returns the nonce (`NONCE_SIZE` bytes), then the ciphertext, then
    ##   the tag (`TAG_SIZE` bytes)
    seal(plaintext: u8[], associated_data: u8[]): u8[] {
        return _seal_random(false, _key, plaintext, associated_data);
    }

    ## Checks and decrypts what `seal` returned.
    ##
    ## @param sealed the nonce, ciphertext and tag `seal` returned
    ## @returns the plaintext, or an error when `sealed` was changed, is too
    ##   short, or was sealed under another key
    open(sealed: u8[]): Result<u8[]> {
        return open(sealed, Array<u8>());
    }

    ## Checks and decrypts what `seal` returned with `associated_data`.
    ##
    ## @param sealed the nonce, ciphertext and tag `seal` returned
    ## @param associated_data the bytes given to `seal`
    ## @returns the plaintext, or an error when `sealed` or
    ##   `associated_data` was changed, `sealed` is too short, or it was
    ##   sealed under another key
    open(sealed: u8[], associated_data: u8[]): Result<u8[]> {
        return _open_prefixed(false, _key, sealed, associated_data);
    }

    ## Encrypts and authenticates under a nonce the caller chooses. Never
    ## use one nonce twice with the same key: that reveals both messages.
    ##
    ## @param nonce the nonce, `NONCE_SIZE` bytes
    ## @param plaintext the message
    ## @param associated_data bytes authenticated but not encrypted
    ## @returns the ciphertext then the tag (`TAG_SIZE` bytes), or an error
    ##   when `nonce` is not `NONCE_SIZE` bytes
    seal_with_nonce(nonce: u8[], plaintext: u8[], associated_data: u8[]): Result<u8[]> {
        return _seal(false, _key, nonce, plaintext, associated_data);
    }

    ## Checks and decrypts a ciphertext from `seal_with_nonce`.
    ##
    ## @param nonce the nonce it was sealed under
    ## @param ciphertext the ciphertext then the tag
    ## @param associated_data the bytes given to `seal_with_nonce`
    ## @returns the plaintext, or an error when anything was changed or
    ##   `nonce` is not `NONCE_SIZE` bytes
    open_with_nonce(nonce: u8[], ciphertext: u8[], associated_data: u8[]): Result<u8[]> {
        return _open(false, _key, nonce, ciphertext, associated_data);
    }
}

## AES-256-GCM: encrypts and authenticates with a 32-byte key, on the CPU's
## AES instructions.
##
## It runs only where the CPU has them (x86-64 with AES-NI and PCLMUL, and
## ARMv8 with its crypto extensions); `is_available` says whether it can,
## and `from_key` fails when it cannot. `ChaCha20Poly1305` runs anywhere.
## Nonces and associated data work as they do for `ChaCha20Poly1305`.
##
## @example
##     import crypto;
##
##     main(): int {
##         if (!crypto.Aes256Gcm.is_available()) {
##             return 0;
##         }
##         var cipher = crypto.Aes256Gcm.from_key(crypto.Aes256Gcm.generate_key()).value();
##         var sealed = cipher.seal("attack at dawn".bytes(), "header".bytes());
##         print(cipher.open(sealed, "header".bytes()).is_ok());   # true
##         return 0;
##     }
export struct Aes256Gcm {
    var _key: u8[];

    ## Makes a cipher that seals and opens with `key`; `from_key` returns
    ## an error instead of panicking.
    ##
    ## @param key the key, `KEY_SIZE` bytes, which the cipher copies
    ## @panics if `key` is not `KEY_SIZE` bytes, or the CPU cannot run
    ##   AES-256-GCM
    construct(key: u8[]) {
        assert(key.count == KEY_SIZE, $"an AES-256-GCM key is {KEY_SIZE} bytes, not {key.count}");
        assert(is_available(), "this CPU has no AES-256-GCM instructions");
        _key = key.copy();
    }

    ## Returns whether this CPU can run AES-256-GCM.
    ##
    ## @returns true when the CPU has the instructions it needs
    static is_available(): bool {
        _init();
        return crypto_aead_aes256gcm_is_available() == 1;
    }

    ## Returns a new random key.
    ##
    ## @returns `KEY_SIZE` random bytes
    static generate_key(): u8[] {
        return random_bytes(KEY_SIZE);
    }

    ## Makes a cipher that seals and opens with `key`.
    ##
    ## @param key the key, `KEY_SIZE` bytes
    ## @returns the cipher, or an error when `key` is not `KEY_SIZE` bytes
    ##   or the CPU cannot run AES-256-GCM
    static from_key(key: u8[]): Result<Aes256Gcm> {
        if (key.count != KEY_SIZE) {
            return Result<Aes256Gcm>.err(Error($"an AES-256-GCM key is {KEY_SIZE} bytes, not {key.count}"));
        }
        if (!is_available()) {
            return Result<Aes256Gcm>.err(Error("this CPU has no AES-256-GCM instructions"));
        }
        return Result<Aes256Gcm>.ok(Aes256Gcm(key));
    }

    ## Encrypts and authenticates `plaintext` under a fresh random nonce.
    ##
    ## @param plaintext the message
    ## @returns the nonce (`NONCE_SIZE` bytes), then the ciphertext, then
    ##   the tag (`TAG_SIZE` bytes)
    seal(plaintext: u8[]): u8[] {
        return seal(plaintext, Array<u8>());
    }

    ## Encrypts and authenticates `plaintext`, and authenticates
    ## `associated_data`, under a fresh random nonce.
    ##
    ## @param plaintext the message
    ## @param associated_data bytes `open` must be given too
    ## @returns the nonce (`NONCE_SIZE` bytes), then the ciphertext, then
    ##   the tag (`TAG_SIZE` bytes)
    seal(plaintext: u8[], associated_data: u8[]): u8[] {
        return _seal_random(true, _key, plaintext, associated_data);
    }

    ## Checks and decrypts what `seal` returned.
    ##
    ## @param sealed the nonce, ciphertext and tag `seal` returned
    ## @returns the plaintext, or an error when `sealed` was changed, is too
    ##   short, or was sealed under another key
    open(sealed: u8[]): Result<u8[]> {
        return open(sealed, Array<u8>());
    }

    ## Checks and decrypts what `seal` returned with `associated_data`.
    ##
    ## @param sealed the nonce, ciphertext and tag `seal` returned
    ## @param associated_data the bytes given to `seal`
    ## @returns the plaintext, or an error when anything was changed,
    ##   `sealed` is too short, or it was sealed under another key
    open(sealed: u8[], associated_data: u8[]): Result<u8[]> {
        return _open_prefixed(true, _key, sealed, associated_data);
    }

    ## Encrypts and authenticates under a nonce the caller chooses. Never
    ## use one nonce twice with the same key: that reveals the key's
    ## authentication secret and both messages.
    ##
    ## @param nonce the nonce, `NONCE_SIZE` bytes
    ## @param plaintext the message
    ## @param associated_data bytes authenticated but not encrypted
    ## @returns the ciphertext then the tag (`TAG_SIZE` bytes), or an error
    ##   when `nonce` is not `NONCE_SIZE` bytes
    seal_with_nonce(nonce: u8[], plaintext: u8[], associated_data: u8[]): Result<u8[]> {
        return _seal(true, _key, nonce, plaintext, associated_data);
    }

    ## Checks and decrypts a ciphertext from `seal_with_nonce`.
    ##
    ## @param nonce the nonce it was sealed under
    ## @param ciphertext the ciphertext then the tag
    ## @param associated_data the bytes given to `seal_with_nonce`
    ## @returns the plaintext, or an error when anything was changed or
    ##   `nonce` is not `NONCE_SIZE` bytes
    open_with_nonce(nonce: u8[], ciphertext: u8[], associated_data: u8[]): Result<u8[]> {
        return _open(true, _key, nonce, ciphertext, associated_data);
    }
}

## Returns `count` bytes from the operating system's secure random number
## generator, for keys, nonces and salts.
##
## @param count how many bytes
## @returns the random bytes
export random_bytes(count: ulong): u8[] {
    _init();
    var buffer = _alloc(count);
    randombytes_buf(buffer as __ptr<void>, count);
    var bytes = _copy_out(buffer, count);
    _wipe(buffer, count);
    return bytes;
}

_seal_random(aes: bool, key: u8[], plaintext: u8[], associated_data: u8[]): u8[] {
    var nonce = random_bytes(NONCE_SIZE);
    var sealed = nonce.copy();
    sealed.append_all(_seal(aes, key, nonce, plaintext, associated_data).value());
    return sealed;
}

_open_prefixed(aes: bool, key: u8[], sealed: u8[], associated_data: u8[]): Result<u8[]> {
    if (sealed.count < NONCE_SIZE + TAG_SIZE) {
        return Result<u8[]>.err(Error("the sealed message is too short"));
    }
    var nonce = sealed.slice(0, NONCE_SIZE).to_array();
    var ciphertext = sealed.slice(NONCE_SIZE, sealed.count).to_array();
    return _open(aes, key, nonce, ciphertext, associated_data);
}

_seal(aes: bool, key: u8[], nonce: u8[], plaintext: u8[], associated_data: u8[]): Result<u8[]> {
    if (nonce.count != NONCE_SIZE) {
        return Result<u8[]>.err(Error($"a nonce is {NONCE_SIZE} bytes, not {nonce.count}"));
    }
    _init();
    var size = plaintext.count + TAG_SIZE;
    var out = _alloc(size);
    var m = _copy_in(plaintext);
    var ad = _copy_in(associated_data);
    var n = _copy_in(nonce);
    var k = _copy_in(key);
    if (aes) {
        crypto_aead_aes256gcm_encrypt(out, __null, m, plaintext.count, ad, associated_data.count, __null, n, k);
    } else {
        crypto_aead_chacha20poly1305_ietf_encrypt(
            out, __null, m, plaintext.count, ad, associated_data.count, __null, n, k
        );
    }
    var sealed = _copy_out(out, size);
    _wipe(out, size);
    _wipe(m, plaintext.count);
    _wipe(ad, associated_data.count);
    _wipe(n, nonce.count);
    _wipe(k, key.count);
    return Result<u8[]>.ok(sealed);
}

_open(aes: bool, key: u8[], nonce: u8[], ciphertext: u8[], associated_data: u8[]): Result<u8[]> {
    if (nonce.count != NONCE_SIZE) {
        return Result<u8[]>.err(Error($"a nonce is {NONCE_SIZE} bytes, not {nonce.count}"));
    }
    if (ciphertext.count < TAG_SIZE) {
        return Result<u8[]>.err(Error("the ciphertext is shorter than its tag"));
    }
    _init();
    var size = ciphertext.count - TAG_SIZE;
    var out = _alloc(size);
    var c = _copy_in(ciphertext);
    var ad = _copy_in(associated_data);
    var n = _copy_in(nonce);
    var k = _copy_in(key);
    int status;
    if (aes) {
        status = crypto_aead_aes256gcm_decrypt(
            out, __null, __null, c, ciphertext.count, ad, associated_data.count, n, k
        );
    } else {
        status = crypto_aead_chacha20poly1305_ietf_decrypt(
            out, __null, __null, c, ciphertext.count, ad, associated_data.count, n, k
        );
    }
    var plaintext = _copy_out(out, size);
    _wipe(out, size);
    _wipe(c, ciphertext.count);
    _wipe(ad, associated_data.count);
    _wipe(n, nonce.count);
    _wipe(k, key.count);
    if (status != 0) {
        return Result<u8[]>.err(Error("the message failed authentication: wrong key, or changed in transit"));
    }
    return Result<u8[]>.ok(plaintext);
}
