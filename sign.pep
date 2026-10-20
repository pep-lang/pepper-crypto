## Ed25519 signatures (RFC 8032): `SigningKey` and `VerifyingKey`.

import "aead";
import "sodium";

## The size in bytes of an Ed25519 seed, the secret a `SigningKey` is made
## from.
export const SEED_SIZE: ulong = 32;
## The size in bytes of an Ed25519 public key.
export const PUBLIC_KEY_SIZE: ulong = 32;
## The size in bytes of an Ed25519 signature.
export const SIGNATURE_SIZE: ulong = 64;

## An Ed25519 secret key, which signs messages.
##
## Make one with `generate`, or from a stored 32-byte seed with
## `from_seed`. Store the `seed()` secretly; share `verifying_key()`.
##
## @example
##     import crypto;
##
##     main(): int {
##         var key = crypto.SigningKey.generate();
##         var signature = key.sign("hello".bytes());
##         var ok = key.verifying_key().verify("hello".bytes(), signature);
##         print(ok);   # true
##         return 0;
##     }
export struct SigningKey {
    var _seed: u8[];
    # libsodium's 64-byte secret key: the seed, then the public key.
    var _secret: u8[];
    var _public: u8[];

    ## Makes the key a seed stands for; `from_seed` returns an error
    ## instead of panicking.
    ##
    ## @param seed the seed, `SEED_SIZE` bytes, which the key copies
    ## @panics if `seed` is not `SEED_SIZE` bytes
    construct(seed: u8[]) {
        assert(seed.count == SEED_SIZE, $"an Ed25519 seed is {SEED_SIZE} bytes, not {seed.count}");
        _init();
        var s = _copy_in(seed);
        var public_key = _alloc(PUBLIC_KEY_SIZE);
        var secret = _alloc(64);
        crypto_sign_seed_keypair(public_key, secret, s);
        _seed = seed.copy();
        _secret = _copy_out(secret, 64);
        _public = _copy_out(public_key, PUBLIC_KEY_SIZE);
        _wipe(s, SEED_SIZE);
        _wipe(secret, 64);
        _wipe(public_key, PUBLIC_KEY_SIZE);
    }

    ## Returns a new random key.
    ##
    ## @returns the key
    static generate(): SigningKey {
        return SigningKey(random_bytes(SEED_SIZE));
    }

    ## Makes the key a seed stands for: the same seed always makes the same
    ## key.
    ##
    ## @param seed the seed, `SEED_SIZE` bytes
    ## @returns the key, or an error when `seed` is not `SEED_SIZE` bytes
    static from_seed(seed: u8[]): Result<SigningKey> {
        if (seed.count != SEED_SIZE) {
            return Result<SigningKey>.err(Error($"an Ed25519 seed is {SEED_SIZE} bytes, not {seed.count}"));
        }
        return Result<SigningKey>.ok(SigningKey(seed));
    }

    ## Returns the seed, to store the key and make it again with
    ## `from_seed`. Keep it secret.
    ##
    ## @returns a copy of the `SEED_SIZE`-byte seed
    seed(): u8[] {
        return _seed.copy();
    }

    ## Returns the public half, which checks this key's signatures.
    ##
    ## @returns the verifying key
    verifying_key(): VerifyingKey {
        return VerifyingKey(_public);
    }

    ## Signs `message`. Ed25519 is deterministic: one key and message
    ## always give the same signature.
    ##
    ## @param message the bytes to sign
    ## @returns the `SIGNATURE_SIZE`-byte signature
    sign(message: u8[]): u8[] {
        _init();
        var signature = _alloc(SIGNATURE_SIZE);
        var m = _copy_in(message);
        var k = _copy_in(_secret);
        crypto_sign_detached(signature, __null, m, message.count, k);
        var bytes = _copy_out(signature, SIGNATURE_SIZE);
        _wipe(signature, SIGNATURE_SIZE);
        _wipe(m, message.count);
        _wipe(k, 64);
        return bytes;
    }
}

## An Ed25519 public key, which checks signatures.
export struct VerifyingKey {
    var _bytes: u8[];

    ## Makes a verifying key from its 32 bytes; `from_bytes` returns an
    ## error instead of panicking.
    ##
    ## @param bytes the public key, `PUBLIC_KEY_SIZE` bytes, which the key
    ##   copies
    ## @panics if `bytes` is not `PUBLIC_KEY_SIZE` bytes
    construct(bytes: u8[]) {
        assert(bytes.count == PUBLIC_KEY_SIZE, $"an Ed25519 public key is {PUBLIC_KEY_SIZE} bytes, not {bytes.count}");
        _bytes = bytes.copy();
    }

    ## Makes a verifying key from its 32 bytes, as `bytes()` gives them.
    ##
    ## @param bytes the public key, `PUBLIC_KEY_SIZE` bytes
    ## @returns the key, or an error when `bytes` is not
    ##   `PUBLIC_KEY_SIZE` bytes
    static from_bytes(bytes: u8[]): Result<VerifyingKey> {
        if (bytes.count != PUBLIC_KEY_SIZE) {
            return Result<VerifyingKey>.err(
                Error($"an Ed25519 public key is {PUBLIC_KEY_SIZE} bytes, not {bytes.count}")
            );
        }
        return Result<VerifyingKey>.ok(VerifyingKey(bytes));
    }

    ## Returns the key's bytes, to store or send.
    ##
    ## @returns a copy of the `PUBLIC_KEY_SIZE`-byte key
    bytes(): u8[] {
        return _bytes.copy();
    }

    ## Checks that `signature` is this key's signature of `message`.
    ##
    ## @param message the signed bytes
    ## @param signature the signature
    ## @returns true when it is; false when the message or signature was
    ##   changed, the signature is another key's, or it is not
    ##   `SIGNATURE_SIZE` bytes
    verify(message: u8[], signature: u8[]): bool {
        if (signature.count != SIGNATURE_SIZE) {
            return false;
        }
        _init();
        var s = _copy_in(signature);
        var m = _copy_in(message);
        var k = _copy_in(_bytes);
        var status = crypto_sign_verify_detached(s, m, message.count, k);
        _wipe(s, SIGNATURE_SIZE);
        _wipe(m, message.count);
        _wipe(k, PUBLIC_KEY_SIZE);
        return status == 0;
    }
}
