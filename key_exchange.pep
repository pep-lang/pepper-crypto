## X25519 key exchange (RFC 7748): `X25519SecretKey`.

import "aead";
import "sodium";

## The size in bytes of an X25519 secret key, public key and shared secret.
export const X25519_KEY_SIZE: ulong = 32;

## An X25519 secret key, for agreeing on a shared secret with a peer.
##
## Each side makes a key, sends the other its `public_key()`, and calls
## `shared_secret` with the peer's: both get the same 32 bytes. Pass them
## through `hkdf_sha256`, with both public keys in `info`, before using
## them as a key.
##
## @example
##     import crypto;
##
##     main(): int {
##         var alice = crypto.X25519SecretKey.generate();
##         var bob = crypto.X25519SecretKey.generate();
##         var a = alice.shared_secret(bob.public_key()).value();
##         var b = bob.shared_secret(alice.public_key()).value();
##         print(a.compare(b) == 0);   # true
##         return 0;
##     }
export struct X25519SecretKey {
    var _bytes: u8[];

    ## Makes a key from its 32 bytes; `from_bytes` returns an error instead
    ## of panicking.
    ##
    ## @param bytes the secret key, `X25519_KEY_SIZE` bytes, which the key
    ##   copies
    ## @panics if `bytes` is not `X25519_KEY_SIZE` bytes
    construct(bytes: u8[]) {
        assert(bytes.count == X25519_KEY_SIZE, $"an X25519 secret key is {X25519_KEY_SIZE} bytes, not {bytes.count}");
        _bytes = bytes.copy();
    }

    ## Returns a new random key.
    ##
    ## @returns the key
    static generate(): X25519SecretKey {
        return X25519SecretKey(random_bytes(X25519_KEY_SIZE));
    }

    ## Makes a key from its 32 bytes, as `bytes()` gives them.
    ##
    ## @param bytes the secret key, `X25519_KEY_SIZE` bytes
    ## @returns the key, or an error when `bytes` is not `X25519_KEY_SIZE`
    ##   bytes
    static from_bytes(bytes: u8[]): Result<X25519SecretKey> {
        if (bytes.count != X25519_KEY_SIZE) {
            return Result<X25519SecretKey>.err(
                Error($"an X25519 secret key is {X25519_KEY_SIZE} bytes, not {bytes.count}")
            );
        }
        return Result<X25519SecretKey>.ok(X25519SecretKey(bytes));
    }

    ## Returns the key's bytes, to store it. Keep them secret.
    ##
    ## @returns a copy of the `X25519_KEY_SIZE`-byte key
    bytes(): u8[] {
        return _bytes.copy();
    }

    ## Returns the public key to send to the peer.
    ##
    ## @returns the `X25519_KEY_SIZE`-byte public key
    public_key(): u8[] {
        _init();
        var n = _copy_in(_bytes);
        var q = _alloc(X25519_KEY_SIZE);
        crypto_scalarmult_base(q, n);
        var bytes = _copy_out(q, X25519_KEY_SIZE);
        _wipe(n, X25519_KEY_SIZE);
        _wipe(q, X25519_KEY_SIZE);
        return bytes;
    }

    ## Computes the secret this key shares with the owner of `peer_public`.
    ##
    ## @param peer_public the peer's public key
    ## @returns the `X25519_KEY_SIZE`-byte shared secret, or an error when
    ##   `peer_public` is not `X25519_KEY_SIZE` bytes or is a low-order
    ##   point, which would make the secret all zeros
    shared_secret(peer_public: u8[]): Result<u8[]> {
        if (peer_public.count != X25519_KEY_SIZE) {
            return Result<u8[]>.err(Error($"an X25519 public key is {X25519_KEY_SIZE} bytes, not {peer_public.count}"));
        }
        _init();
        var n = _copy_in(_bytes);
        var p = _copy_in(peer_public);
        var q = _alloc(X25519_KEY_SIZE);
        var status = crypto_scalarmult(q, n, p);
        var secret = _copy_out(q, X25519_KEY_SIZE);
        _wipe(n, X25519_KEY_SIZE);
        _wipe(p, X25519_KEY_SIZE);
        _wipe(q, X25519_KEY_SIZE);
        if (status != 0) {
            return Result<u8[]>.err(Error("the peer's public key is a low-order point"));
        }
        return Result<u8[]>.ok(secret);
    }
}
