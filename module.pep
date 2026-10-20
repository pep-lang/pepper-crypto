## Authenticated encryption, signatures, key exchange, key derivation and
## password hashing, on libsodium.
##
## Bring it in with `import crypto`. It links the system's libsodium
## (1.0.18 or later): `apt install libsodium-dev` on Linux,
## `brew install libsodium` on macOS, and on Windows
## `vcpkg install libsodium:x64-windows-static` with that triplet's
## `lib` folder on `PEPPER_LIBRARY_PATH`. Keys, nonces and data are byte
## arrays (`u8[]`); a call that can fail returns a `Result`.
##
## - `ChaCha20Poly1305`, `Aes256Gcm`: AEAD; `seal` picks a random nonce and
##   `open` fails on any change
## - `SigningKey`, `VerifyingKey`: Ed25519 signatures
## - `X25519SecretKey`: X25519 key exchange
## - `hkdf_sha256`: HKDF key derivation
## - `hash_password`, `verify_password`: Argon2id password hashing
## - `random_bytes`: secure random bytes
## - `version`: the libsodium version
##
## @example
##     import crypto;
##
##     main(): int {
##         var cipher = crypto.ChaCha20Poly1305.from_key(crypto.ChaCha20Poly1305.generate_key()).value();
##         var sealed = cipher.seal("secret".bytes());
##         print(cipher.open(sealed).is_ok());   # true
##         return 0;
##     }

import "aead";
import "kdf";
import "key_exchange";
import "password";
import "sign";
import "sodium";

export ChaCha20Poly1305;
export Aes256Gcm;
export KEY_SIZE;
export NONCE_SIZE;
export TAG_SIZE;
export random_bytes;
export SigningKey;
export VerifyingKey;
export SEED_SIZE;
export PUBLIC_KEY_SIZE;
export SIGNATURE_SIZE;
export X25519SecretKey;
export X25519_KEY_SIZE;
export hkdf_sha256;
export hash_password;
export verify_password;

## Returns the version of the libsodium the program runs against.
##
## @returns the version, such as `"1.0.20"`
export version(): String {
    return String(sodium_version_string());
}
