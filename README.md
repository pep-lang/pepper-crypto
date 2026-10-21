# pepper-crypto

Cryptography for [Pepper](https://github.com/pep-lang/pepper), on
[libsodium](https://libsodium.org): authenticated encryption, Ed25519
signatures, X25519 key exchange, HKDF key derivation and Argon2id password
hashing. Every primitive is libsodium's; this package only binds it. Keys,
nonces and data are byte arrays (`u8[]`), and a call that can fail returns
a `Result`.

One module, **`crypto`**:

- **`ChaCha20Poly1305`** (RFC 8439) and **`Aes256Gcm`**: authenticated
  encryption with associated data. **`from_key(key)`** makes a cipher
  (**`generate_key()`** makes a random key); **`seal(plaintext,
  associated_data)`** picks a fresh random nonce and returns nonce,
  ciphertext and tag in one array, and **`open(sealed,
  associated_data)`** returns the plaintext, or an error when anything
  was changed. **`seal_with_nonce`** and **`open_with_nonce`** take the
  nonce from the caller, for protocols that fix it. AES-256-GCM needs the
  CPU's AES instructions: **`Aes256Gcm.is_available()`** says whether it
  has them.
- **`SigningKey`** and **`VerifyingKey`**: Ed25519 (RFC 8032).
  **`generate()`** or **`from_seed(seed)`**, **`sign(message)`**,
  **`verifying_key()`**, and **`verify(message, signature)`**.
- **`X25519SecretKey`**: X25519 key exchange (RFC 7748).
  **`generate()`**, **`public_key()`**, and **`shared_secret(peer_public)`**,
  which fails on a low-order peer key.
- **`hkdf_sha256(input_key, salt, info, size)`**: HKDF (RFC 5869), to turn
  a shared secret into keys.
- **`hash_password(password)`** and **`verify_password(password,
  encoded)`**: Argon2id, in the standard `$argon2id$...` encoded form,
  which holds its salt and cost.
- **`random_bytes(count)`**: the system's secure random bytes.
- **`version()`**: the libsodium version linked.

```pepper
import crypto;

main(): int {
    # Encrypt: a random key, and a fresh random nonce inside each sealed message.
    var key = crypto.ChaCha20Poly1305.generate_key();
    var cipher = crypto.ChaCha20Poly1305.from_key(key).value();
    var sealed = cipher.seal("attack at dawn".bytes(), "message 1".bytes());
    var opened = cipher.open(sealed, "message 1".bytes());
    if (opened is Err(e)) {
        print($"rejected: {e.message}");
        return 1;
    }

    # Sign and verify.
    var signer = crypto.SigningKey.generate();
    var signature = signer.sign(sealed);
    print(signer.verifying_key().verify(sealed, signature));   # true

    # Agree on a key, then derive the one to use.
    var alice = crypto.X25519SecretKey.generate();
    var bob = crypto.X25519SecretKey.generate();
    var shared = alice.shared_secret(bob.public_key()).value();
    var session = crypto.hkdf_sha256(shared, Array<u8>(), "chat v1".bytes(), crypto.KEY_SIZE).value();
    print(session.count);   # 32

    # Store a password.
    var stored = crypto.hash_password("correct horse battery staple").value();
    print(crypto.verify_password("correct horse battery staple", stored));   # true
    return 0;
}
```

## Installing libsodium

The package links the system's libsodium, 1.0.18 or later, rather than
building its own copy:

- **Linux:** `libsodium.so`, from the distribution's development package
  (`apt install libsodium-dev`, `dnf install libsodium-devel`).
- **macOS:** Homebrew's (`brew install libsodium`); the package looks in
  `/opt/homebrew/lib` and `/usr/local/lib`.
- **Windows:** the static `libsodium.lib` from vcpkg
  (`vcpkg install libsodium:x64-windows-static`). Put its folder on
  `PEPPER_LIBRARY_PATH`:

  ```sh
  set PEPPER_LIBRARY_PATH=C:\vcpkg\installed\x64-windows-static\lib
  ```

`crypto.version()` says which version the program runs against.

## Limits

- No PBKDF2 or scrypt: libsodium offers neither PBKDF2 nor an encoded
  scrypt form that other tools share. Use `hash_password` (Argon2id) for
  passwords and `hkdf_sha256` for key derivation.
- Random nonces of 12 bytes are safe for about 2^32 messages under one key;
  use a new key before that.
- Keys live in ordinary Pepper arrays, which are not locked in memory or
  wiped when freed. The C buffers the package hands libsodium are wiped.
- `hash_password` uses libsodium's interactive cost (64 MiB, 2 passes);
  there is no option for another cost yet.

## Using it

This repository is a package: `pep.toml` marks its root, and its root
`module.pep` is the `crypto` module. Add it to a project under the name
`crypto`:

```sh
pepper package add pep-lang/pepper-crypto --name crypto
```

which writes

```toml
[dependencies]
crypto = { github = "pep-lang/pepper-crypto" }
```

Without a project, put a folder named `crypto` that holds (or links to)
this repository on the import path: `pepper build -I packages main.pep`.

## Tests

```sh
tests/run.sh path/to/pepper
```

runs the `[Test]` functions in `tests/` with `pepper test`, against the
published test vectors: RFC 8439 for ChaCha20-Poly1305, the GCM
specification's test cases 14 and 16 for AES-256-GCM
(`aead_test.pep`), RFC 8032 for Ed25519 (`sign_test.pep`), RFC 7748 for
X25519 (`key_exchange_test.pep`), RFC 5869 for HKDF (`kdf_test.pep`)
and encoded Argon2id hashes from the Argon2 reference implementation's
tests (`password_test.pep`), plus tamper tests (a flipped bit must fail
to open or verify) and password hashing round trips. On Windows, set `PEPPER_LIBRARY_PATH` first
(see above).

## Releasing

CI (`.github/workflows/ci.yml`) runs the tests on Linux, macOS and
Windows for every push to `main` and every pull request. To release, set
`version` in `pep.toml`, merge, then push the matching tag
(`git tag v1.0.0 && git push origin v1.0.0`): CI tests the tag and
publishes a GitHub release for it. `pepper package add` and `pepper
package update` find versions by their tags.

## License

Apache-2.0; see [LICENSE](LICENSE). libsodium is under the ISC license
and is not part of this repository; see [NOTICE](NOTICE).
