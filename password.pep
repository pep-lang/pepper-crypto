## Password hashing with Argon2id: `hash_password` and `verify_password`.

import "sodium";

## Hashes `password` with Argon2id, under a fresh random salt, for storing.
##
## The result is the standard encoded form
## (`$argon2id$v=19$m=65536,t=2,p=1$<salt>$<hash>`), which holds the
## salt and the cost, so `verify_password` needs nothing else. The cost is
## libsodium's interactive level: 64 MiB of memory and 2 passes, about
## 0.1 s on a desktop CPU, for logins.
##
## @param password the password
## @returns the encoded hash, or an error when the memory it needs cannot
##   be allocated
## @example
##     import crypto;
##
##     main(): int {
##         var stored = crypto.hash_password("correct horse").value();
##         print(crypto.verify_password("correct horse", stored));   # true
##         print(crypto.verify_password("wrong", stored));           # false
##         return 0;
##     }
export hash_password(password: String): Result<String> {
    _init();
    var buffer = _alloc(_PWHASH_STRBYTES);
    var out = unsafe_cast<__ptr<char>>(buffer);
    var status = crypto_pwhash_str_alg(
        out,
        _c_text(password),
        password.size,
        crypto_pwhash_argon2id_opslimit_interactive(),
        crypto_pwhash_argon2id_memlimit_interactive(),
        _ARGON2ID13
    );
    var encoded = String(out);
    _wipe(buffer, _PWHASH_STRBYTES);
    if (status != 0) {
        return Result<String>.err(Error("Argon2id could not allocate its memory"));
    }
    return Result<String>.ok(encoded);
}

## Checks `password` against a hash from `hash_password`, in time that does
## not depend on where they differ.
##
## @param password the password to check
## @param encoded the stored hash
## @returns true when the password matches; false when it does not, or
##   `encoded` is not an Argon2 hash
export verify_password(password: String, encoded: String): bool {
    _init();
    return crypto_pwhash_str_verify(_c_text(encoded), _c_text(password), password.size) == 0;
}

# `text` as a NUL-terminated C string, never null.
_c_text(text: String): __ptr<char> {
    if (text.size == 0) {
        return "";
    }
    return text.c_str();
}
