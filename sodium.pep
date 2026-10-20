## The parts of libsodium's C API (`sodium.h`) the module calls, private to
## the module, and the helpers that move bytes between Pepper arrays and C
## buffers. Each declaration is the C function of the same name, with C's
## types: `unsigned char*` is `u8*`, `unsigned long long` and `size_t` are
## `ulong`.
##
## Which library is linked, per platform:
##
## - **Linux:** `libsodium.so` (`apt install libsodium-dev`).
## - **macOS:** `libsodium.dylib` from Homebrew (`brew install libsodium`),
##   found in `/opt/homebrew/lib` or `/usr/local/lib`.
## - **Windows:** the static `libsodium.lib` (`vcpkg install
##   libsodium:x64-windows-static`), whose folder goes on
##   `PEPPER_LIBRARY_PATH`; it also needs `advapi32` for its random numbers.

# The [Link]s on sodium_init and sodium_library_version_major link the
# library for every program that imports the module; the second carries
# what one attribute cannot: advapi32 on Windows, Intel Homebrew's folder
# on macOS.

[Target(OS(Windows))]
[Link("libsodium")]
extern int sodium_init();
[Target(OS(Windows))]
[Link("advapi32")]
extern int sodium_library_version_major();

[Target(OS(Mac))]
[Link(lib = "sodium", path = "/opt/homebrew/lib")]
extern int sodium_init();
[Target(OS(Mac))]
[Link(lib = "sodium", path = "/usr/local/lib")]
extern int sodium_library_version_major();

[Target(!OS(Windows) && !OS(Mac))]
[Link("sodium")]
extern int sodium_init();

extern void* malloc(ulong size);
extern void free(void* p);

extern char* sodium_version_string();
extern void sodium_memzero(void* p, ulong size);
extern int sodium_memcmp(void* a, void* b, ulong size);
extern void randombytes_buf(void* buffer, ulong size);

extern int crypto_aead_chacha20poly1305_ietf_encrypt(
    u8* c, ulong* c_size, u8* m, ulong m_size, u8* ad, ulong ad_size, u8* nsec, u8* nonce, u8* key
);
extern int crypto_aead_chacha20poly1305_ietf_decrypt(
    u8* m, ulong* m_size, u8* nsec, u8* c, ulong c_size, u8* ad, ulong ad_size, u8* nonce, u8* key
);
extern int crypto_aead_aes256gcm_is_available();
extern int crypto_aead_aes256gcm_encrypt(
    u8* c, ulong* c_size, u8* m, ulong m_size, u8* ad, ulong ad_size, u8* nsec, u8* nonce, u8* key
);
extern int crypto_aead_aes256gcm_decrypt(
    u8* m, ulong* m_size, u8* nsec, u8* c, ulong c_size, u8* ad, ulong ad_size, u8* nonce, u8* key
);

extern int crypto_sign_seed_keypair(u8* public_key, u8* secret_key, u8* seed);
extern int crypto_sign_detached(u8* signature, ulong* signature_size, u8* m, ulong m_size, u8* secret_key);
extern int crypto_sign_verify_detached(u8* signature, u8* m, ulong m_size, u8* public_key);

extern int crypto_scalarmult_base(u8* q, u8* n);
extern int crypto_scalarmult(u8* q, u8* n, u8* p);

extern int crypto_pwhash_str_alg(char* out, char* password, ulong password_size, ulong ops, ulong memory, int alg);
extern int crypto_pwhash_str_verify(char* hash, char* password, ulong password_size);
extern ulong crypto_pwhash_argon2id_opslimit_interactive();
extern ulong crypto_pwhash_argon2id_memlimit_interactive();

const _ARGON2ID13 = 2;
# crypto_pwhash_STRBYTES: an encoded hash and its NUL.
const _PWHASH_STRBYTES: ulong = 128;

# Starts libsodium; a no-op after the first call, and safe from any thread.
_init() {
    assert(sodium_init() >= 0, "libsodium could not start");
}

# A C copy of `bytes` (at least one byte, so it is never null), which the
# caller passes to `_wipe` when done.
_copy_in(bytes: u8[]): __ptr<u8> {
    var size = bytes.count;
    __ptr<u8> buffer = malloc(size == 0 ? 1 : size) as __ptr<u8>;
    assert(buffer != __null, "out of memory");
    for (var i in 0..size) {
        buffer[i] = bytes[i];
    }
    return buffer;
}

# A zeroed C buffer of `size` bytes (at least one), freed with `_wipe`.
_alloc(size: ulong): __ptr<u8> {
    __ptr<u8> buffer = malloc(size == 0 ? 1 : size) as __ptr<u8>;
    assert(buffer != __null, "out of memory");
    sodium_memzero(buffer as __ptr<void>, size == 0 ? 1 : size);
    return buffer;
}

# The `size` bytes at `data`, as an array.
_copy_out(data: __ptr<u8>, size: ulong): u8[] {
    var bytes = Array<u8>();
    bytes.reserve(size);
    for (var i in 0..size) {
        bytes.append(data[i]);
    }
    return bytes;
}

# Zeroes the `size` bytes at `buffer`, which may hold secrets, and frees it.
_wipe(buffer: __ptr<u8>, size: ulong) {
    sodium_memzero(buffer as __ptr<void>, size == 0 ? 1 : size);
    free(buffer as __ptr<void>);
}
