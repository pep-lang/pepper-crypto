## Key derivation: `hkdf_sha256` (RFC 5869).

import digest;

## Derives `size` bytes of key material from `input_key` with HKDF-SHA256
## (RFC 5869): extract, then expand.
##
## Use it to turn a shared secret, such as one from
## `X25519SecretKey.shared_secret`, into keys. It is not for passwords:
## those need `hash_password`, which is slow on purpose.
##
## @param input_key the secret to derive from
## @param salt a non-secret random value, or empty
## @param info what the key is for, such as `"app v1 encryption"`; keys
##   derived with different `info` are independent
## @param size how many bytes to derive, at most 8160 (255 * 32)
## @returns the derived bytes, or an error when `size` is over 8160
## @example
##     import crypto;
##
##     main(): int {
##         var key = crypto.hkdf_sha256(crypto.random_bytes(32), Array<u8>(), "demo".bytes(), 32).value();
##         print(key.count);   # 32
##         return 0;
##     }
export hkdf_sha256(input_key: u8[], salt: u8[], info: u8[], size: ulong): Result<u8[]> {
    if (size > 255 * 32) {
        return Result<u8[]>.err(Error($"HKDF-SHA256 derives at most 8160 bytes, not {size}"));
    }
    # An empty salt is HMAC's all-zero key, as RFC 5869 says.
    var prk = digest.hmac_sha256(salt, input_key);
    var out = Array<u8>();
    var block = Array<u8>();
    u8 counter = 1;
    while (out.count < size) {
        var message = block.copy();
        message.append_all(info);
        message.append(counter);
        block = digest.hmac_sha256(prk, message);
        out.append_all(block);
        counter += 1;
    }
    out.truncate(size);
    return Result<u8[]>.ok(out);
}
