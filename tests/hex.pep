# Shared by the tests: the bytes hexadecimal test-vector text stands for.

import digest;

_hex(text: String): u8[] {
    return digest.from_hex(text).value();
}
