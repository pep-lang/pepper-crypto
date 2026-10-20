import crypto;
import digest;
import "hex";

_flip_bit(bytes: u8[], index: ulong): u8[] {
    var changed = bytes.copy();
    changed[index] = changed[index] ^ 1;
    return changed;
}

# RFC 8439, section 2.8.2.
const _RFC8439_KEY = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
const _RFC8439_NONCE = "070000004041424344454647";
const _RFC8439_AAD = "50515253c0c1c2c3c4c5c6c7";
const _RFC8439_PLAINTEXT = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
const _RFC8439_CIPHERTEXT = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
const _RFC8439_TAG = "1ae10b594f09e26a7e902ecbd0600691";

_rfc8439(): crypto.ChaCha20Poly1305 {
    return crypto.ChaCha20Poly1305.from_key(_hex(_RFC8439_KEY)).value();
}

[Test]
chacha20_poly1305_matches_rfc8439() {
    var sealed = _rfc8439().seal_with_nonce(
        _hex(_RFC8439_NONCE), _RFC8439_PLAINTEXT.bytes(), _hex(_RFC8439_AAD)
    ).value();
    expect_equal(digest.to_hex(sealed), _RFC8439_CIPHERTEXT + _RFC8439_TAG);
}

[Test]
chacha20_poly1305_opens_the_rfc8439_vector() {
    var opened = _rfc8439().open_with_nonce(
        _hex(_RFC8439_NONCE), _hex(_RFC8439_CIPHERTEXT + _RFC8439_TAG), _hex(_RFC8439_AAD)
    ).value();
    expect_equal(digest.to_hex(opened), digest.to_hex(_RFC8439_PLAINTEXT.bytes()));
}

[Test]
a_flipped_ciphertext_bit_fails_to_open() {
    var cipher = _rfc8439();
    var sealed = _hex(_RFC8439_CIPHERTEXT + _RFC8439_TAG);
    for (var index in [0 as ulong, 57, sealed.count - 1]) {
        var opened = cipher.open_with_nonce(_hex(_RFC8439_NONCE), _flip_bit(sealed, index), _hex(_RFC8439_AAD));
        expect_true(opened.is_err());
    }
}

[Test]
changed_associated_data_fails_to_open() {
    var opened = _rfc8439().open_with_nonce(
        _hex(_RFC8439_NONCE), _hex(_RFC8439_CIPHERTEXT + _RFC8439_TAG), _hex("50515253c0c1c2c3c4c5c6c8")
    );
    expect_true(opened.is_err());
}

[Test]
seal_round_trips_with_a_fresh_nonce_each_time() {
    var cipher = crypto.ChaCha20Poly1305.from_key(crypto.ChaCha20Poly1305.generate_key()).value();
    var message = "attack at dawn".bytes();
    var first = cipher.seal(message, "header".bytes());
    var second = cipher.seal(message, "header".bytes());
    expect_equal(first.count, crypto.NONCE_SIZE + message.count + crypto.TAG_SIZE);
    expect_true(digest.to_hex(first) != digest.to_hex(second));
    expect_equal(digest.to_hex(cipher.open(first, "header".bytes()).value()), digest.to_hex("attack at dawn".bytes()));
    expect_equal(digest.to_hex(cipher.open(second, "header".bytes()).value()), digest.to_hex("attack at dawn".bytes()));
    expect_true(cipher.open(first).is_err());
    expect_true(cipher.open(_flip_bit(first, 3), "header".bytes()).is_err());
}

[Test]
seal_round_trips_an_empty_message() {
    var cipher = crypto.ChaCha20Poly1305.from_key(crypto.ChaCha20Poly1305.generate_key()).value();
    var sealed = cipher.seal(Array<u8>());
    expect_equal(sealed.count, crypto.NONCE_SIZE + crypto.TAG_SIZE);
    expect_equal(cipher.open(sealed).value().count, 0 as ulong);
}

[Test]
another_key_fails_to_open() {
    var sealed = _rfc8439().seal("hello".bytes());
    var other = crypto.ChaCha20Poly1305.from_key(crypto.ChaCha20Poly1305.generate_key()).value();
    expect_true(other.open(sealed).is_err());
}

[Test]
bad_sizes_are_errors() {
    expect_true(crypto.ChaCha20Poly1305.from_key(_hex("0011")).is_err());
    expect_true(_rfc8439().seal_with_nonce(_hex("00"), "x".bytes(), Array<u8>()).is_err());
    expect_true(_rfc8439().open(_hex("000102")).is_err());
    expect_true(_rfc8439().open_with_nonce(_hex(_RFC8439_NONCE), _hex("00"), Array<u8>()).is_err());
}

# Test cases 14 and 16 of the GCM specification (McGrew and Viega), which
# NIST's GCM validation uses.
[Test]
aes256_gcm_matches_the_gcm_test_vectors() {
    if (!crypto.Aes256Gcm.is_available()) {
        print("skipped: no AES-256-GCM instructions on this CPU");
        return;
    }
    var zero = crypto.Aes256Gcm.from_key(
        _hex("0000000000000000000000000000000000000000000000000000000000000000")
    ).value();
    var sealed = zero.seal_with_nonce(
        _hex("000000000000000000000000"), _hex("00000000000000000000000000000000"), Array<u8>()
    ).value();
    expect_equal(digest.to_hex(sealed), "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");

    var key = crypto.Aes256Gcm.from_key(
        _hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
    ).value();
    var nonce = _hex("cafebabefacedbaddecaf888");
    var aad = _hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    var plaintext = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
    var expected = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
        + "76fc6ece0f4e1768cddf8853bb2d551b";
    expect_equal(digest.to_hex(key.seal_with_nonce(nonce, _hex(plaintext), aad).value()), expected);
    expect_equal(digest.to_hex(key.open_with_nonce(nonce, _hex(expected), aad).value()), plaintext);
    expect_true(key.open_with_nonce(nonce, _flip_bit(_hex(expected), 10), aad).is_err());
}

[Test]
aes256_gcm_seal_round_trips() {
    if (!crypto.Aes256Gcm.is_available()) {
        expect_true(crypto.Aes256Gcm.from_key(crypto.Aes256Gcm.generate_key()).is_err());
        return;
    }
    var cipher = crypto.Aes256Gcm.from_key(crypto.Aes256Gcm.generate_key()).value();
    var sealed = cipher.seal("attack at dawn".bytes());
    expect_equal(digest.to_hex(cipher.open(sealed).value()), digest.to_hex("attack at dawn".bytes()));
    expect_true(cipher.open(_flip_bit(sealed, sealed.count - 1)).is_err());
}

[Test]
random_bytes_differ() {
    var a = crypto.random_bytes(32);
    expect_equal(a.count, 32 as ulong);
    expect_true(digest.to_hex(a) != digest.to_hex(crypto.random_bytes(32)));
}

[Test]
reports_the_library_version() {
    expect_true(crypto.version().starts_with("1."));
}

[Test]
[ShouldPanic("a ChaCha20-Poly1305 key is 32 bytes, not 2")]
constructing_with_a_short_key_panics() {
    crypto.ChaCha20Poly1305(_hex("0011"));
}
