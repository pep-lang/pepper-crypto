import crypto;
import digest;
import "hex";

# RFC 5869, appendix A, test cases 1 to 3.
[Test]
hkdf_matches_rfc5869_test_1() {
    var okm = crypto.hkdf_sha256(
        _hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        _hex("000102030405060708090a0b0c"),
        _hex("f0f1f2f3f4f5f6f7f8f9"),
        42
    ).value();
    expect_equal(
        digest.to_hex(okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
}

[Test]
hkdf_matches_rfc5869_test_2() {
    var ikm = Array<u8>();
    var salt = Array<u8>();
    var info = Array<u8>();
    for (var i in 0..80) {
        ikm.append(i as u8);
        salt.append((0x60 + i) as u8);
        info.append((0xb0 + i) as u8);
    }
    var okm = crypto.hkdf_sha256(ikm, salt, info, 82).value();
    expect_equal(
        digest.to_hex(okm),
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
    );
}

[Test]
hkdf_matches_rfc5869_test_3() {
    var okm = crypto.hkdf_sha256(
        _hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), Array<u8>(), Array<u8>(), 42
    ).value();
    expect_equal(
        digest.to_hex(okm), "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    );
}

[Test]
hkdf_size_limits() {
    expect_equal(crypto.hkdf_sha256(_hex("00"), Array<u8>(), Array<u8>(), 8160).value().count, 8160 as ulong);
    expect_true(crypto.hkdf_sha256(_hex("00"), Array<u8>(), Array<u8>(), 8161).is_err());
    expect_equal(crypto.hkdf_sha256(_hex("00"), Array<u8>(), Array<u8>(), 0).value().count, 0 as ulong);
}
