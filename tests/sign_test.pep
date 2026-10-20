import crypto;
import digest;
import "hex";

# Checks one test of RFC 8032, section 7.1: seed, public key, message and
# signature.
_check_rfc8032(seed: String, public_key: String, message: String, signature: String) {
    var key = crypto.SigningKey.from_seed(_hex(seed)).value();
    expect_equal(digest.to_hex(key.verifying_key().bytes()), public_key);
    expect_equal(digest.to_hex(key.sign(_hex(message))), signature);
    var verifying = crypto.VerifyingKey.from_bytes(_hex(public_key)).value();
    expect_true(verifying.verify(_hex(message), _hex(signature)));
}

[Test]
ed25519_matches_rfc8032_test_1() {
    _check_rfc8032(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
}

[Test]
ed25519_matches_rfc8032_test_2() {
    _check_rfc8032(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    );
}

[Test]
ed25519_matches_rfc8032_test_3() {
    _check_rfc8032(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
    );
}

[Test]
a_changed_message_or_signature_fails_to_verify() {
    var key = crypto.SigningKey.generate();
    var verifying = key.verifying_key();
    var signature = key.sign("hello".bytes());
    expect_true(verifying.verify("hello".bytes(), signature));
    expect_false(verifying.verify("hellp".bytes(), signature));
    var changed = signature.copy();
    changed[0] = changed[0] ^ 1;
    expect_false(verifying.verify("hello".bytes(), changed));
    expect_false(verifying.verify("hello".bytes(), _hex("00")));
    expect_false(crypto.SigningKey.generate().verifying_key().verify("hello".bytes(), signature));
}

[Test]
a_seed_makes_the_same_key_again() {
    var key = crypto.SigningKey.generate();
    var again = crypto.SigningKey.from_seed(key.seed()).value();
    expect_equal(digest.to_hex(again.verifying_key().bytes()), digest.to_hex(key.verifying_key().bytes()));
}

[Test]
bad_signing_key_sizes_are_errors() {
    expect_true(crypto.SigningKey.from_seed(_hex("00")).is_err());
    expect_true(crypto.VerifyingKey.from_bytes(_hex("00")).is_err());
}
