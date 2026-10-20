import crypto;

[Test]
a_password_verifies_against_its_hash() {
    var stored = crypto.hash_password("correct horse battery staple").value();
    expect_true(stored.starts_with("$argon2id$"));
    expect_true(crypto.verify_password("correct horse battery staple", stored));
    expect_false(crypto.verify_password("correct horse battery stapler", stored));
}

[Test]
each_hash_has_its_own_salt() {
    var a = crypto.hash_password("pw").value();
    var b = crypto.hash_password("pw").value();
    expect_true(a != b);
    expect_true(crypto.verify_password("pw", b));
}

[Test]
an_empty_password_hashes_and_verifies() {
    var stored = crypto.hash_password("").value();
    expect_true(crypto.verify_password("", stored));
    expect_false(crypto.verify_password("x", stored));
}

[Test]
a_malformed_hash_does_not_verify() {
    expect_false(crypto.verify_password("pw", "not a hash"));
    expect_false(crypto.verify_password("pw", ""));
}
