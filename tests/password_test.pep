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

# Hashes made by the Argon2 reference implementation (P-H-C/phc-winner-argon2,
# src/test.c): "password" under the salt "somesalt", Argon2id, version 19.
[Test]
a_reference_hash_verifies() {
    # hash_password's own cost: 64 MiB, 2 passes, 1 lane.
    var interactive = "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc";
    expect_true(crypto.verify_password("password", interactive));
    expect_false(crypto.verify_password("differentpassword", interactive));
    # 256 KiB over 2 lanes.
    var two_lanes = "$argon2id$v=19$m=256,t=2,p=2$c29tZXNhbHQ$bQk8UB/VmZZF4Oo79iDXuL5/0ttZwg2f/5U52iv1cDc";
    expect_true(crypto.verify_password("password", two_lanes));
    expect_false(crypto.verify_password("Password", two_lanes));
}
