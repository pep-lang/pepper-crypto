import crypto;
import digest;
import "hex";

# RFC 7748, section 6.1.
const _ALICE_SECRET = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const _ALICE_PUBLIC = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const _BOB_SECRET = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
const _BOB_PUBLIC = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
const _SHARED = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

[Test]
x25519_matches_rfc7748() {
    var alice = crypto.X25519SecretKey.from_bytes(_hex(_ALICE_SECRET)).value();
    var bob = crypto.X25519SecretKey.from_bytes(_hex(_BOB_SECRET)).value();
    expect_equal(digest.to_hex(alice.public_key()), _ALICE_PUBLIC);
    expect_equal(digest.to_hex(bob.public_key()), _BOB_PUBLIC);
    expect_equal(digest.to_hex(alice.shared_secret(_hex(_BOB_PUBLIC)).value()), _SHARED);
    expect_equal(digest.to_hex(bob.shared_secret(_hex(_ALICE_PUBLIC)).value()), _SHARED);
}

# RFC 7748, section 5.2: the first vector, and the iterated test after 1
# and 1000 rounds, which walks the field arithmetic through many values.
[Test]
x25519_matches_rfc7748_function_vectors() {
    var scalar = crypto.X25519SecretKey.from_bytes(
        _hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    ).value();
    expect_equal(
        digest.to_hex(
            scalar.shared_secret(_hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")).value()
        ),
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    );

    var k = _hex("0900000000000000000000000000000000000000000000000000000000000000");
    var u = k.copy();
    for (var round in 1..1001) {
        var next = crypto.X25519SecretKey.from_bytes(k).value().shared_secret(u).value();
        u = k;
        k = next;
        if (round == 1) {
            expect_equal(digest.to_hex(k), "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
        }
    }
    expect_equal(digest.to_hex(k), "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
}

[Test]
generated_keys_agree() {
    var alice = crypto.X25519SecretKey.generate();
    var bob = crypto.X25519SecretKey.generate();
    var a = alice.shared_secret(bob.public_key()).value();
    var b = bob.shared_secret(alice.public_key()).value();
    expect_equal(digest.to_hex(a), digest.to_hex(b));
}

[Test]
a_low_order_public_key_is_an_error() {
    var zero = _hex("0000000000000000000000000000000000000000000000000000000000000000");
    expect_true(crypto.X25519SecretKey.generate().shared_secret(zero).is_err());
}

[Test]
bad_x25519_key_sizes_are_errors() {
    expect_true(crypto.X25519SecretKey.from_bytes(_hex("00")).is_err());
    expect_true(crypto.X25519SecretKey.generate().shared_secret(_hex("00")).is_err());
}
