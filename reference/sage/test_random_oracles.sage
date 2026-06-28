load("reference/sage/lvc_lattice.sage")
load("reference/sage/test_helpers.sage")


h1_vector = h1_to_zq_vector([b"UAV-001", b"epoch-1"], 4, 17)
h2_scalar = h2_challenge_scalar([b"Yid", b"w", b"nonce", b"root", b"id"], 17)
oracle_report = random_oracle_instantiation_report(
    MP12GadgetParameters(n=2, q=97, base=2, m_bar=5),
    AuthenticationParameters(challenge_modulus=17, sigma_mask=20, beta_response=5000),
)

assert list(h1_vector) == [12, 6, 3, 14]
assert h2_scalar == 1
assert 0 <= h2_scalar < 17
assert oracle_report["active_h2_challenge_method"] == "h2_challenge_scalar"
assert oracle_report["implementation_language"] == "SageMath"
assert oracle_report["hash_primitive_source"] == "python_standard_library_hashlib_shake_256"
assert not oracle_report["third_party_crypto_dependency"]
assert not oracle_report["sage_native_crypto_hash_available"]
assert oracle_report["h1_output_is_sage_vector"]
assert oracle_report["h1_base_ring_matches_zq"]
assert oracle_report["h1_dimension_matches"]
assert oracle_report["h2_raw_is_sage_integer"]
assert oracle_report["h2_centered_is_sage_integer"]
assert oracle_report["active_h2_transcript_order"] == ["Y_id", "w", "rho", "rt", "id"]
assert oracle_report["framing_avoids_concat_ambiguity"]
assert oracle_report["challenge_space_instantiation"] == "centered_scalar"
assert oracle_report["challenge_space_cardinality"] == 17
assert oracle_report["challenge_bound_B_c"] == 8
assert oracle_report["delta_c_min"] == 1
assert oracle_report["centered_space_has_expected_cardinality"]
assert oracle_report["all_checks_hold"]
assert_raises(
    "expected dimension > 0",
    lambda: h1_to_zq_vector([b"id"], 0, 17),
)
assert_raises(
    "expected modulus > 1",
    lambda: h1_to_zq_vector([b"id"], 3, 1),
)
assert_raises(
    "expected modulus > 1",
    lambda: h2_challenge_scalar([b"Yid", b"w"], 1),
)

print("Sage random-oracle tests passed.")
