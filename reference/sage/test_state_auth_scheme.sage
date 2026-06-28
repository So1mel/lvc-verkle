load("reference/sage/lvc_lattice.sage")
load("reference/sage/test_helpers.sage")


mp12_params = MP12GadgetParameters(n=2, q=97, base=2, m_bar=5)
mp12_A, mp12_trapdoor = trap_gen_mp12(mp12_params, [b"mp12-experiment-1"])
mp12_Rq = mp12_params.ring()

state_tree_params = VerkleTreeParameters(branching_factor=4, height=3)
state_tree = LatticeVerkleTree(state_tree_params, mp12_params)
state_tree_empty_root = state_tree.root()
mp12_full_credential, state_tree_root = register_identity(
    mp12_A,
    mp12_trapdoor,
    mp12_params,
    state_tree,
    b"UAV-STATE-001",
    b"epoch-1",
    sigma=120,
    beta=200,
    seed_parts=[b"register-state-1"],
    omega_factor=1,
)
state_tree_wrong_y = vector(
    mp12_Rq,
    [mp12_full_credential.y_id[0] + 1, mp12_full_credential.y_id[1]],
)
auth_params = AuthenticationParameters(
    challenge_modulus=17,
    sigma_mask=20,
    beta_response=5000,
)
auth_nonce = b"N" * int(auth_params.nonce_bytes)
wrong_auth_nonce = b"W" * int(auth_params.nonce_bytes)
auth_transcript = authenticate_identity(
    mp12_A,
    mp12_params,
    mp12_full_credential,
    b"UAV-STATE-001",
    auth_nonce,
    state_tree_root,
    auth_params,
    seed_parts=[b"auth-1"],
)
rejection_sampling_path_audit = authentication_rejection_sampling_path_audit(
    mp12_A,
    mp12_params,
    mp12_full_credential,
    b"UAV-STATE-001",
    auth_nonce,
    state_tree_root,
    auth_params,
    seed_parts=[b"auth-rejection-trace"],
    omega_factor=1,
)
auth_parameter_report = authentication_parameter_report(
    mp12_params,
    auth_params,
    beta=200,
    omega_factor=1,
)
lattice_asymptotic_report = paper_lattice_asymptotic_parameter_report(mp12_params)
auth_transcript_report = authentication_transcript_report(
    mp12_A,
    mp12_params,
    state_tree_params,
    b"UAV-STATE-001",
    mp12_full_credential.y_id,
    auth_nonce,
    state_tree_root,
    auth_transcript,
    auth_params,
)
wrong_nonce_auth_transcript_report = authentication_transcript_report(
    mp12_A,
    mp12_params,
    state_tree_params,
    b"UAV-STATE-001",
    mp12_full_credential.y_id,
    wrong_auth_nonce,
    state_tree_root,
    auth_transcript,
    auth_params,
)
weak_auth_parameter_report = authentication_parameter_report(
    mp12_params,
    AuthenticationParameters(
        challenge_modulus=17,
        sigma_mask=20,
        beta_response=100,
    ),
    beta=200,
    omega_factor=1,
)
assert auth_params.challenge_bound() == 8
assert auth_params.delta_c_min() == 1
assert auth_params.contains_challenge(auth_transcript.challenge)
assert -auth_params.challenge_bound() <= auth_transcript.challenge <= auth_params.challenge_bound()
assert auth_parameter_report["challenge_bound_B_c"] == 8
assert auth_parameter_report["delta_c_min"] == 1
assert auth_parameter_report["modulus_q"] == mp12_params.q
assert auth_parameter_report["sigma_mask_formula"] == "sigma_mask = alpha * B_c * beta"
assert auth_parameter_report["alpha_formula"] == (
    "alpha = sigma_mask / (B_c * beta), target alpha = omega(sqrt(log m))"
)
assert auth_parameter_report["alpha_sigma_mask"] == (
    auth_params.sigma_mask / (auth_params.challenge_bound() * 200)
)
assert auth_parameter_report["sqrt_log_m"] > 0
assert auth_parameter_report["alpha_over_sqrt_log_m"] > 0
assert not auth_parameter_report["alpha_dominates_sqrt_log_m"]
assert auth_parameter_report["recommended_beta_response"] == (
    auth_parameter_report["mask_norm_bound"] + auth_parameter_report["challenge_term_bound"]
)
assert auth_parameter_report["response_beta_formula"] == (
    "beta_response > sigma_mask * sqrt(m) * omega_factor + B_c * beta"
)
assert auth_parameter_report["q_bound_formula"] == (
    "q > max(2 * beta_response, 2 * beta_response / Delta_c_min + beta_response * omega_factor * sqrt(n * log(n)))"
)
assert auth_parameter_report["q_lower_bound_direct"] == 2 * auth_params.beta_response
assert auth_parameter_report["recommended_q_lower_bound"] == max(
    auth_parameter_report["q_lower_bound_direct"],
    auth_parameter_report["q_lower_bound_sis"],
)
assert auth_parameter_report["passes_recommended_bound"]
assert not auth_parameter_report["q_bound_holds"]
assert not weak_auth_parameter_report["passes_recommended_bound"]
assert lattice_asymptotic_report["scope"] == "paper_lattice_asymptotic_parameters"
assert lattice_asymptotic_report["formula"] == "m = n^(1 + delta), n^delta > ceil(log q)"
assert lattice_asymptotic_report["n"] == mp12_params.n
assert lattice_asymptotic_report["m"] == mp12_params.m
assert lattice_asymptotic_report["q"] == mp12_params.q
assert lattice_asymptotic_report["ceil_log_q_base2"] == 7
assert lattice_asymptotic_report["n_delta_proxy"] == mp12_params.m / mp12_params.n
assert lattice_asymptotic_report["n_delta_bound_holds"]
assert lattice_asymptotic_report["all_checks_hold"]
assert auth_transcript_report["verifies"]
assert auth_transcript_report["paper_algorithm"] == "Verify"
assert auth_transcript_report["paper_input"] == "Verify(pp,id,Y_id,rho,rt,tau)"
assert auth_transcript_report["paper_transcript"] == "tau=(pi_id,w,c,s)"
assert auth_transcript_report["paper_challenge_equation"] == (
    "c = H2(Y_id || w || rho || rt || id)"
)
assert auth_transcript_report["h2_transcript_order"] == ["Y_id", "w", "rho", "rt", "id"]
assert auth_transcript_report["transcript_fields"] == ["pi_id", "w", "c", "s"]
assert auth_transcript_report["transcript_shape_holds"]
assert auth_transcript_report["transcript_shape_report"]["response_base_ring_matches_zz"]
assert auth_transcript_report["transcript_shape_report"]["response_entries_are_integers"]
assert auth_transcript_report["path_proof_holds"]
assert auth_transcript_report["challenge_matches"]
assert auth_transcript_report["challenge_in_space"]
assert auth_transcript_report["response_norm_bound_holds"]
assert auth_transcript_report["equation_holds"]
assert auth_transcript_report["all_algorithmic_checks_hold"]
assert auth_transcript_report["expected_challenge"] == auth_transcript.challenge
assert auth_transcript.audit_report["mask_sampler"] == "truncated_discrete_gaussian_vector"
assert auth_transcript.audit_report["paper_algorithm"] == "Authenticate"
assert auth_transcript.audit_report["paper_transcript"] == "tau=(pi_id,w,c,s)"
assert auth_transcript.audit_report["paper_challenge"] == "(rho,rt)"
assert auth_transcript.audit_report["paper_mask_sampling"] == "r <- D_sigma^m"
assert auth_transcript.audit_report["paper_commitment_equation"] == "w = A*r mod q"
assert auth_transcript.audit_report["paper_challenge_equation"] == (
    "c = H2(Y_id || w || rho || rt || id)"
)
assert auth_transcript.audit_report["paper_response_equation"] == "s = r + c*z_id"
assert auth_transcript.audit_report["h2_transcript_order"] == ["Y_id", "w", "rho", "rt", "id"]
assert auth_transcript.audit_report["transcript_fields"] == ["pi_id", "w", "c", "s"]
assert auth_transcript.audit_report["sampler_backend"] == "shake256_inverse_cdf_truncated_window"
assert auth_transcript.audit_report["sampler_real_precision_bits"] == 256
assert auth_transcript.audit_report["sampler_draw_bits"] == 256
assert auth_transcript.audit_report["mask_dimension"] == mp12_params.m
assert auth_transcript.audit_report["mask_dimension_matches_m"]
assert auth_transcript.audit_report["commitment_dimension"] == mp12_params.n
assert auth_transcript.audit_report["commitment_dimension_matches_n"]
assert auth_transcript.audit_report["response_dimension"] == mp12_params.m
assert auth_transcript.audit_report["response_dimension_matches_m"]
assert auth_transcript.audit_report["sigma_mask"] == auth_params.sigma_mask
assert auth_transcript.audit_report["tail_cutoff"] == 12
assert auth_transcript.audit_report["continuous_tail_heuristic_bound"] > 0
assert auth_transcript.audit_report["accepted_attempt_index"] >= 0
assert auth_transcript.audit_report["attempt_count"] == (
    auth_transcript.audit_report["accepted_attempt_index"] + 1
)
assert auth_transcript.audit_report["attempt_count"] <= auth_params.max_attempts
assert auth_transcript.audit_report["rejected_attempt_count"] == (
    auth_transcript.audit_report["accepted_attempt_index"]
)
assert auth_transcript.audit_report["attempt_trace_count"] == (
    auth_transcript.audit_report["attempt_count"]
)
assert len(auth_transcript.audit_report["attempt_trace"]) == (
    auth_transcript.audit_report["attempt_count"]
)
assert auth_transcript.audit_report["all_rejected_attempts_failed_norm_bound"]
assert auth_transcript.audit_report["accepted_attempt_bound_holds"]
assert auth_transcript.audit_report["attempt_trace"][-1]["accepted"]
assert auth_transcript.audit_report["attempt_trace"][-1][
    "response_norm_bound_holds"
]
assert auth_transcript.audit_report["paper_rejection_sampling_step"] == (
    "If ||s|| > beta_response, resample r and repeat."
)
assert auth_transcript.audit_report["response_norm_squared"] == sum(
    value * value for value in auth_transcript.response
)
assert auth_transcript.audit_report["paper_response_bound_formula"] == (
    "||s|| <= ||r|| + ||c*z_id|| <= sigma_mask * sqrt(m) * omega_factor + B_c * beta"
)
assert auth_transcript.audit_report["mask_norm_bound"] > 0
assert auth_transcript.audit_report["mask_norm_bound_squared"] > 0
assert auth_transcript.audit_report["challenge_scaled_credential_bound"] == (
    auth_params.challenge_bound() * mp12_full_credential.beta
)
assert auth_transcript.audit_report["challenge_scaled_credential_norm_squared"] == (
    auth_transcript.challenge * auth_transcript.challenge * mp12_full_credential.norm_squared
)
assert auth_transcript.audit_report["challenge_scaled_credential_bound_holds"]
assert auth_transcript.audit_report["triangle_response_norm_bound"] > 0
assert auth_transcript.audit_report["triangle_response_norm_bound_squared"] > 0
assert auth_transcript.audit_report["response_norm_bound_holds"]
assert auth_transcript.audit_report["challenge_in_space"]
assert auth_transcript.audit_report["challenge_equation_holds"]
assert auth_transcript.audit_report["all_algorithmic_checks_hold"]
assert auth_transcript.audit_report["challenge"] == auth_transcript.challenge
assert rejection_sampling_path_audit["scope"] == "authentication_rejection_sampling_path"
assert rejection_sampling_path_audit["status"] == "controlled_rejection_then_acceptance"
assert rejection_sampling_path_audit["controlled_rejection_path_found"]
assert rejection_sampling_path_audit["rejected_before_accept"]
assert rejection_sampling_path_audit["accepted_at_selected_index"]
assert rejection_sampling_path_audit["all_checks_hold"]
assert rejection_sampling_path_audit["selected_accept_index"] > 0
assert rejection_sampling_path_audit["generation_report"]["rejected_attempt_count"] > 0
assert rejection_sampling_path_audit["generation_report"]["attempt_count"] == (
    rejection_sampling_path_audit["selected_accept_index"] + 1
)
assert rejection_sampling_path_audit["generation_report"][
    "all_rejected_attempts_failed_norm_bound"
]
assert rejection_sampling_path_audit["generation_report"]["accepted_attempt_bound_holds"]
assert wrong_nonce_auth_transcript_report["path_proof_holds"]
assert not wrong_nonce_auth_transcript_report["challenge_matches"]
assert not wrong_nonce_auth_transcript_report["verifies"]
tampered_auth_transcript = AuthenticationTranscript(
    auth_transcript.path_proof,
    auth_transcript.commitment,
    auth_transcript.challenge,
    auth_transcript.response + vector(ZZ, [1] + [0] * (mp12_params.m - 1)),
)
tampered_auth_transcript_report = authentication_transcript_report(
    mp12_A,
    mp12_params,
    state_tree_params,
    b"UAV-STATE-001",
    mp12_full_credential.y_id,
    auth_nonce,
    state_tree_root,
    tampered_auth_transcript,
    auth_params,
)
state_tree_registered_report = lattice_verkle_tree_state_report(state_tree)
state_tree_active_path_report = lattice_verkle_path_report(
    b"UAV-STATE-001",
    mp12_full_credential.y_id,
    mp12_full_credential.path_proof,
    state_tree_root,
    state_tree_params,
)
state_tree_position_binding_report = lattice_verkle_position_binding_report(
    b"UAV-STATE-001",
    mp12_full_credential.y_id,
    mp12_full_credential.path_proof,
    state_tree_root,
    state_tree_params,
)
state_commitment_backend_report = lattice_verkle_state_commitment_backend_report(
    state_tree
)
state_tree_wrong_y_path_report = lattice_verkle_path_report(
    b"UAV-STATE-001",
    state_tree_wrong_y,
    mp12_full_credential.path_proof,
    state_tree_root,
    state_tree_params,
)
state_tree_register_transition_report = root_transition_report(
    state_tree_empty_root,
    state_tree_root,
    "register_state_1",
)
state_tree_revoked_root = state_tree.revoke(b"UAV-STATE-001")
state_tree_revoked_report = lattice_verkle_tree_state_report(state_tree)
state_tree_revoked_path_report = lattice_verkle_path_report(
    b"UAV-STATE-001",
    mp12_full_credential.y_id,
    mp12_full_credential.path_proof,
    state_tree_revoked_root,
    state_tree_params,
)
state_tree_revoke_transition_report = root_transition_report(
    state_tree_root,
    state_tree_revoked_root,
    "revoke_state_1",
)
state_tree_reinsert_y = _tamper_zq_vector_first_coordinate(mp12_full_credential.y_id)
assert_raises(
    "identity is already revoked",
    lambda: state_tree.revoke(b"UAV-STATE-001"),
)
state_tree_reinsert_path, state_tree_reinsert_root = state_tree.insert(
    b"UAV-STATE-001",
    state_tree_reinsert_y,
)
state_tree_reinsert_report = lattice_verkle_tree_state_report(state_tree)
assert state_tree_reinsert_root != state_tree_revoked_root
assert state_tree_reinsert_path.slot_probe > 0
assert verify_verkle_path(
    b"UAV-STATE-001",
    state_tree_reinsert_y,
    state_tree_reinsert_path,
    state_tree_reinsert_root,
    state_tree_params,
)
assert not verify_verkle_path(
    b"UAV-STATE-001",
    mp12_full_credential.y_id,
    mp12_full_credential.path_proof,
    state_tree_reinsert_root,
    state_tree_params,
)
revoked_auth_transcript_report = authentication_transcript_report(
    mp12_A,
    mp12_params,
    state_tree_params,
    b"UAV-STATE-001",
    mp12_full_credential.y_id,
    auth_nonce,
    state_tree_revoked_root,
    auth_transcript,
    auth_params,
)
assert tampered_auth_transcript_report["challenge_matches"]
assert tampered_auth_transcript_report["path_proof_holds"]
assert not tampered_auth_transcript_report["equation_holds"]
assert not tampered_auth_transcript_report["verifies"]
assert not revoked_auth_transcript_report["path_proof_holds"]
assert not revoked_auth_transcript_report["verifies"]
transcript_input_validation = authentication_transcript_input_validation_audit(
    mp12_A,
    mp12_params,
    state_tree_params,
    b"UAV-STATE-001",
    mp12_full_credential.y_id,
    auth_nonce,
    state_tree_root,
    auth_transcript,
    auth_params,
)
assert transcript_input_validation["scope"] == "authentication_verify_malformed_transcript_inputs"
assert transcript_input_validation["valid_transcript_accepts"]
assert transcript_input_validation["all_malformed_rejected"]
assert transcript_input_validation["at_least_one_shape_failure_per_malformed"]
assert transcript_input_validation["all_checks_hold"]
validation_by_name = {
    case["name"]: case for case in transcript_input_validation["cases"]
}
for case_name in [
    "missing_transcript_fields",
    "malformed_path_proof",
    "commitment_dimension_mismatch",
    "commitment_ring_mismatch",
    "response_dimension_mismatch",
    "response_ring_mismatch",
    "challenge_not_integer",
]:
    assert validation_by_name[case_name]["verify_rejects"]
assert not validation_by_name["response_ring_mismatch"]["shape_checks_hold"]
assert not validation_by_name["response_ring_mismatch"]["shape_report"][
    "response_base_ring_matches_zz"
]
assert state_tree_registered_report["active_leaf_count"] == 1
assert state_tree_registered_report["revoked_leaf_count"] == 0
assert state_tree_registered_report["occupied_leaf_count"] == 1
assert state_tree_active_path_report["paper_object"] == (
    "pi_id = (idx_0..idx_{h-1}; Auth_0..Auth_{h-1}) for active (id, Y_id) membership"
)
assert state_tree_active_path_report["proof_commitment_model"] == (
    "paper_linear_verkle_auth_layers_with_b_minus_1_sibling_Zq_vectors"
)
assert state_tree_active_path_report["proof_size_model"] == (
    "leaf_index_u64 + slot_probe_u64 + height * index_u64 + height * (branching_factor - 1) * serialized_Zq_vector"
)
assert state_tree_active_path_report["vector_commitment_target_model"] == (
    "paper_linear_aggregation_Y_parent=sum_alpha_k_Com_k_mod_q"
)
assert state_tree_active_path_report["vector_commitment_target_opening_count"] == (
    state_tree_params.height
)
assert state_tree_active_path_report["commitment_count_over_vector_commitment_target"] == (
    state_tree_params.branching_factor - 1
)
assert state_tree_active_path_report["extra_commitments_over_vector_commitment_target"] == (
    state_tree_params.height * (state_tree_params.branching_factor - 2)
)
assert not state_tree_active_path_report["state_commitment_upgrade_required_for_verkle_claim"]
assert state_tree_active_path_report["paper_verkle_backend_claim_permitted"]
assert state_tree_active_path_report["paper_verkle_proof_size_model_claim_permitted"]
assert not state_tree_active_path_report["production_verkle_vector_commitment"]
assert not state_tree_active_path_report["production_verkle_proof_size_claim_permitted"]
assert state_tree_active_path_report["verification_leaf_status"] == "active"
assert state_tree_active_path_report["active_leaf_domain"] != state_tree_active_path_report["revoked_leaf_domain"]
assert state_tree_active_path_report["active_revoked_leaf_domains_distinct"]
assert state_tree_active_path_report["active_revoked_leaf_commitments_distinct"]
assert not state_tree_active_path_report["verifies_revoked_leaf_path"]
assert state_tree_active_path_report["revoked_leaf_does_not_verify_as_active_path"]
assert state_tree_active_path_report["active_membership_leaf_domain_checks_hold"]
assert state_tree_active_path_report["proof_shape_holds"]
assert state_tree_active_path_report["slot_probe"] == 0
assert state_tree_active_path_report["slot_probe_in_range"]
assert state_tree_active_path_report["leaf_index_matches_identity_probe"]
assert state_tree_active_path_report["commitment_count"] == (
    state_tree_params.height * (state_tree_params.branching_factor - 1)
)
assert state_tree_active_path_report["sibling_commitment_count"] == (
    state_tree_params.height * (state_tree_params.branching_factor - 1)
)
assert state_tree_active_path_report["path_metadata_bytes"] == 16 + 8 * state_tree_params.height
assert state_tree_active_path_report["proof_size_bytes"] == (
    16
    + 8 * state_tree_params.height
    + state_tree_active_path_report["commitment_count"] * (16 + 8 * mp12_params.n)
)
assert state_tree_active_path_report["verifies_active_path"]
assert state_tree_position_binding_report["security_model"] == "lattice_linear_verkle_position_binding_experiment"
assert state_tree_position_binding_report["paper_assumption"] == "Verkle commitment is position-binding"
assert state_tree_position_binding_report["slot_probe"] == 0
assert state_tree_position_binding_report["leaf_index_matches_identity_probe"]
assert state_tree_position_binding_report["leaf_index_matches_identity"]
assert state_tree_position_binding_report["verifies_active_path"]
assert state_tree_position_binding_report["rejects_tampered_y_id"]
assert state_tree_position_binding_report["rejects_tampered_identity"]
assert state_tree_position_binding_report["rejects_tampered_root"]
assert state_tree_position_binding_report["position_binding_checks_hold"]
assert state_commitment_backend_report["scope"] == "state_commitment_backend_audit"
assert state_commitment_backend_report["paper_security_assumption"] == (
    "SIS-backed binding of lattice vector commitments and Fiat-Shamir linear aggregation"
)
assert state_commitment_backend_report["current_backend"] == (
    "lattice_linear_verkle_tree"
)
assert state_commitment_backend_report["implemented_paper_claim_level"] == (
    "paper_linear_verkle_tree_with_Zq_vector_nodes_and_FS_coefficients"
)
assert state_commitment_backend_report["target_backend_family"] == (
    "paper_lattice_linear_verkle_tree"
)
assert state_commitment_backend_report["current_commitments_per_path"] == (
    state_tree_params.height * (state_tree_params.branching_factor - 1)
)
assert state_commitment_backend_report["vector_commitment_target_openings_per_path"] == (
    state_tree_params.height * (state_tree_params.branching_factor - 1)
)
assert state_commitment_backend_report["extra_commitments_over_vector_commitment_target"] == (
    0
)
assert state_commitment_backend_report["commitment_count_over_vector_commitment_target"] == (
    1
)
assert state_commitment_backend_report["implements_register_verify_revoke_state_semantics"]
assert state_commitment_backend_report["implements_position_binding_experiment"]
assert state_commitment_backend_report["verification_leaf_status"] == "active"
assert state_commitment_backend_report["revoked_state_leaf_status"] == "revoked"
assert state_commitment_backend_report["active_leaf_domain"] != state_commitment_backend_report["revoked_leaf_domain"]
assert state_commitment_backend_report["active_revoked_leaf_domains_distinct"]
assert state_commitment_backend_report["active_revoked_leaf_commitments_distinct"]
assert state_commitment_backend_report["revoked_leaf_represents_revocation_not_active_membership"]
fs_context_report = state_commitment_backend_report[
    "fiat_shamir_coefficient_context_report"
]
assert fs_context_report["scope"] == "lattice_verkle_fiat_shamir_coefficient_context"
assert fs_context_report["paper_formula"] == "alpha_k = H_FS(Com_k || context) mod q"
for field_name in [
    "branching_factor",
    "height",
    "lattice_dimension_n",
    "modulus_q",
    "level_from_leaf",
    "child_index",
    "parent_prefix_digits",
    "child_commitment",
]:
    assert field_name in fs_context_report["context_fields"]
assert fs_context_report["parent_prefix_digits_bound"]
assert fs_context_report["deterministic_replay_holds"]
assert fs_context_report["child_commitment_changes_coefficient"]
assert fs_context_report["child_index_changes_coefficient"]
assert fs_context_report["level_changes_coefficient"]
assert fs_context_report["parent_prefix_changes_coefficient"]
assert fs_context_report["all_checks_hold"]
assert state_commitment_backend_report["fiat_shamir_context_binds_parent_prefix"]
assert state_commitment_backend_report["fiat_shamir_context_checks_hold"]
assert state_commitment_backend_report["paper_verkle_backend_claim_permitted"]
assert state_commitment_backend_report["paper_verkle_proof_size_model_claim_permitted"]
assert state_commitment_backend_report["paper_verkle_security_assumption_matches_backend"]
assert state_commitment_backend_report["research_reference_backend"]
assert not state_commitment_backend_report["production_verkle_vector_commitment"]
assert not state_commitment_backend_report["production_verkle_proof_size_claim_permitted"]
assert not state_commitment_backend_report["final_security_claim_permitted"]
assert not state_commitment_backend_report["verkle_security_claim_permitted"]
assert state_commitment_backend_report["paper_alignment_action"] == (
    "paper_verkle_claim_matches_lattice_linear_verkle_reference_backend"
)
assert state_commitment_backend_report["all_checks_hold"]
assert state_tree_wrong_y_path_report["proof_shape_holds"]
assert not state_tree_wrong_y_path_report["verifies_active_path"]
assert state_tree_register_transition_report["root_changed"]
assert state_tree_revoked_report["active_leaf_count"] == 0
assert state_tree_revoked_report["revoked_leaf_count"] == 1
assert state_tree_revoked_path_report["proof_shape_holds"]
assert not state_tree_revoked_path_report["verifies_active_path"]
assert state_tree_revoked_path_report["verifies_revoked_leaf_path"]
assert state_tree_revoked_path_report["revoked_leaf_does_not_verify_as_active_path"]
assert state_tree_revoked_path_report["active_membership_leaf_domain_checks_hold"]
assert state_tree_reinsert_report["active_leaf_count"] == 1
assert state_tree_reinsert_report["revoked_leaf_count"] == 1
assert state_tree_revoke_transition_report["root_changed"]

state_tree_collision_report = lattice_verkle_collision_resolution_report(
    VerkleTreeParameters(branching_factor=2, height=1),
    mp12_params,
)
assert state_tree_collision_report["scope"] == "lattice_verkle_finite_tree_collision_resolution"
assert state_tree_collision_report["initial_indices_collide"]
assert state_tree_collision_report["primary_slot_probe"] == 0
assert state_tree_collision_report["collision_uses_nonzero_probe"]
assert state_tree_collision_report["assigned_indices_distinct"]
assert state_tree_collision_report["primary_path_verifies_before_collision_insert"]
assert state_tree_collision_report["primary_path_stale_after_collision_insert"]
assert state_tree_collision_report["primary_refreshed_path_verifies_after_collision_insert"]
assert state_tree_collision_report["colliding_path_verifies"]
assert state_tree_collision_report["duplicate_identity_rejected"]
assert state_tree_collision_report["active_leaf_count"] == 2
assert state_tree_collision_report["root_changes_on_primary_insert"]
assert state_tree_collision_report["root_changes_on_collision_insert"]
assert state_tree_collision_report["all_checks_hold"]

assert state_tree_empty_root != state_tree_root
assert state_tree_root == mp12_full_credential.root
assert state_tree.verify_path(
    b"UAV-STATE-001",
    mp12_full_credential.y_id,
    mp12_full_credential.path_proof,
    state_tree_root,
)
assert verify_verkle_path(
    b"UAV-STATE-001",
    mp12_full_credential.y_id,
    mp12_full_credential.path_proof,
    state_tree_root,
    state_tree_params,
)
assert not verify_verkle_path(
    b"UAV-STATE-001",
    state_tree_wrong_y,
    mp12_full_credential.path_proof,
    state_tree_root,
    state_tree_params,
)
assert state_tree_revoked_root != state_tree_root
assert not verify_verkle_path(
    b"UAV-STATE-001",
    mp12_full_credential.y_id,
    mp12_full_credential.path_proof,
    state_tree_revoked_root,
    state_tree_params,
)
assert verify_authentication(
    mp12_A,
    mp12_params,
    state_tree_params,
    b"UAV-STATE-001",
    mp12_full_credential.y_id,
    auth_nonce,
    state_tree_root,
    auth_transcript,
    auth_params,
)
assert not verify_authentication(
    mp12_A,
    mp12_params,
    state_tree_params,
    b"UAV-STATE-001",
    mp12_full_credential.y_id,
    wrong_auth_nonce,
    state_tree_root,
    auth_transcript,
    auth_params,
)
assert not verify_authentication(
    mp12_A,
    mp12_params,
    state_tree_params,
    b"UAV-STATE-001",
    mp12_full_credential.y_id,
    auth_nonce,
    state_tree_revoked_root,
    auth_transcript,
    auth_params,
)
assert not verify_authentication(
    mp12_A,
    mp12_params,
    state_tree_params,
    b"UAV-STATE-001",
    mp12_full_credential.y_id,
    auth_nonce,
    state_tree_root,
    tampered_auth_transcript,
    auth_params,
)
assert_raises(
    "expected odd challenge_modulus",
    lambda: AuthenticationParameters(
        challenge_modulus=16,
        sigma_mask=20,
        beta_response=5000,
    ),
)
scheme_setup = LVCVerkleSetupParameters(
    lattice_params=MP12GadgetParameters(n=2, q=97, base=2, m_bar=5),
    beta=220,
    sigma_pre=120,
    tree_params=VerkleTreeParameters(branching_factor=4, height=3),
    auth_params=AuthenticationParameters(
        challenge_modulus=17,
        sigma_mask=20,
        beta_response=5000,
    ),
    omega_factor=1,
)
scheme_pp, scheme_msk, scheme_state = setup_lvc_verkle(
    scheme_setup,
    [b"scheme-setup-1"],
)
scheme_initial_root = scheme_pp.root
scheme_setup_key_surface_report = setup_key_surface_report(
    scheme_pp,
    scheme_msk,
    scheme_state,
)
assert scheme_setup_key_surface_report["scope"] == "paper_setup_public_master_secret_surface"
assert scheme_setup_key_surface_report["paper_setup_output"] == (
    "pp = (A, beta, sigma, H1, H2, b, h, rt0), msk = T_A"
)
assert scheme_setup_key_surface_report["sage_setup_extensions"] == [
    "G",
    "q",
    "root",
    "root0",
    "tree_params",
    "auth_params",
    "lattice_params",
]
for public_field in [
    "A",
    "G",
    "H1",
    "H2",
    "auth_params",
    "b",
    "beta",
    "h",
    "lattice_params",
    "q",
    "root",
    "root0",
    "rt0",
    "sigma",
    "sigma_pre",
    "tree_params",
]:
    assert public_field in scheme_setup_key_surface_report["public_parameter_fields"]
assert scheme_setup_key_surface_report["public_parameter_sigma"] == (
    scheme_pp.auth_params.sigma_mask
)
assert scheme_setup_key_surface_report["public_parameter_sigma_matches_authentication_mask"]
assert "trapdoor" not in scheme_setup_key_surface_report["public_parameter_fields"]
assert scheme_setup_key_surface_report["master_secret_fields"] == ["trapdoor"]
assert scheme_setup_key_surface_report["public_parameter_matrix_A_dimensions"] == [
    scheme_pp.lattice_params.n,
    scheme_pp.lattice_params.m,
]
assert scheme_setup_key_surface_report["public_parameter_matrix_G_dimensions"] == [
    scheme_pp.lattice_params.n,
    scheme_pp.lattice_params.w,
]
assert scheme_setup_key_surface_report["public_parameter_contains_G"]
assert scheme_setup_key_surface_report["public_parameter_G_matches_gadget_matrix"]
assert scheme_setup_key_surface_report["public_parameter_q"] == scheme_pp.lattice_params.q
assert scheme_setup_key_surface_report["public_parameter_q_matches_lattice_parameters"]
assert scheme_pp.H1.name == "H1"
assert scheme_pp.H1.domain == H1_DOMAIN
assert scheme_pp.H1.output_spec == "Z_q^n"
assert scheme_pp.H1.active
assert scheme_pp.H2.name == "H2"
assert scheme_pp.H2.domain == H2_SCALAR_DOMAIN
assert scheme_pp.H2.output_spec == "C_lambda = {-B_c, ..., B_c}"
assert scheme_pp.H2.active
assert scheme_pp.b == scheme_pp.tree_params.branching_factor
assert scheme_pp.h == scheme_pp.tree_params.height
assert scheme_pp.root0 == scheme_initial_root
assert scheme_pp.rt0 == scheme_initial_root
assert scheme_setup_key_surface_report["public_parameter_H1_descriptor_matches"]
assert scheme_setup_key_surface_report["public_parameter_H2_descriptor_matches"]
assert scheme_setup_key_surface_report["public_parameter_tree_shape_aliases_match"]
assert scheme_setup_key_surface_report["public_parameter_root0_matches_setup_root"]
assert scheme_setup_key_surface_report["public_parameter_rt0_matches_setup_root"]
assert scheme_setup_key_surface_report["public_has_expected_fields"]
assert scheme_setup_key_surface_report["public_omits_trapdoor"]
assert scheme_setup_key_surface_report["master_secret_is_trapdoor_only"]
assert scheme_setup_key_surface_report["master_secret_contains_trapdoor"]
assert scheme_setup_key_surface_report["root_matches_state"]
assert scheme_setup_key_surface_report["all_checks_hold"]
scheme_credential, scheme_registered_root = register_lvc_verkle_by_identity(
    scheme_pp,
    scheme_msk,
    scheme_state,
    b"UAV-END-TO-END-001",
    [b"scheme-register-1"],
)
scheme_nonce_1 = b"A" * int(scheme_pp.auth_params.nonce_bytes)
scheme_nonce_2 = b"B" * int(scheme_pp.auth_params.nonce_bytes)
scheme_nonce_stale_root = b"D" * int(scheme_pp.auth_params.nonce_bytes)
assert scheme_credential.epoch == registration_epoch_for_identity(b"UAV-END-TO-END-001")
assert_raises(
    "expected rho length",
    lambda: issue_authentication_challenge(scheme_pp, b"short-rho"),
)
scheme_transcript = authenticate_lvc_verkle(
    scheme_pp,
    scheme_credential,
    b"UAV-END-TO-END-001",
    scheme_nonce_1,
    [b"scheme-auth-1"],
)

assert scheme_initial_root != scheme_registered_root
assert scheme_pp.root == scheme_registered_root
assert scheme_credential.root == scheme_registered_root
assert scheme_state.credentials_by_identity[b"UAV-END-TO-END-001"] == scheme_credential
assert scheme_state.credential_history_by_identity[b"UAV-END-TO-END-001"] == [
    scheme_credential
]
assert verify_lvc_verkle_at_root(
    scheme_pp,
    b"UAV-END-TO-END-001",
    scheme_credential.y_id,
    scheme_nonce_1,
    scheme_registered_root,
    scheme_transcript,
)
assert verify_lvc_verkle(
    LVCVerklePublicParameters(
        scheme_pp.A,
        scheme_pp.lattice_params,
        scheme_pp.beta,
        scheme_pp.sigma_pre,
        scheme_pp.tree_params,
        scheme_pp.auth_params,
        scheme_registered_root,
        omega_factor=scheme_pp.omega_factor,
    ),
    b"UAV-END-TO-END-001",
    scheme_credential.y_id,
    scheme_nonce_1,
    scheme_transcript,
)
scheme_second_credential, scheme_second_root = register_lvc_verkle_by_identity(
    scheme_pp,
    scheme_msk,
    scheme_state,
    b"UAV-END-TO-END-002",
    [b"scheme-register-2"],
)
assert scheme_second_credential.epoch == registration_epoch_for_identity(
    b"UAV-END-TO-END-002"
)
assert scheme_second_credential.epoch != scheme_credential.epoch
assert scheme_second_root != scheme_registered_root
assert scheme_second_credential.root == scheme_second_root
assert_raises(
    "credential path proof root is not current",
    lambda: authenticate_lvc_verkle(
        scheme_pp,
        scheme_credential,
        b"UAV-END-TO-END-001",
        scheme_nonce_stale_root,
        [b"scheme-auth-stale-credential"],
    ),
)
assert not verify_lvc_verkle(
    scheme_pp,
    b"UAV-END-TO-END-001",
    scheme_credential.y_id,
    scheme_nonce_1,
    scheme_transcript,
)
assert verify_lvc_verkle_at_root(
    scheme_pp,
    b"UAV-END-TO-END-001",
    scheme_credential.y_id,
    scheme_nonce_1,
    scheme_registered_root,
    scheme_transcript,
)
scheme_stale_verify_root_report = verification_root_parameterization_report(
    scheme_pp,
    scheme_state,
    b"UAV-END-TO-END-001",
    scheme_credential.y_id,
    AuthenticationChallenge(scheme_nonce_1, scheme_registered_root),
    scheme_transcript,
)
assert scheme_stale_verify_root_report["scope"] == "paper_verify_explicit_root_parameterization"
assert scheme_stale_verify_root_report["paper_verify_input"] == "Verify(pp,id,Y_id,rho,rt,tau)"
assert scheme_stale_verify_root_report["explicit_root_verify_accepts"]
assert not scheme_stale_verify_root_report["current_root_verify_accepts"]
assert not scheme_stale_verify_root_report["root_is_current"]
assert not scheme_stale_verify_root_report["paper_current_root_accepts"]
scheme_public_refresh = proof_refresh_service(
    scheme_pp,
    scheme_state,
    b"UAV-END-TO-END-001",
    scheme_credential.y_id,
)
assert scheme_public_refresh is not None
assert scheme_public_refresh.identity == b"UAV-END-TO-END-001"
assert scheme_public_refresh.y_id == scheme_credential.y_id
assert scheme_public_refresh.root == scheme_second_root
assert not hasattr(scheme_public_refresh, "z_id")
assert not hasattr(scheme_public_refresh, "credential")
assert verify_verkle_path(
    b"UAV-END-TO-END-001",
    scheme_credential.y_id,
    scheme_public_refresh.path_proof,
    scheme_second_root,
    scheme_pp.tree_params,
)
assert proof_refresh_service(
    scheme_pp,
    scheme_state,
    b"UAV-END-TO-END-001",
    _tamper_zq_vector_first_coordinate(scheme_credential.y_id),
) is None
scheme_credential = apply_proof_refresh_to_credential(
    scheme_pp,
    scheme_credential,
    scheme_public_refresh,
)
scheme_refreshed_challenge = issue_authentication_challenge(
    scheme_pp,
    scheme_nonce_2,
)
scheme_refreshed_challenge_report = authentication_challenge_report(
    scheme_pp,
    scheme_state,
    scheme_refreshed_challenge,
)
scheme_refreshed_transcript = authenticate_lvc_verkle_challenge(
    scheme_pp,
    scheme_credential,
    b"UAV-END-TO-END-001",
    scheme_refreshed_challenge,
    [b"scheme-auth-2"],
)
assert scheme_refreshed_challenge_report["scope"] == "authentication_challenge_binding"
assert scheme_refreshed_challenge_report["nonce"] == scheme_nonce_2
assert scheme_refreshed_challenge_report["root"] == scheme_second_root
assert scheme_refreshed_challenge_report["root_is_public_current"]
assert scheme_refreshed_challenge_report["root_is_state_current"]
assert scheme_refreshed_challenge_report["challenge_root_is_current"]
assert_raises(
    "authentication challenge root is not current",
    lambda: authenticate_lvc_verkle_challenge(
        scheme_pp,
        scheme_credential,
        b"UAV-END-TO-END-001",
        AuthenticationChallenge(scheme_nonce_stale_root, scheme_registered_root),
        [b"scheme-auth-stale-challenge-root"],
    ),
)
assert scheme_credential.root == scheme_second_root
assert scheme_pp.auth_params.contains_challenge(scheme_refreshed_transcript.challenge)
assert verify_lvc_verkle_challenge(
    scheme_pp,
    b"UAV-END-TO-END-001",
    scheme_credential.y_id,
    scheme_refreshed_challenge,
    scheme_refreshed_transcript,
)
scheme_refreshed_verify_root_report = verification_root_parameterization_report(
    scheme_pp,
    scheme_state,
    b"UAV-END-TO-END-001",
    scheme_credential.y_id,
    scheme_refreshed_challenge,
    scheme_refreshed_transcript,
)
assert scheme_refreshed_verify_root_report["root_is_current"]
assert scheme_refreshed_verify_root_report["explicit_root_verify_accepts"]
assert scheme_refreshed_verify_root_report["current_root_verify_accepts"]
assert scheme_refreshed_verify_root_report["paper_current_root_accepts"]
assert scheme_refreshed_verify_root_report["current_root_wrapper_matches_explicit_when_current"]
assert verify_lvc_verkle(
    scheme_pp,
    b"UAV-END-TO-END-001",
    scheme_credential.y_id,
    scheme_nonce_2,
    scheme_refreshed_transcript,
)
assert_raises(
    "credential identity does not match authentication identity",
    lambda: authenticate_lvc_verkle(
        scheme_pp,
        scheme_credential,
        b"UAV-END-TO-END-002",
        b"F" * int(scheme_pp.auth_params.nonce_bytes),
        [b"scheme-auth-wrong-identity"],
    ),
)
scheme_negative_verify_report = authentication_negative_verification_report(
    scheme_pp.A,
    scheme_pp.lattice_params,
    scheme_pp.tree_params,
    b"UAV-END-TO-END-001",
    scheme_credential.y_id,
    scheme_nonce_2,
    scheme_second_root,
    scheme_refreshed_transcript,
    scheme_pp.auth_params,
)
assert scheme_negative_verify_report["scope"] == "authentication_verify_negative_cases"
assert scheme_negative_verify_report["valid_transcript_verifies"]
assert scheme_negative_verify_report["rejects_wrong_nonce"]
assert scheme_negative_verify_report["rejects_tampered_root"]
assert scheme_negative_verify_report["rejects_tampered_y_id"]
assert scheme_negative_verify_report["rejects_tampered_commitment"]
assert scheme_negative_verify_report["rejects_tampered_challenge"]
assert scheme_negative_verify_report["rejects_tampered_response"]
assert scheme_negative_verify_report["wrong_nonce_challenge_mismatch"]
assert scheme_negative_verify_report["tampered_root_path_rejected"]
assert scheme_negative_verify_report["tampered_y_id_path_rejected"]
assert scheme_negative_verify_report["tampered_commitment_rejected_by_challenge_or_equation"]
assert (
    scheme_negative_verify_report["tampered_commitment_challenge_mismatch"]
    or scheme_negative_verify_report["tampered_commitment_equation_rejected"]
)
assert scheme_negative_verify_report["tampered_challenge_mismatch"]
assert scheme_negative_verify_report["tampered_response_equation_rejected"]
assert scheme_negative_verify_report["all_negative_checks_hold"]
scheme_malformed_path_transcript = AuthenticationTranscript(
    object(),
    scheme_refreshed_transcript.commitment,
    scheme_refreshed_transcript.challenge,
    scheme_refreshed_transcript.response,
    scheme_refreshed_transcript.audit_report,
)
assert not verify_lvc_verkle(
    scheme_pp,
    b"UAV-END-TO-END-001",
    scheme_credential.y_id,
    scheme_nonce_2,
    scheme_malformed_path_transcript,
)
assert identity_active_in_state(scheme_state, b"UAV-END-TO-END-001")
scheme_revoked_root = revoke_lvc_verkle(
    scheme_pp,
    scheme_msk,
    scheme_state,
    b"UAV-END-TO-END-001",
)
assert scheme_pp.root == scheme_revoked_root
assert scheme_revoked_root != scheme_second_root
assert b"UAV-END-TO-END-001" not in scheme_state.credentials_by_identity
assert scheme_state.credential_history_by_identity[b"UAV-END-TO-END-001"] == [
    scheme_credential
]
assert proof_refresh_service(
    scheme_pp,
    scheme_state,
    b"UAV-END-TO-END-001",
    scheme_credential.y_id,
) is None
assert not verify_lvc_verkle(
    scheme_pp,
    b"UAV-END-TO-END-001",
    scheme_credential.y_id,
    scheme_nonce_2,
    scheme_refreshed_transcript,
)
assert not identity_active_in_state(scheme_state, b"UAV-END-TO-END-001")
scheme_reregister_credential, scheme_reregister_root = register_lvc_verkle(
    scheme_pp,
    scheme_msk,
    scheme_state,
    b"UAV-END-TO-END-001",
    b"epoch-reregister-1",
    [b"scheme-reregister-after-revoke"],
)
assert scheme_reregister_root != scheme_revoked_root
assert scheme_pp.root == scheme_reregister_root
assert scheme_state.credentials_by_identity[b"UAV-END-TO-END-001"] == scheme_reregister_credential
assert scheme_state.credential_history_by_identity[b"UAV-END-TO-END-001"] == [
    scheme_credential,
    scheme_reregister_credential,
]
assert scheme_reregister_credential.epoch == b"epoch-reregister-1"
assert scheme_reregister_credential.y_id != scheme_credential.y_id
assert scheme_reregister_credential.path_proof.slot_probe > scheme_credential.path_proof.slot_probe
assert identity_active_in_state(scheme_state, b"UAV-END-TO-END-001")
scheme_reregister_challenge = issue_authentication_challenge(
    scheme_pp,
    b"E" * int(scheme_pp.auth_params.nonce_bytes),
)
scheme_reregister_transcript = authenticate_lvc_verkle_challenge(
    scheme_pp,
    scheme_reregister_credential,
    b"UAV-END-TO-END-001",
    scheme_reregister_challenge,
    [b"scheme-auth-reregistered"],
)
assert verify_lvc_verkle_challenge(
    scheme_pp,
    b"UAV-END-TO-END-001",
    scheme_reregister_credential.y_id,
    scheme_reregister_challenge,
    scheme_reregister_transcript,
)
assert not verify_lvc_verkle(
    scheme_pp,
    b"UAV-END-TO-END-001",
    scheme_credential.y_id,
    scheme_nonce_2,
    scheme_refreshed_transcript,
)
assert_raises(
    "identity is not registered",
    lambda: refresh_lvc_verkle_credential(
        scheme_pp,
        scheme_state,
        b"UAV-END-TO-END-404",
    ),
)
assert_raises(
    "identity already registered",
    lambda: register_lvc_verkle(
        scheme_pp,
        scheme_msk,
        scheme_state,
        b"UAV-END-TO-END-001",
        b"epoch-1",
        [b"scheme-register-dup"],
    ),
)
scheme_reregister_revoked_root = revoke_lvc_verkle(
    scheme_pp,
    scheme_msk,
    scheme_state,
    b"UAV-END-TO-END-001",
)
assert scheme_reregister_revoked_root != scheme_reregister_root
assert not identity_active_in_state(scheme_state, b"UAV-END-TO-END-001")
scheme_identity_only_reregister_credential, scheme_identity_only_reregister_root = (
    register_lvc_verkle_by_identity(
        scheme_pp,
        scheme_msk,
        scheme_state,
        b"UAV-END-TO-END-001",
        [b"scheme-identity-only-reregister-after-revoke"],
    )
)
assert scheme_identity_only_reregister_root != scheme_reregister_revoked_root
assert scheme_identity_only_reregister_credential.epoch == registration_epoch_for_identity(
    b"UAV-END-TO-END-001",
    2,
)
assert scheme_identity_only_reregister_credential.epoch != scheme_credential.epoch
assert scheme_identity_only_reregister_credential.epoch != scheme_reregister_credential.epoch
assert scheme_identity_only_reregister_credential.y_id != scheme_reregister_credential.y_id
assert scheme_state.credential_history_by_identity[b"UAV-END-TO-END-001"] == [
    scheme_credential,
    scheme_reregister_credential,
    scheme_identity_only_reregister_credential,
]
assert identity_active_in_state(scheme_state, b"UAV-END-TO-END-001")

api_scheme = LVCVerkleSchemeInstance.setup(
    scheme_setup,
    [b"scheme-object-setup-1"],
)
api_credential, api_root_1 = api_scheme.register(
    b"UAV-SCHEME-API-001",
    [b"scheme-object-register-1"],
)
assert api_scheme.pp.root == api_root_1
assert api_scheme.current_root() == api_root_1
assert api_scheme.msk.trapdoor is api_scheme.master_secret_key.trapdoor
assert api_scheme.is_active(b"UAV-SCHEME-API-001")
api_challenge_1 = api_scheme.issue_challenge(
    nonce=b"A" * int(api_scheme.pp.auth_params.nonce_bytes),
)
assert api_challenge_1.root == api_root_1
api_transcript_1 = api_scheme.authenticate(
    api_credential,
    b"UAV-SCHEME-API-001",
    api_challenge_1,
    [b"scheme-object-auth-1"],
)
assert api_scheme.verify(
    b"UAV-SCHEME-API-001",
    api_credential.y_id,
    api_challenge_1,
    api_transcript_1,
)
api_credential_2, api_root_2 = api_scheme.register(
    b"UAV-SCHEME-API-002",
    [b"scheme-object-register-2"],
)
assert api_credential_2.root == api_root_2
assert api_root_2 != api_root_1
assert not api_scheme.verify(
    b"UAV-SCHEME-API-001",
    api_credential.y_id,
    api_challenge_1.nonce,
    api_transcript_1,
)
assert api_scheme.verify_at_root(
    b"UAV-SCHEME-API-001",
    api_credential.y_id,
    api_challenge_1.nonce,
    api_root_1,
    api_transcript_1,
)
assert_raises(
    "credential path proof root is not current",
    lambda: api_scheme.authenticate(
        api_credential,
        b"UAV-SCHEME-API-001",
        api_scheme.issue_challenge(nonce=b"Y" * int(api_scheme.pp.auth_params.nonce_bytes)),
        [b"scheme-object-auth-stale-credential"],
    ),
)
api_credential = api_scheme.refresh_credential(b"UAV-SCHEME-API-001")
assert api_credential.root == api_root_2
api_challenge_2 = api_scheme.issue_challenge(
    seed_parts=[b"scheme-object-sampled-challenge-2"],
)
assert len(api_challenge_2.nonce) == int(api_scheme.pp.auth_params.nonce_bytes)
assert api_challenge_2.root == api_root_2
api_transcript_2 = api_scheme.authenticate(
    api_credential,
    b"UAV-SCHEME-API-001",
    api_challenge_2,
    [b"scheme-object-auth-2"],
)
assert api_scheme.verify(
    b"UAV-SCHEME-API-001",
    api_credential.y_id,
    api_challenge_2,
    api_transcript_2,
)
api_revoked_root = api_scheme.revoke(b"UAV-SCHEME-API-001")
assert api_revoked_root != api_root_2
assert api_scheme.current_root() == api_revoked_root
assert not api_scheme.is_active(b"UAV-SCHEME-API-001")
assert b"UAV-SCHEME-API-001" not in api_scheme.state.credentials_by_identity
assert api_scheme.state.credential_history_by_identity[b"UAV-SCHEME-API-001"] == [
    api_credential
]
assert not api_scheme.verify(
    b"UAV-SCHEME-API-001",
    api_credential.y_id,
    api_challenge_2.nonce,
    api_transcript_2,
)
assert_raises(
    "identity is not registered",
    lambda: api_scheme.refresh_credential(b"UAV-SCHEME-API-001"),
)
api_reregister_credential, api_reregister_root = api_scheme.register(
    b"UAV-SCHEME-API-001",
    [b"scheme-object-reregister-1"],
    epoch=b"scheme-object-epoch-reregister-1",
)
assert api_reregister_root != api_revoked_root
assert api_scheme.current_root() == api_reregister_root
assert api_scheme.is_active(b"UAV-SCHEME-API-001")
assert api_reregister_credential.y_id != api_credential.y_id
api_reregister_challenge = api_scheme.issue_challenge(
    nonce=b"Z" * int(api_scheme.pp.auth_params.nonce_bytes),
)
api_reregister_transcript = api_scheme.authenticate(
    api_reregister_credential,
    b"UAV-SCHEME-API-001",
    api_reregister_challenge,
    [b"scheme-object-auth-reregistered"],
)
assert api_scheme.verify(
    b"UAV-SCHEME-API-001",
    api_reregister_credential.y_id,
    api_reregister_challenge,
    api_reregister_transcript,
)
assert not api_scheme.verify(
    b"UAV-SCHEME-API-001",
    api_credential.y_id,
    api_challenge_2.nonce,
    api_transcript_2,
)
api_reregister_revoked_root = api_scheme.revoke(b"UAV-SCHEME-API-001")
assert api_reregister_revoked_root != api_reregister_root
api_identity_only_reregister, api_identity_only_root = api_scheme.register(
    b"UAV-SCHEME-API-001",
    [b"scheme-object-identity-only-reregister"],
)
assert api_identity_only_root != api_reregister_revoked_root
assert api_identity_only_reregister.epoch == registration_epoch_for_identity(
    b"UAV-SCHEME-API-001",
    2,
)
assert api_identity_only_reregister.epoch != api_credential.epoch
assert api_identity_only_reregister.epoch != api_reregister_credential.epoch

print("Sage state/auth/scheme tests passed.")
