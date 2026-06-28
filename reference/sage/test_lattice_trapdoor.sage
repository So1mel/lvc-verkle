load("reference/sage/lvc_lattice.sage")
load("reference/sage/test_helpers.sage")

mp12_params = MP12GadgetParameters(n=2, q=97, base=2, m_bar=5)
mp12_A, mp12_trapdoor = trap_gen_mp12(mp12_params, [b"mp12-experiment-1"])
mp12_A_via_dispatch, mp12_trapdoor_via_dispatch = trap_gen(
    mp12_params,
    [b"mp12-experiment-1"],
)
mp12_Rq = mp12_params.ring()
mp12_target = vector(mp12_Rq, [5, -1])
mp12_preimage = _sample_pre_mp12_canonical(
    mp12_A,
    mp12_trapdoor,
    mp12_target,
    mp12_params,
)
mp12_gpv = sample_pre_mp12_gpv_klein(
    mp12_A,
    mp12_trapdoor,
    mp12_target,
    mp12_params,
    sigma=40,
    seed_parts=[b"sample-pre-gpv-1"],
)
mp12_gpv_via_dispatch = sample_pre(
    mp12_A,
    mp12_trapdoor,
    mp12_target,
    mp12_params,
    sigma=40,
    seed_parts=[b"sample-pre-gpv-1"],
)
mp12_gpv_again = sample_pre_mp12_gpv_klein(
    mp12_A,
    mp12_trapdoor,
    mp12_target,
    mp12_params,
    sigma=40,
    seed_parts=[b"sample-pre-gpv-1"],
)
mp12_gpv_traced, mp12_gpv_trace = sample_pre_mp12_gpv_klein_with_trace(
    mp12_A,
    mp12_trapdoor,
    mp12_target,
    mp12_params,
    sigma=40,
    seed_parts=[b"sample-pre-gpv-1"],
)
mp12_gpv_coset_report = mp12_gpv_trace["coset_decomposition_report"]

trapdoor_relation_matrix = matrix(mp12_Rq, mp12_trapdoor.r).stack(
    identity_matrix(mp12_Rq, mp12_params.w)
)
mp12_gadget_basis = gadget_kernel_basis(mp12_params)
mp12_kernel = mp12_kernel_basis(mp12_trapdoor, mp12_params)
mp12_report = mp12_sample_pre_parameter_report(
    mp12_trapdoor,
    mp12_params,
    sigma=40,
    omega_factor=1,
)
mp12_trap_gen_report = mp12_trap_gen_parameter_report(
    mp12_A,
    mp12_trapdoor,
    mp12_params,
)
mp12_trap_gen_multi_seed_audit = trap_gen_multi_seed_audit(
    mp12_params,
    [b"mp12-trapgen-test"],
)
mp12_sample_pre_input_validation_audit = sample_pre_input_validation_audit(
    mp12_A,
    mp12_trapdoor,
    mp12_params,
    sigma=40,
    seed_parts=[b"sample-pre-input-validation-test"],
)
mp12_report_at_bound = mp12_sample_pre_parameter_report(
    mp12_trapdoor,
    mp12_params,
    sigma=mp12_report["recommended_sigma"],
    omega_factor=1,
)

assert mp12_params.k == 7
assert mp12_params.w == 14
assert mp12_params.m == 19
assert mp12_A_via_dispatch == mp12_A
assert mp12_trapdoor_via_dispatch.r == mp12_trapdoor.r
assert mp12_trapdoor_via_dispatch.gadget == mp12_trapdoor.gadget
assert mp12_trapdoor_via_dispatch.a_bar == mp12_trapdoor.a_bar
assert mp12_A.nrows() == mp12_params.n
assert mp12_A.ncols() == mp12_params.m
assert mp12_A[:, 0:mp12_params.m_bar] == mp12_trapdoor.a_bar
assert mp12_A[:, mp12_params.m_bar:mp12_params.m] == (
    mp12_trapdoor.gadget - mp12_trapdoor.a_bar * matrix(mp12_Rq, mp12_trapdoor.r)
)
assert mp12_A * trapdoor_relation_matrix == mp12_trapdoor.gadget
assert mp12_trapdoor.gadget * matrix(mp12_Rq, mp12_gadget_basis) == zero_matrix(
    mp12_Rq,
    mp12_params.n,
    mp12_params.w,
)
assert mp12_A * matrix(mp12_Rq, mp12_kernel) == zero_matrix(
    mp12_Rq,
    mp12_params.n,
    mp12_params.m,
)
assert mp12_A * mp12_preimage == mp12_target
assert mp12_A * mp12_gpv == mp12_target
assert mp12_gpv == mp12_gpv_again
assert mp12_gpv_traced == mp12_gpv
assert mp12_gpv_via_dispatch == mp12_gpv
assert mp12_gpv_trace["scope"] == "sample_pre_klein_coordinate_trace"
assert mp12_gpv_coset_report["scope"] == "sample_pre_gpv_coset_decomposition"
assert mp12_gpv_coset_report["canonical_equation_holds"]
assert mp12_gpv_coset_report["kernel_sample_relation_holds"]
assert mp12_gpv_coset_report["candidate_decomposition_holds"]
assert mp12_gpv_coset_report["candidate_equation_holds"]
assert mp12_gpv_coset_report["kernel_basis_full_rank"]
assert mp12_gpv_coset_report["kernel_basis_relation_holds"]
assert mp12_gpv_coset_report["all_checks_hold"]
assert mp12_gpv_coset_report["candidate_norm_squared"] == centered_norm_squared(
    mp12_gpv_traced,
    mp12_params.q,
)
assert mp12_gpv_trace["sampler_algorithm"] == "randomized_nearest_plane_klein"
assert mp12_gpv_trace["sampler_backend"] == "shake256_shifted_inverse_cdf_truncated_window"
assert mp12_gpv_trace["sampling_distribution_status"] == (
    "finite_window_truncated_shifted_discrete_gaussian_not_full_lattice_gaussian"
)
assert mp12_gpv_trace["coordinate_count"] == mp12_kernel.ncols()
assert mp12_gpv_trace["reported_coordinate_count"] == mp12_kernel.ncols()
assert not mp12_gpv_trace["report_truncated"]
assert mp12_gpv_trace["continuous_tail_heuristic_bound"] > 0
assert mp12_gpv_trace["finite_window_mass_heuristic_lower_bound"] < 1
assert mp12_gpv_trace["finite_window_mass_heuristic_lower_bound"] > 0
assert mp12_gpv_trace["min_coordinate_window_mass_heuristic_lower_bound"] == (
    mp12_gpv_trace["finite_window_mass_heuristic_lower_bound"]
)
assert mp12_gpv_trace["max_coordinate_tail_heuristic_bound"] == (
    mp12_gpv_trace["continuous_tail_heuristic_bound"]
)
assert mp12_gpv_trace["all_local_sigmas_positive"]
assert mp12_gpv_trace["all_centers_finite"]
assert mp12_gpv_trace["all_support_windows_finite"]
assert mp12_gpv_trace["all_coefficients_inside_windows"]
assert mp12_gpv_trace["all_window_mass_bounds_valid"]
assert mp12_gpv_trace["all_checks_hold"]
assert not mp12_gpv_trace["production_sampler_claim_permitted"]
assert not mp12_gpv_trace["statistical_distance_claim_permitted"]
assert len(mp12_gpv_trace["coordinate_samples"]) == mp12_kernel.ncols()
for coordinate_sample in mp12_gpv_trace["coordinate_samples"]:
    assert coordinate_sample["support_lower"] <= coordinate_sample["coefficient"]
    assert coordinate_sample["coefficient"] <= coordinate_sample["support_upper"]
    assert coordinate_sample["coefficient_inside_window"]
    assert coordinate_sample["continuous_tail_heuristic_bound"] == (
        mp12_gpv_trace["continuous_tail_heuristic_bound"]
    )
    assert coordinate_sample["finite_window_mass_heuristic_lower_bound"] == (
        mp12_gpv_trace["finite_window_mass_heuristic_lower_bound"]
    )
assert centered_norm_squared(mp12_gpv, mp12_params.q) >= 0
assert mp12_report["dimension"] == mp12_params.m
assert mp12_report["rank"] == mp12_params.m
assert mp12_report["gso_backend"] == "realfield_gram_schmidt_columns"
assert mp12_report["gso_real_precision_bits"] == 256
assert mp12_report["min_gso_norm"] > 0
assert mp12_report["max_gso_norm"] > 0
assert mp12_report["min_gso_norm"] <= mp12_report["max_gso_norm"]
assert mp12_report["min_local_sigma"] == mp12_report["sigma"] / mp12_report["max_gso_norm"]
assert mp12_report["max_local_sigma"] == mp12_report["sigma"] / mp12_report["min_gso_norm"]
assert mp12_report["recommended_sigma"] == mp12_report["max_gso_norm"]
assert mp12_report["sample_pre_sigma_formula"] == "sigma_pre >= max_gso_norm * omega_factor"
assert mp12_report["sample_pre_beta_formula"] == "beta >= sigma_pre * sqrt(m) * omega_factor"
mp12_report_rr = RealField(256)
assert mp12_report["recommended_beta"] == (
    mp12_report["sigma"] * sqrt(mp12_report_rr(mp12_report["dimension"])) * mp12_report["omega_factor"]
)
assert mp12_report["sigma_over_recommended"] == (
    mp12_report["sigma"] / mp12_report["recommended_sigma"]
)
assert mp12_report["passes_recommended_bound"] == (
    mp12_report["sigma"] >= mp12_report["recommended_sigma"]
)
assert mp12_report_at_bound["passes_recommended_bound"]
assert mp12_trap_gen_report["trapdoor_type"] == "mp12_g_trapdoor"
assert mp12_trap_gen_report["paper_trapgen_matrix_formula"] == (
    "A = [A_bar | G - A_bar * R]"
)
assert mp12_trap_gen_report["paper_trapdoor_relation"] == "A * [R; I] = G"
assert mp12_trap_gen_report["matrix_rows"] == mp12_params.n
assert mp12_trap_gen_report["matrix_columns"] == mp12_params.m
assert mp12_trap_gen_report["modulus"] == mp12_params.q
assert mp12_trap_gen_report["r_has_expected_shape"]
assert mp12_trap_gen_report["r_entries_are_ternary"]
assert mp12_trap_gen_report["r_entry_set"] == [-1, 0, 1]
assert mp12_trap_gen_report["r_entry_count"] == mp12_params.m_bar * mp12_params.w
assert mp12_trap_gen_report["r_nonzero_count"] > 0
assert mp12_trap_gen_report["r_frobenius_norm_squared"] == (
    mp12_trap_gen_report["r_nonzero_count"]
)
assert mp12_trap_gen_report["r_infinity_norm"] <= 1
assert mp12_trap_gen_report["r_density"] > 0
assert mp12_trap_gen_report["r_shortness_model"] == (
    "ternary_g_trapdoor_R_entries_in_{-1,0,1}"
)
assert mp12_trap_gen_report["trapdoor_distribution_status"] == (
    "seeded_reproducible_reference_not_production_distribution_proof"
)
assert not mp12_trap_gen_report["a_bar_uniformity_claim_permitted"]
assert not mp12_trap_gen_report["r_distribution_claim_permitted"]
assert not mp12_trap_gen_report["production_trapgen_claim_permitted"]
assert mp12_trap_gen_report["trapdoor_quality_checks_hold"]
assert mp12_trap_gen_report["a_bar_relation_holds"]
assert mp12_trap_gen_report["tail_relation_holds"]
assert mp12_trap_gen_report["trapdoor_relation_holds"]
assert mp12_trap_gen_report["gadget_kernel_relation_holds"]
mp12_gadget_audit = mp12_trap_gen_report["gadget_decomposition_audit"]
assert mp12_gadget_audit["scope"] == (
    "mp12_gadget_decomposition_and_canonical_preimage"
)
assert mp12_gadget_audit["sample_count"] == 4
assert mp12_gadget_audit["all_digit_bounds_hold"]
assert mp12_gadget_audit["all_gadget_equations_hold"]
assert mp12_gadget_audit["all_canonical_preimage_equations_hold"]
assert mp12_gadget_audit["all_checks_hold"]
for gadget_sample in mp12_gadget_audit["samples"]:
    assert gadget_sample["digit_count"] == gadget_sample["expected_digit_count"]
    assert gadget_sample["digit_bounds_hold"]
    assert gadget_sample["gadget_equation_holds"]
    assert gadget_sample["canonical_preimage_equation_holds"]
assert mp12_trap_gen_report["kernel_basis_full_rank"]
assert mp12_trap_gen_report["kernel_basis_relation_holds"]
assert mp12_trap_gen_multi_seed_audit["scope"] == "trap_gen_multi_seed_reproducibility"
assert mp12_trap_gen_multi_seed_audit["trapdoor_type"] == "mp12_g_trapdoor"
assert mp12_trap_gen_multi_seed_audit["sample_count"] == 3
assert mp12_trap_gen_multi_seed_audit["unique_instance_count"] >= 2
assert mp12_trap_gen_multi_seed_audit["same_seed_reproducible"]
assert mp12_trap_gen_multi_seed_audit["different_seed_distinct"]
assert mp12_trap_gen_multi_seed_audit["all_relations_hold"]
assert mp12_trap_gen_multi_seed_audit["all_quality_checks_hold"]
assert mp12_trap_gen_multi_seed_audit["all_checks_hold"]
for trap_gen_sample in mp12_trap_gen_multi_seed_audit["samples"]:
    assert trap_gen_sample["a_bar_relation_holds"]
    assert trap_gen_sample["tail_relation_holds"]
    assert trap_gen_sample["trapdoor_relation_holds"]
    assert trap_gen_sample["gadget_decomposition_audit_all_checks_hold"]
    assert trap_gen_sample["kernel_basis_relation_holds"]
    assert trap_gen_sample["trapdoor_quality_checks_hold"]
    assert trap_gen_sample["r_entries_are_ternary"]
    assert not trap_gen_sample["a_bar_uniformity_claim_permitted"]
    assert not trap_gen_sample["r_distribution_claim_permitted"]
    assert not trap_gen_sample["production_trapgen_claim_permitted"]
assert mp12_sample_pre_input_validation_audit["scope"] == (
    "sample_pre_public_entrypoint_input_validation"
)
assert mp12_sample_pre_input_validation_audit["sampler_algorithm"] == (
    "sample_pre_mp12_gpv_klein"
)
assert mp12_sample_pre_input_validation_audit["rejection_case_count"] == 12
assert mp12_sample_pre_input_validation_audit["all_rejection_cases_hold"]
assert mp12_sample_pre_input_validation_audit["valid_case_holds"]
assert mp12_sample_pre_input_validation_audit["all_checks_hold"]
sample_pre_rejection_names = [
    case["name"]
    for case in mp12_sample_pre_input_validation_audit["rejection_cases"]
]
assert sample_pre_rejection_names == [
    "missing_sigma",
    "missing_seed_parts",
    "target_dimension_mismatch",
    "target_modulus_mismatch",
    "matrix_dimension_mismatch",
    "trapdoor_r_ring_mismatch",
    "trapdoor_r_dimension_mismatch",
    "trapdoor_r_entries_not_ternary",
    "trapdoor_gadget_mismatch",
    "trapdoor_a_bar_modulus_mismatch",
    "trapdoor_a_bar_dimension_mismatch",
    "matrix_trapdoor_relation_mismatch",
]
for rejection_case in mp12_sample_pre_input_validation_audit["rejection_cases"]:
    assert rejection_case["rejected"]
    assert rejection_case["expected_error_substring"] in rejection_case["error"]
assert mp12_sample_pre_input_validation_audit["valid_case"]["accepted"]
assert mp12_sample_pre_input_validation_audit["valid_case"]["equation_holds"]
assert mp12_sample_pre_input_validation_audit["valid_case"]["output_dimension"] == (
    mp12_params.m
)

mp12_register_h1 = h1_to_zq_vector([b"UAV-001", b"epoch-1"], mp12_params.n, mp12_params.q)
mp12_credential = register_lattice_credential(
    mp12_A,
    mp12_trapdoor,
    mp12_params,
    b"UAV-001",
    b"epoch-1",
    sigma=120,
    beta=140,
    seed_parts=[b"register-1"],
    omega_factor=1,
)
mp12_credential_again = register_lattice_credential(
    mp12_A,
    mp12_trapdoor,
    mp12_params,
    b"UAV-001",
    b"epoch-1",
    sigma=120,
    beta=140,
    seed_parts=[b"register-1"],
    omega_factor=1,
)
mp12_credential_different = register_lattice_credential(
    mp12_A,
    mp12_trapdoor,
    mp12_params,
    b"UAV-001",
    b"epoch-1",
    sigma=120,
    beta=140,
    seed_parts=[b"register-2"],
    omega_factor=1,
)

assert mp12_register_h1 == mp12_credential.y_id
assert mp12_A * mp12_credential.z_id == mp12_credential.y_id
assert mp12_credential.norm_squared <= mp12_credential.beta * mp12_credential.beta
assert mp12_credential.parameter_report["passes_recommended_bound"]
assert mp12_credential.sample_pre_report["sampler_algorithm"] == "sample_pre_mp12_gpv_klein"
assert mp12_credential.sample_pre_report["paper_algorithm"] == "SamplePre(A,T_A,Y_id)->z_id"
assert mp12_credential.sample_pre_report["paper_register_target_relation"] == (
    "Y_id = H1(id || epoch)"
)
assert mp12_credential.sample_pre_report["paper_sample_pre_equation"] == (
    "A*z_id = Y_id mod q"
)
assert mp12_credential.sample_pre_report["paper_sample_pre_norm_bound"] == (
    "||z_id||_2 <= beta"
)
assert mp12_credential.sample_pre_report["target_module"] == "Z_q^n"
assert mp12_credential.sample_pre_report["output_module"] == "Z_q^m"
assert mp12_credential.sample_pre_report["matrix_rows"] == mp12_params.n
assert mp12_credential.sample_pre_report["matrix_columns"] == mp12_params.m
assert mp12_credential.sample_pre_report["modulus"] == mp12_params.q
assert mp12_credential.sample_pre_report["matrix_dimension_holds"]
assert mp12_credential.sample_pre_report["matrix_base_ring_matches_zq"]
assert mp12_credential.sample_pre_report["target_dimension_matches_n"]
assert mp12_credential.sample_pre_report["target_base_ring_matches_zq"]
assert mp12_credential.sample_pre_report["target_coordinates_in_zq"]
assert mp12_credential.sample_pre_report["output_dimension_matches_m"]
assert mp12_credential.sample_pre_report["output_base_ring_matches_zq"]
assert mp12_credential.sample_pre_report["output_coordinates_in_zq"]
assert mp12_credential.sample_pre_report["sampling_distribution_status"] == (
    "finite_window_truncated_shifted_discrete_gaussian_not_full_lattice_gaussian"
)
assert mp12_credential.sample_pre_report["sampler_backend"] == "shake256_inverse_cdf_truncated_window"
assert mp12_credential.sample_pre_report["sampler_real_precision_bits"] == 256
assert mp12_credential.sample_pre_report["sampler_draw_bits"] == 256
assert mp12_credential.sample_pre_report["tail_cutoff"] == 12
assert mp12_credential.sample_pre_report["continuous_tail_heuristic_bound"] > 0
assert mp12_credential.sample_pre_report[
    "trace_continuous_tail_heuristic_bound"
] == mp12_credential.sample_pre_report["sampler_trace_report"][
    "continuous_tail_heuristic_bound"
]
assert mp12_credential.sample_pre_report[
    "finite_window_mass_heuristic_lower_bound"
] == mp12_credential.sample_pre_report["sampler_trace_report"][
    "finite_window_mass_heuristic_lower_bound"
]
assert not mp12_credential.sample_pre_report[
    "statistical_distance_claim_permitted"
]
assert mp12_credential.sample_pre_report["gso_backend"] == "realfield_gram_schmidt_columns"
assert mp12_credential.sample_pre_report["gso_real_precision_bits"] == 256
assert mp12_credential.sample_pre_report["sampler_trace_all_checks_hold"]
assert mp12_credential.sample_pre_report["sampler_trace_report"]["coordinate_count"] == (
    mp12_kernel.ncols()
)
credential_coset_report = mp12_credential.sample_pre_report[
    "sampler_trace_report"
]["coset_decomposition_report"]
assert credential_coset_report["scope"] == "sample_pre_gpv_coset_decomposition"
assert credential_coset_report["canonical_equation_holds"]
assert credential_coset_report["kernel_sample_relation_holds"]
assert credential_coset_report["candidate_decomposition_holds"]
assert credential_coset_report["candidate_equation_holds"]
assert credential_coset_report["kernel_basis_full_rank"]
assert credential_coset_report["kernel_basis_relation_holds"]
assert credential_coset_report["all_checks_hold"]
assert credential_coset_report["candidate_norm_squared"] == (
    mp12_credential.sample_pre_report["norm_squared"]
)
assert not mp12_credential.sample_pre_report["sampler_trace_report"][
    "production_sampler_claim_permitted"
]
assert mp12_credential.sample_pre_report["recommended_beta"] == (
    mp12_credential.parameter_report["recommended_beta"]
)
assert mp12_credential.sample_pre_report["beta_over_recommended"] == (
    mp12_credential.sample_pre_report["beta"] / mp12_credential.sample_pre_report["recommended_beta"]
)
assert not mp12_credential.sample_pre_report["paper_beta_bound_holds"]
assert mp12_credential.sample_pre_report["equation_holds"]
assert mp12_credential.sample_pre_report["norm_bound_holds"]
assert mp12_credential.sample_pre_report["all_algorithmic_checks_hold"]
assert mp12_credential.sample_pre_report["parameter_bound_holds"]
assert mp12_credential.sample_pre_report["norm_squared"] == mp12_credential.norm_squared
assert mp12_credential.sample_pre_report["beta"] == mp12_credential.beta
assert mp12_credential.sample_pre_report["sigma_over_recommended"] == (
    mp12_credential.parameter_report["sigma_over_recommended"]
)
assert mp12_credential.z_id == mp12_credential_again.z_id
assert mp12_credential.y_id == mp12_credential_again.y_id
assert mp12_credential_different.z_id != mp12_credential.z_id
assert_raises(
    "credential norm exceeds beta",
    lambda: register_lattice_credential(
        mp12_A,
        mp12_trapdoor,
        mp12_params,
        b"UAV-001",
        b"epoch-1",
        sigma=120,
        beta=100,
        seed_parts=[b"register-1"],
        omega_factor=1,
    ),
)
assert_raises(
    "sigma below recommended SamplePre bound",
    lambda: register_lattice_credential(
        mp12_A,
        mp12_trapdoor,
        mp12_params,
        b"UAV-001",
        b"epoch-1",
        sigma=40,
        beta=140,
        seed_parts=[b"register-1"],
        omega_factor=1,
    ),
)
assert_raises(
    "MP12 SamplePre requires sigma",
    lambda: sample_pre(mp12_A, mp12_trapdoor, mp12_target, mp12_params),
)

mp12_gadget_solution = gadget_decompose(mp12_target, mp12_params)
assert mp12_trapdoor.gadget * mp12_gadget_solution == mp12_target
assert mp12_preimage[0:mp12_params.m_bar] == matrix(mp12_Rq, mp12_trapdoor.r) * mp12_gadget_solution
assert mp12_preimage[mp12_params.m_bar:mp12_params.m] == mp12_gadget_solution

mp12_A_again, mp12_trapdoor_again = trap_gen_mp12(mp12_params, [b"mp12-experiment-1"])
mp12_A_different, mp12_trapdoor_different = trap_gen_mp12(mp12_params, [b"mp12-experiment-2"])

assert mp12_A_again == mp12_A
assert mp12_trapdoor_again.r == mp12_trapdoor.r
assert mp12_A_different != mp12_A or mp12_trapdoor_different.r != mp12_trapdoor.r

print("Sage lattice/trapdoor tests passed.")
