import json
import os
import sys
from hashlib import sha256
from numbers import Real


load("reference/sage/lvc_lattice.sage")


EXPERIMENT_CONFIG_FORMAT = "lvc_verkle_experiment_config_v1"
EXPERIMENT_CONFIG_SCHEMA_PATH = "reference/configs/schemas/experiment_config.schema.json"
EXPERIMENT_TOP_LEVEL_KEYS = set([
    "format",
    "name",
    "description",
    "lattice",
    "sample_pre",
    "tree",
    "authentication",
])
LATTICE_CONFIG_KEYS = set(["n", "q", "base", "m_bar"])
SAMPLE_PRE_CONFIG_KEYS = set(["beta", "sigma_pre", "omega_factor", "tail_cutoff"])
TREE_CONFIG_KEYS = set(["branching_factor", "height"])
AUTHENTICATION_CONFIG_KEYS = set([
    "challenge_modulus",
    "sigma_mask",
    "omega_factor",
    "beta_response",
    "max_attempts",
    "nonce_bytes",
    "mask_tail_cutoff",
])


def _bytes_hex(value):
    return value.hex()


def _seed_report(seed_parts):
    return [_bytes_hex(_as_bytes(seed)) for seed in seed_parts]


def _zq_vector_report(vector_value, modulus):
    return {
        "dimension": int(len(vector_value)),
        "values": [int(ZZ(value)) for value in vector_value],
        "centered_values": [int(value) for value in centered_vector(vector_value, modulus)],
        "centered_norm_squared": int(centered_norm_squared(vector_value, modulus)),
    }


def _zz_vector_norm_squared(vector_value):
    return sum(value * value for value in vector_value)


def _integer_vector_report(vector_value):
    return {
        "dimension": int(len(vector_value)),
        "values": [int(value) for value in vector_value],
        "norm_squared": int(_zz_vector_norm_squared(vector_value)),
    }


def _parameter_report(report):
    return {
        "dimension": int(report["dimension"]),
        "rank": int(report["rank"]),
        "basis_columns": int(report["basis_columns"]),
        "gso_backend": report["gso_backend"],
        "gso_real_precision_bits": int(report["gso_real_precision_bits"]),
        "min_gso_norm": float(report["min_gso_norm"]),
        "max_gso_norm": float(report["max_gso_norm"]),
        "min_local_sigma": float(report["min_local_sigma"]),
        "max_local_sigma": float(report["max_local_sigma"]),
        "omega_factor": float(report["omega_factor"]),
        "recommended_sigma": float(report["recommended_sigma"]),
        "recommended_beta": float(report["recommended_beta"]),
        "sample_pre_sigma_formula": report["sample_pre_sigma_formula"],
        "sample_pre_beta_formula": report["sample_pre_beta_formula"],
        "sigma": float(report["sigma"]),
        "sigma_over_recommended": float(report["sigma_over_recommended"]),
        "passes_recommended_bound": bool(report["passes_recommended_bound"]),
        "sample_pre_context_backend": report.get("sample_pre_context_backend"),
    }


def _sample_pre_sampler_trace_report(report):
    if report is None:
        return None

    coset_report = report.get("coset_decomposition_report")
    return {
        "scope": report["scope"],
        "sampler_algorithm": report["sampler_algorithm"],
        "sampler_backend": report["sampler_backend"],
        "gso_backend": report.get("gso_backend"),
        "sampling_distribution_status": report["sampling_distribution_status"],
        "coordinate_count": int(report["coordinate_count"]),
        "reported_coordinate_count": int(report["reported_coordinate_count"]),
        "report_truncated": bool(report["report_truncated"]),
        "sigma": float(report["sigma"]),
        "tail_cutoff": int(report["tail_cutoff"]),
        "continuous_tail_heuristic_bound": float(
            report["continuous_tail_heuristic_bound"]
        ),
        "finite_window_mass_heuristic_lower_bound": float(
            report["finite_window_mass_heuristic_lower_bound"]
        ),
        "min_coordinate_window_mass_heuristic_lower_bound": float(
            report["min_coordinate_window_mass_heuristic_lower_bound"]
        ),
        "max_coordinate_tail_heuristic_bound": float(
            report["max_coordinate_tail_heuristic_bound"]
        ),
        "sampler_real_precision_bits": int(report["sampler_real_precision_bits"]),
        "sampler_draw_bits": int(report["sampler_draw_bits"]),
        "min_local_sigma": float(report["min_local_sigma"]),
        "max_local_sigma": float(report["max_local_sigma"]),
        "min_support_size": int(report["min_support_size"]),
        "max_support_size": int(report["max_support_size"]),
        "all_local_sigmas_positive": bool(report["all_local_sigmas_positive"]),
        "all_centers_finite": bool(report["all_centers_finite"]),
        "all_support_windows_finite": bool(report["all_support_windows_finite"]),
        "all_coefficients_inside_windows": bool(
            report["all_coefficients_inside_windows"]
        ),
        "all_window_mass_bounds_valid": bool(report["all_window_mass_bounds_valid"]),
        "coordinate_samples": [
            {
                "basis_index": int(sample["basis_index"]),
                "sampling_order": int(sample["sampling_order"]),
                "gso_norm_squared": float(sample["gso_norm_squared"]),
                "gso_norm": float(sample["gso_norm"]),
                "local_sigma": float(sample["local_sigma"]),
                "coordinate_center": float(sample["coordinate_center"]),
                "support_lower": int(sample["support_lower"]),
                "support_upper": int(sample["support_upper"]),
                "support_size": int(sample["support_size"]),
                "continuous_tail_heuristic_bound": float(
                    sample["continuous_tail_heuristic_bound"]
                ),
                "finite_window_mass_heuristic_lower_bound": float(
                    sample["finite_window_mass_heuristic_lower_bound"]
                ),
                "coefficient": int(sample["coefficient"]),
                "coefficient_inside_window": bool(sample["coefficient_inside_window"]),
            }
            for sample in report["coordinate_samples"]
        ],
        "all_checks_hold": bool(report["all_checks_hold"]),
        "coset_decomposition_report": (
            None
            if coset_report is None
            else {
                "scope": coset_report["scope"],
                "paper_statement": coset_report["paper_statement"],
                "canonical_preimage_equation": coset_report[
                    "canonical_preimage_equation"
                ],
                "kernel_sample_equation": coset_report["kernel_sample_equation"],
                "candidate_decomposition": coset_report["candidate_decomposition"],
                "decomposition_relation_model": coset_report[
                    "decomposition_relation_model"
                ],
                "target_dimension": int(coset_report["target_dimension"]),
                "output_dimension": int(coset_report["output_dimension"]),
                "kernel_basis_rows": int(coset_report["kernel_basis_rows"]),
                "kernel_basis_columns": int(coset_report["kernel_basis_columns"]),
                "kernel_basis_rank": int(coset_report["kernel_basis_rank"]),
                "kernel_basis_full_rank": bool(
                    coset_report["kernel_basis_full_rank"]
                ),
                "kernel_basis_relation_holds": bool(
                    coset_report["kernel_basis_relation_holds"]
                ),
                "canonical_norm_squared": int(
                    coset_report["canonical_norm_squared"]
                ),
                "kernel_sample_norm_squared": int(
                    coset_report["kernel_sample_norm_squared"]
                ),
                "candidate_norm_squared": int(
                    coset_report["candidate_norm_squared"]
                ),
                "canonical_equation_holds": bool(
                    coset_report["canonical_equation_holds"]
                ),
                "kernel_sample_relation_holds": bool(
                    coset_report["kernel_sample_relation_holds"]
                ),
                "candidate_decomposition_holds": bool(
                    coset_report["candidate_decomposition_holds"]
                ),
                "centered_representative_decomposition_holds": bool(
                    coset_report["centered_representative_decomposition_holds"]
                ),
                "candidate_equation_holds": bool(
                    coset_report["candidate_equation_holds"]
                ),
                "all_checks_hold": bool(coset_report["all_checks_hold"]),
                "caveat": coset_report["caveat"],
            }
        ),
        "caveat": report["caveat"],
    }


def _sample_pre_output_report(report):
    return {
        "paper_algorithm": report["paper_algorithm"],
        "paper_register_target_relation": report["paper_register_target_relation"],
        "paper_sample_pre_equation": report["paper_sample_pre_equation"],
        "paper_sample_pre_norm_bound": report["paper_sample_pre_norm_bound"],
        "target_module": report["target_module"],
        "output_module": report["output_module"],
        "matrix_rows": int(report["matrix_rows"]),
        "matrix_columns": int(report["matrix_columns"]),
        "modulus": int(report["modulus"]),
        "matrix_dimension_holds": bool(report["matrix_dimension_holds"]),
        "matrix_base_ring_matches_zq": bool(report["matrix_base_ring_matches_zq"]),
        "target_dimension_matches_n": bool(report["target_dimension_matches_n"]),
        "target_base_ring_matches_zq": bool(report["target_base_ring_matches_zq"]),
        "target_coordinates_in_zq": bool(report["target_coordinates_in_zq"]),
        "output_dimension_matches_m": bool(report["output_dimension_matches_m"]),
        "output_base_ring_matches_zq": bool(report["output_base_ring_matches_zq"]),
        "output_coordinates_in_zq": bool(report["output_coordinates_in_zq"]),
        "sampler_algorithm": report["sampler_algorithm"],
        "sampling_distribution_status": report["sampling_distribution_status"],
        "discrete_gaussian": report["discrete_gaussian"],
        "sampler_backend": report["sampler_backend"],
        "sampler_real_precision_bits": int(report["sampler_real_precision_bits"]),
        "sampler_draw_bits": int(report["sampler_draw_bits"]),
        "tail_cutoff": int(report["tail_cutoff"]),
        "continuous_tail_heuristic_bound": float(report["continuous_tail_heuristic_bound"]),
        "trace_continuous_tail_heuristic_bound": (
            None
            if report["trace_continuous_tail_heuristic_bound"] is None
            else float(report["trace_continuous_tail_heuristic_bound"])
        ),
        "finite_window_mass_heuristic_lower_bound": (
            None
            if report["finite_window_mass_heuristic_lower_bound"] is None
            else float(report["finite_window_mass_heuristic_lower_bound"])
        ),
        "gso_backend": report["gso_backend"],
        "gso_real_precision_bits": int(report["gso_real_precision_bits"]),
        "target_dimension": int(report["target_dimension"]),
        "output_dimension": int(report["output_dimension"]),
        "sigma": float(report["sigma"]),
        "recommended_sigma": float(report["recommended_sigma"]),
        "recommended_beta": float(report["recommended_beta"]),
        "sigma_over_recommended": float(report["sigma_over_recommended"]),
        "beta_over_recommended": float(report["beta_over_recommended"]),
        "min_gso_norm": float(report["min_gso_norm"]),
        "max_gso_norm": float(report["max_gso_norm"]),
        "min_local_sigma": float(report["min_local_sigma"]),
        "max_local_sigma": float(report["max_local_sigma"]),
        "parameter_bound_holds": bool(report["parameter_bound_holds"]),
        "paper_beta_bound_holds": bool(report["paper_beta_bound_holds"]),
        "sample_pre_sigma_formula": report["sample_pre_sigma_formula"],
        "sample_pre_beta_formula": report["sample_pre_beta_formula"],
        "sampler_trace_report": _sample_pre_sampler_trace_report(
            report["sampler_trace_report"]
        ),
        "sampler_trace_all_checks_hold": (
            None
            if report["sampler_trace_all_checks_hold"] is None
            else bool(report["sampler_trace_all_checks_hold"])
        ),
        "equation_holds": bool(report["equation_holds"]),
        "norm_squared": int(report["norm_squared"]),
        "beta": int(report["beta"]),
        "norm_bound_holds": bool(report["norm_bound_holds"]),
        "all_algorithmic_checks_hold": bool(
            report["all_algorithmic_checks_hold"]
        ),
        "distribution_audit_caveat": report["distribution_audit_caveat"],
    }


def _sample_pre_diversity_audit_report(report):
    return {
        "scope": report["scope"],
        "paper_statement": report["paper_statement"],
        "sampler_algorithm": report["sampler_algorithm"],
        "discrete_gaussian": report["discrete_gaussian"],
        "sample_count": int(report["sample_count"]),
        "target_dimension": int(report["target_dimension"]),
        "output_dimension": int(report["output_dimension"]),
        "same_target_for_all_samples": bool(report["same_target_for_all_samples"]),
        "parameter_bound_holds": bool(report["parameter_bound_holds"]),
        "all_equations_hold": bool(report["all_equations_hold"]),
        "all_norm_bounds_hold": bool(report["all_norm_bounds_hold"]),
        "unique_output_count": int(report["unique_output_count"]),
        "produces_distinct_preimages": bool(report["produces_distinct_preimages"]),
        "deterministic_reproducibility_checked": bool(
            report["deterministic_reproducibility_checked"]
        ),
        "samples": [
            {
                "index": int(sample["index"]),
                "seed_label": sample["seed_label"],
                "equation_holds": bool(sample["equation_holds"]),
                "norm_squared": int(sample["norm_squared"]),
                "norm_bound_holds": bool(sample["norm_bound_holds"]),
            }
            for sample in report["samples"]
        ],
        "all_checks_hold": bool(report["all_checks_hold"]),
        "caveat": report["caveat"],
    }


def _sample_pre_input_validation_audit_report(report):
    return {
        "scope": report["scope"],
        "paper_statement": report["paper_statement"],
        "sampler_algorithm": report["sampler_algorithm"],
        "rejection_case_count": int(report["rejection_case_count"]),
        "rejection_cases": [
            {
                "name": rejection_case["name"],
                "rejected": bool(rejection_case["rejected"]),
                "expected_error_substring": rejection_case[
                    "expected_error_substring"
                ],
                "error": rejection_case["error"],
            }
            for rejection_case in report["rejection_cases"]
        ],
        "valid_case": {
            "name": report["valid_case"]["name"],
            "accepted": bool(report["valid_case"]["accepted"]),
            "equation_holds": bool(report["valid_case"]["equation_holds"]),
            "output_dimension": int(report["valid_case"]["output_dimension"]),
            "expected_output_dimension": int(
                report["valid_case"]["expected_output_dimension"]
            ),
        },
        "all_rejection_cases_hold": bool(report["all_rejection_cases_hold"]),
        "valid_case_holds": bool(report["valid_case_holds"]),
        "all_checks_hold": bool(report["all_checks_hold"]),
        "caveat": report["caveat"],
    }


def _trap_gen_parameter_report(report):
    return {
        "trapdoor_type": report["trapdoor_type"],
        "paper_trapgen_matrix_formula": report["paper_trapgen_matrix_formula"],
        "paper_trapdoor_relation": report["paper_trapdoor_relation"],
        "matrix_rows": int(report["matrix_rows"]),
        "matrix_columns": int(report["matrix_columns"]),
        "modulus": int(report["modulus"]),
        "m_bar": int(report["m_bar"]),
        "gadget_width": int(report["gadget_width"]),
        "gadget_base": int(report["gadget_base"]),
        "gadget_digits": int(report["gadget_digits"]),
        "r_rows": int(report["r_rows"]),
        "r_columns": int(report["r_columns"]),
        "r_entry_set": [int(entry) for entry in report["r_entry_set"]],
        "r_entries_are_ternary": bool(report["r_entries_are_ternary"]),
        "r_has_expected_shape": bool(report["r_has_expected_shape"]),
        "r_nonzero_count": int(report["r_nonzero_count"]),
        "r_entry_count": int(report["r_entry_count"]),
        "r_density": float(report["r_density"]),
        "r_frobenius_norm_squared": int(report["r_frobenius_norm_squared"]),
        "r_infinity_norm": int(report["r_infinity_norm"]),
        "r_max_row_norm_squared": int(report["r_max_row_norm_squared"]),
        "r_max_column_norm_squared": int(report["r_max_column_norm_squared"]),
        "r_shortness_model": report["r_shortness_model"],
        "a_bar_sampling_model": report["a_bar_sampling_model"],
        "r_sampling_model": report["r_sampling_model"],
        "trapdoor_distribution_status": report["trapdoor_distribution_status"],
        "a_bar_uniformity_claim_permitted": bool(
            report["a_bar_uniformity_claim_permitted"]
        ),
        "r_distribution_claim_permitted": bool(
            report["r_distribution_claim_permitted"]
        ),
        "production_trapgen_claim_permitted": bool(
            report["production_trapgen_claim_permitted"]
        ),
        "a_bar_relation_holds": bool(report["a_bar_relation_holds"]),
        "tail_relation_holds": bool(report["tail_relation_holds"]),
        "trapdoor_relation_holds": bool(report["trapdoor_relation_holds"]),
        "gadget_kernel_relation_holds": bool(report["gadget_kernel_relation_holds"]),
        "gadget_decomposition_audit": {
            "scope": report["gadget_decomposition_audit"]["scope"],
            "paper_statement": report["gadget_decomposition_audit"][
                "paper_statement"
            ],
            "sample_count": int(report["gadget_decomposition_audit"]["sample_count"]),
            "samples": [
                {
                    "index": int(sample["index"]),
                    "target": _zq_vector_report(sample["target"], report["modulus"]),
                    "digit_count": int(sample["digit_count"]),
                    "expected_digit_count": int(sample["expected_digit_count"]),
                    "digit_bounds_hold": bool(sample["digit_bounds_hold"]),
                    "gadget_equation_holds": bool(sample["gadget_equation_holds"]),
                    "canonical_preimage_equation_holds": bool(
                        sample["canonical_preimage_equation_holds"]
                    ),
                }
                for sample in report["gadget_decomposition_audit"]["samples"]
            ],
            "all_digit_bounds_hold": bool(
                report["gadget_decomposition_audit"]["all_digit_bounds_hold"]
            ),
            "all_gadget_equations_hold": bool(
                report["gadget_decomposition_audit"]["all_gadget_equations_hold"]
            ),
            "all_canonical_preimage_equations_hold": bool(
                report["gadget_decomposition_audit"][
                    "all_canonical_preimage_equations_hold"
                ]
            ),
            "all_checks_hold": bool(
                report["gadget_decomposition_audit"]["all_checks_hold"]
            ),
        },
        "kernel_basis_rank": int(report["kernel_basis_rank"]),
        "kernel_basis_columns": int(report["kernel_basis_columns"]),
        "kernel_basis_full_rank": bool(report["kernel_basis_full_rank"]),
        "kernel_basis_relation_holds": bool(report["kernel_basis_relation_holds"]),
        "trapdoor_quality_checks_hold": bool(report["trapdoor_quality_checks_hold"]),
        "distribution_audit_caveat": report["distribution_audit_caveat"],
    }


def _trap_gen_multi_seed_audit_report(report):
    return {
        "scope": report["scope"],
        "trapdoor_type": report["trapdoor_type"],
        "sample_count": int(report["sample_count"]),
        "unique_instance_count": int(report["unique_instance_count"]),
        "same_seed_reproducible": bool(report["same_seed_reproducible"]),
        "different_seed_distinct": bool(report["different_seed_distinct"]),
        "all_relations_hold": bool(report["all_relations_hold"]),
        "all_quality_checks_hold": bool(report["all_quality_checks_hold"]),
        "samples": [
            {
                "index": int(sample["index"]),
                "seed_label": sample["seed_label"],
                "a_bar_relation_holds": bool(sample["a_bar_relation_holds"]),
                "tail_relation_holds": bool(sample["tail_relation_holds"]),
                "trapdoor_relation_holds": bool(sample["trapdoor_relation_holds"]),
                "gadget_decomposition_audit_all_checks_hold": bool(
                    sample["gadget_decomposition_audit_all_checks_hold"]
                ),
                "kernel_basis_relation_holds": bool(
                    sample["kernel_basis_relation_holds"]
                ),
                "trapdoor_quality_checks_hold": bool(
                    sample["trapdoor_quality_checks_hold"]
                ),
                "r_entries_are_ternary": bool(sample["r_entries_are_ternary"]),
                "a_bar_uniformity_claim_permitted": bool(
                    sample["a_bar_uniformity_claim_permitted"]
                ),
                "r_distribution_claim_permitted": bool(
                    sample["r_distribution_claim_permitted"]
                ),
                "production_trapgen_claim_permitted": bool(
                    sample["production_trapgen_claim_permitted"]
                ),
                "r_nonzero_count": int(sample["r_nonzero_count"]),
                "r_density": float(sample["r_density"]),
            }
            for sample in report["samples"]
        ],
        "all_checks_hold": bool(report["all_checks_hold"]),
        "caveat": report["caveat"],
    }


def _paper_lattice_asymptotic_parameter_report(report):
    return {
        "scope": report["scope"],
        "formula": report["formula"],
        "log_q_interpretation": report["log_q_interpretation"],
        "n": int(report["n"]),
        "m": int(report["m"]),
        "q": int(report["q"]),
        "delta_estimate": float(report["delta_estimate"]),
        "n_delta_proxy": float(report["n_delta_proxy"]),
        "ceil_log_q_base2": int(report["ceil_log_q_base2"]),
        "ceil_log_q_natural": int(report["ceil_log_q_natural"]),
        "n_delta_over_ceil_log_q_base2": float(
            report["n_delta_over_ceil_log_q_base2"]
        ),
        "m_relation_reconstructed": float(report["m_relation_reconstructed"]),
        "n_delta_bound_holds": bool(report["n_delta_bound_holds"]),
        "all_checks_hold": bool(report["all_checks_hold"]),
    }


def _authentication_parameter_report(report):
    return {
        "dimension": int(report["dimension"]),
        "lattice_rank_n": int(report["lattice_rank_n"]),
        "modulus_q": int(report["modulus_q"]),
        "challenge_bound_B_c": int(report["challenge_bound_B_c"]),
        "delta_c_min": int(report["delta_c_min"]),
        "nonce_bytes": int(report["nonce_bytes"]),
        "nonce_lambda_bits": int(report["nonce_lambda_bits"]),
        "omega_factor_config_key": report["omega_factor_config_key"],
        "omega_factor": float(report["omega_factor"]),
        "sigma_mask": float(report["sigma_mask"]),
        "sigma_mask_formula": report["sigma_mask_formula"],
        "alpha_formula": report["alpha_formula"],
        "alpha_sigma_mask": float(report["alpha_sigma_mask"]),
        "sqrt_log_m": float(report["sqrt_log_m"]),
        "alpha_over_sqrt_log_m": float(report["alpha_over_sqrt_log_m"]),
        "alpha_dominates_sqrt_log_m": bool(report["alpha_dominates_sqrt_log_m"]),
        "beta": int(report["beta"]),
        "mask_norm_bound": float(report["mask_norm_bound"]),
        "challenge_term_bound": float(report["challenge_term_bound"]),
        "recommended_beta_response": float(report["recommended_beta_response"]),
        "beta_response": int(report["beta_response"]),
        "beta_response_over_recommended": float(report["beta_response_over_recommended"]),
        "passes_recommended_bound": bool(report["passes_recommended_bound"]),
        "response_beta_formula": report["response_beta_formula"],
        "q_lower_bound_direct": float(report["q_lower_bound_direct"]),
        "q_lower_bound_sis": float(report["q_lower_bound_sis"]),
        "recommended_q_lower_bound": float(report["recommended_q_lower_bound"]),
        "q_over_recommended": float(report["q_over_recommended"]),
        "q_bound_holds": bool(report["q_bound_holds"]),
        "q_bound_formula": report["q_bound_formula"],
        "sis_extraction_bound": float(report["sis_extraction_bound"]),
        "sis_slack_term": float(report["sis_slack_term"]),
    }


def _parameter_preflight_report(sample_pre_report, authentication_report):
    sample_pre_sigma_ok = bool(sample_pre_report["passes_recommended_bound"])
    authentication_response_ok = bool(authentication_report["passes_recommended_bound"])
    authentication_q_ok = bool(authentication_report["q_bound_holds"])
    all_bounds_hold = bool(
        sample_pre_sigma_ok
        and authentication_response_ok
        and authentication_q_ok
    )

    return {
        "scope": "split_omega_parameter_preflight",
        "status": "passed" if all_bounds_hold else "failed",
        "sample_pre": {
            "omega_factor_config_key": "sample_pre.omega_factor",
            "sample_pre_omega_factor": float(sample_pre_report["omega_factor"]),
            "sigma_pre": float(sample_pre_report["sigma"]),
            "recommended_sigma": float(sample_pre_report["recommended_sigma"]),
            "recommended_beta": float(sample_pre_report["recommended_beta"]),
            "sigma_bound_holds": sample_pre_sigma_ok,
        },
        "authentication": {
            "omega_factor_config_key": authentication_report["omega_factor_config_key"],
            "authentication_omega_factor": float(authentication_report["omega_factor"]),
            "sigma_mask": float(authentication_report["sigma_mask"]),
            "mask_norm_bound": float(authentication_report["mask_norm_bound"]),
            "challenge_term_bound": float(authentication_report["challenge_term_bound"]),
            "recommended_beta_response": float(
                authentication_report["recommended_beta_response"]
            ),
            "beta_response": int(authentication_report["beta_response"]),
            "response_triangle_bound_holds": authentication_response_ok,
            "q_lower_bound_direct": float(authentication_report["q_lower_bound_direct"]),
            "q_lower_bound_sis": float(authentication_report["q_lower_bound_sis"]),
            "recommended_q_lower_bound": float(
                authentication_report["recommended_q_lower_bound"]
            ),
            "q": int(authentication_report["modulus_q"]),
            "q_bound_holds": authentication_q_ok,
            "alpha_dominates_sqrt_log_m": bool(
                authentication_report["alpha_dominates_sqrt_log_m"]
            ),
        },
        "all_paper_parameter_bounds_hold": all_bounds_hold,
    }


def _sampler_parameter_audit_report(report):
    return {
        "scope": report["scope"],
        "parameter_set_label": report["parameter_set_label"],
        "parameter_set_status": report["parameter_set_status"],
        "explicit_config_required": bool(report["explicit_config_required"]),
        "sample_pre": {
            "algorithm": report["sample_pre"]["algorithm"],
            "sigma_config_key": report["sample_pre"]["sigma_config_key"],
            "sigma_pre": float(report["sample_pre"]["sigma_pre"]),
            "tail_cutoff_config_key": report["sample_pre"]["tail_cutoff_config_key"],
            "tail_cutoff": int(report["sample_pre"]["tail_cutoff"]),
            "tail_cutoff_source": report["sample_pre"]["tail_cutoff_source"],
            "omega_factor_config_key": report["sample_pre"]["omega_factor_config_key"],
            "omega_factor": float(report["sample_pre"]["omega_factor"]),
            "sampler_backend": report["sample_pre"]["sampler_backend"],
            "sampler_real_precision_bits": int(
                report["sample_pre"]["sampler_real_precision_bits"]
            ),
            "sampler_draw_bits": int(report["sample_pre"]["sampler_draw_bits"]),
            "continuous_tail_heuristic_bound": float(
                report["sample_pre"]["continuous_tail_heuristic_bound"]
            ),
        },
        "authentication_mask": {
            "algorithm": report["authentication_mask"]["algorithm"],
            "sigma_config_key": report["authentication_mask"]["sigma_config_key"],
            "sigma_mask": float(report["authentication_mask"]["sigma_mask"]),
            "tail_cutoff_config_key": report["authentication_mask"][
                "tail_cutoff_config_key"
            ],
            "tail_cutoff": int(report["authentication_mask"]["tail_cutoff"]),
            "tail_cutoff_source": report["authentication_mask"][
                "tail_cutoff_source"
            ],
            "omega_factor_config_key": report["authentication_mask"][
                "omega_factor_config_key"
            ],
            "omega_factor": float(report["authentication_mask"]["omega_factor"]),
            "sampler_backend": report["authentication_mask"]["sampler_backend"],
            "sampler_real_precision_bits": int(
                report["authentication_mask"]["sampler_real_precision_bits"]
            ),
            "sampler_draw_bits": int(
                report["authentication_mask"]["sampler_draw_bits"]
            ),
            "continuous_tail_heuristic_bound": float(
                report["authentication_mask"]["continuous_tail_heuristic_bound"]
            ),
        },
        "checks": {name: bool(value) for name, value in report["checks"].items()},
        "all_checks_hold": bool(report["all_checks_hold"]),
        "caveat": report["caveat"],
    }


def _authentication_transcript_shape_report(report):
    return {
        "scope": report["scope"],
        "paper_transcript": report["paper_transcript"],
        "has_path_proof": bool(report["has_path_proof"]),
        "has_commitment": bool(report["has_commitment"]),
        "has_challenge": bool(report["has_challenge"]),
        "has_response": bool(report["has_response"]),
        "has_required_fields": bool(report["has_required_fields"]),
        "commitment_is_sage_vector": bool(report["commitment_is_sage_vector"]),
        "commitment_dimension": int(report["commitment_dimension"]),
        "expected_commitment_dimension": int(report["expected_commitment_dimension"]),
        "commitment_dimension_holds": bool(report["commitment_dimension_holds"]),
        "commitment_base_ring_matches_zq": bool(
            report["commitment_base_ring_matches_zq"]
        ),
        "commitment_coordinates_in_zq": bool(report["commitment_coordinates_in_zq"]),
        "response_is_sequence": bool(report["response_is_sequence"]),
        "response_iterable_valid": bool(report["response_iterable_valid"]),
        "response_has_base_ring": bool(report["response_has_base_ring"]),
        "response_base_ring_matches_zz": bool(
            report["response_base_ring_matches_zz"]
        ),
        "response_dimension": int(report["response_dimension"]),
        "expected_response_dimension": int(report["expected_response_dimension"]),
        "response_dimension_holds": bool(report["response_dimension_holds"]),
        "response_entries_are_integers": bool(
            report["response_entries_are_integers"]
        ),
        "challenge_is_integer": bool(report["challenge_is_integer"]),
        "all_shape_checks_hold": bool(report["all_shape_checks_hold"]),
    }


def _authentication_transcript_audit_report(report):
    return {
        "paper_algorithm": report["paper_algorithm"],
        "paper_input": report["paper_input"],
        "paper_transcript": report["paper_transcript"],
        "paper_challenge_equation": report["paper_challenge_equation"],
        "h2_transcript_order": list(report["h2_transcript_order"]),
        "transcript_fields": list(report["transcript_fields"]),
        "transcript_shape_report": _authentication_transcript_shape_report(
            report["transcript_shape_report"]
        ),
        "transcript_shape_holds": bool(report["transcript_shape_holds"]),
        "challenge_space": report["challenge_space"],
        "challenge_modulus": int(report["challenge_modulus"]),
        "challenge_bound_B_c": int(report["challenge_bound_B_c"]),
        "delta_c_min": int(report["delta_c_min"]),
        "challenge": int(report["challenge"]),
        "expected_challenge": int(report["expected_challenge"]),
        "challenge_matches": bool(report["challenge_matches"]),
        "challenge_in_space": bool(report["challenge_in_space"]),
        "path_proof_holds": bool(report["path_proof_holds"]),
        "response_dimension": int(report["response_dimension"]),
        "expected_response_dimension": int(report["expected_response_dimension"]),
        "response_dimension_holds": bool(report["response_dimension_holds"]),
        "commitment_dimension": int(report["commitment_dimension"]),
        "expected_commitment_dimension": int(report["expected_commitment_dimension"]),
        "commitment_dimension_holds": bool(report["commitment_dimension_holds"]),
        "response_norm_squared": int(report["response_norm_squared"]),
        "beta_response": int(report["beta_response"]),
        "response_norm_bound_holds": bool(report["response_norm_bound_holds"]),
        "verification_equation": report["verification_equation"],
        "equation_holds": bool(report["equation_holds"]),
        "all_algorithmic_checks_hold": bool(
            report["all_algorithmic_checks_hold"]
        ),
        "verifies": bool(report["verifies"]),
    }


def _authentication_transcript_input_validation_audit_report(report):
    return {
        "scope": report["scope"],
        "paper_statement": report["paper_statement"],
        "valid_transcript_accepts": bool(report["valid_transcript_accepts"]),
        "case_count": int(report["case_count"]),
        "cases": [
            {
                "name": case["name"],
                "verify_rejects": bool(case["verify_rejects"]),
                "shape_checks_hold": bool(case["shape_checks_hold"]),
                "shape_report": _authentication_transcript_shape_report(
                    case["shape_report"]
                ),
            }
            for case in report["cases"]
        ],
        "all_malformed_rejected": bool(report["all_malformed_rejected"]),
        "at_least_one_shape_failure_per_malformed": bool(
            report["at_least_one_shape_failure_per_malformed"]
        ),
        "all_checks_hold": bool(report["all_checks_hold"]),
    }


def _authentication_generation_audit_report(report):
    if report is None:
        return None

    return {
        "paper_algorithm": report["paper_algorithm"],
        "paper_transcript": report["paper_transcript"],
        "paper_challenge": report["paper_challenge"],
        "paper_mask_sampling": report["paper_mask_sampling"],
        "paper_commitment_equation": report["paper_commitment_equation"],
        "paper_challenge_equation": report["paper_challenge_equation"],
        "paper_response_equation": report["paper_response_equation"],
        "paper_rejection_condition": report["paper_rejection_condition"],
        "h2_transcript_order": list(report["h2_transcript_order"]),
        "transcript_fields": list(report["transcript_fields"]),
        "mask_sampler": report["mask_sampler"],
        "sampler_backend": report["sampler_backend"],
        "sampler_real_precision_bits": int(report["sampler_real_precision_bits"]),
        "sampler_draw_bits": int(report["sampler_draw_bits"]),
        "mask_dimension": int(report["mask_dimension"]),
        "mask_dimension_matches_m": bool(report["mask_dimension_matches_m"]),
        "commitment_dimension": int(report["commitment_dimension"]),
        "expected_commitment_dimension": int(report["expected_commitment_dimension"]),
        "commitment_dimension_matches_n": bool(
            report["commitment_dimension_matches_n"]
        ),
        "response_dimension": int(report["response_dimension"]),
        "expected_response_dimension": int(report["expected_response_dimension"]),
        "response_dimension_matches_m": bool(report["response_dimension_matches_m"]),
        "sigma_mask": float(report["sigma_mask"]),
        "omega_factor": float(report["omega_factor"]),
        "tail_cutoff": int(report["tail_cutoff"]),
        "continuous_tail_heuristic_bound": float(report["continuous_tail_heuristic_bound"]),
        "accepted_attempt_index": int(report["accepted_attempt_index"]),
        "attempt_count": int(report["attempt_count"]),
        "max_attempts": int(report["max_attempts"]),
        "rejected_attempt_count": int(report["rejected_attempt_count"]),
        "attempt_trace_count": int(report["attempt_trace_count"]),
        "attempt_trace": [
            {
                "attempt_index": int(item["attempt_index"]),
                "mask_norm_squared": int(item["mask_norm_squared"]),
                "challenge": int(item["challenge"]),
                "response_norm_squared": int(item["response_norm_squared"]),
                "response_norm_bound_holds": bool(
                    item["response_norm_bound_holds"]
                ),
                "accepted": bool(item["accepted"]),
            }
            for item in report["attempt_trace"]
        ],
        "all_rejected_attempts_failed_norm_bound": bool(
            report["all_rejected_attempts_failed_norm_bound"]
        ),
        "accepted_attempt_bound_holds": bool(report["accepted_attempt_bound_holds"]),
        "paper_rejection_sampling_step": report["paper_rejection_sampling_step"],
        "mask_norm_squared": int(report["mask_norm_squared"]),
        "mask_norm_bound": float(report["mask_norm_bound"]),
        "mask_norm_bound_squared": float(report["mask_norm_bound_squared"]),
        "mask_norm_bound_holds": bool(report["mask_norm_bound_holds"]),
        "challenge_scaled_credential_norm_squared": int(
            report["challenge_scaled_credential_norm_squared"]
        ),
        "challenge_scaled_credential_bound": float(
            report["challenge_scaled_credential_bound"]
        ),
        "challenge_scaled_credential_bound_squared": float(
            report["challenge_scaled_credential_bound_squared"]
        ),
        "challenge_scaled_credential_bound_holds": bool(
            report["challenge_scaled_credential_bound_holds"]
        ),
        "triangle_response_norm_bound": float(report["triangle_response_norm_bound"]),
        "triangle_response_norm_bound_squared": float(
            report["triangle_response_norm_bound_squared"]
        ),
        "response_triangle_bound_holds": bool(report["response_triangle_bound_holds"]),
        "paper_response_bound_formula": report["paper_response_bound_formula"],
        "response_norm_squared": int(report["response_norm_squared"]),
        "beta_response": int(report["beta_response"]),
        "response_norm_bound_holds": bool(report["response_norm_bound_holds"]),
        "commitment_equation": report["commitment_equation"],
        "commitment_equation_holds": bool(report["commitment_equation_holds"]),
        "challenge_in_space": bool(report["challenge_in_space"]),
        "challenge_equation": report["challenge_equation"],
        "challenge_equation_holds": bool(report["challenge_equation_holds"]),
        "response_relation": report["response_relation"],
        "response_relation_holds": bool(report["response_relation_holds"]),
        "challenge": int(report["challenge"]),
        "all_algorithmic_checks_hold": bool(
            report["all_algorithmic_checks_hold"]
        ),
    }


def _authentication_rejection_sampling_path_audit_report(report):
    return {
        "scope": report["scope"],
        "status": report["status"],
        "paper_step": report.get("paper_step"),
        "selected_beta_response": (
            None
            if "selected_beta_response" not in report
            else int(report["selected_beta_response"])
        ),
        "selected_accept_index": (
            None
            if "selected_accept_index" not in report
            else int(report["selected_accept_index"])
        ),
        "attempts_examined": int(report["attempts_examined"]),
        "simulated_attempts": [
            {
                "attempt_index": int(item["attempt_index"]),
                "challenge": int(item["challenge"]),
                "response_norm_squared": int(item["response_norm_squared"]),
            }
            for item in report["simulated_attempts"]
        ],
        "generation_report": _authentication_generation_audit_report(
            report.get("generation_report")
        ),
        "controlled_rejection_path_found": bool(
            report["controlled_rejection_path_found"]
        ),
        "rejected_before_accept": bool(report.get("rejected_before_accept", False)),
        "accepted_at_selected_index": bool(
            report.get("accepted_at_selected_index", False)
        ),
        "all_checks_hold": bool(report["all_checks_hold"]),
        "caveat": report["caveat"],
    }


def _lattice_verkle_tree_state_report(report):
    result = {
        "state_tree_kind": report["state_tree_kind"],
        "branching_factor": int(report["branching_factor"]),
        "height": int(report["height"]),
        "leaf_count": int(report["leaf_count"]),
        "commitment_bytes": int(report["commitment_bytes"]),
        "occupied_leaf_count": int(report["occupied_leaf_count"]),
        "active_leaf_count": int(report["active_leaf_count"]),
        "revoked_leaf_count": int(report["revoked_leaf_count"]),
        "commitment_cache_backend": report.get("commitment_cache_backend"),
        "cached_node_count": (
            None
            if "cached_node_count" not in report
            else int(report["cached_node_count"])
        ),
        "occupied_prefix_count": (
            None
            if "occupied_prefix_count" not in report
            else int(report["occupied_prefix_count"])
        ),
        "root": _bytes_hex(report["root"]),
    }
    if "root_vector" in report:
        result["root_vector"] = _zq_vector_report(report["root_vector"], report["modulus"])
        result["vector_dimension"] = int(report["vector_dimension"])
        result["modulus"] = int(report["modulus"])
    return result


def _lattice_verkle_path_report(report):
    return {
        "state_tree_kind": report["state_tree_kind"],
        "paper_object": report["paper_object"],
        "proof_commitment_model": report["proof_commitment_model"],
        "verification_leaf_status": report["verification_leaf_status"],
        "active_leaf_domain": report["active_leaf_domain"],
        "revoked_leaf_domain": report["revoked_leaf_domain"],
        "active_revoked_leaf_domains_distinct": bool(
            report["active_revoked_leaf_domains_distinct"]
        ),
        "active_revoked_leaf_commitments_distinct": bool(
            report["active_revoked_leaf_commitments_distinct"]
        ),
        "verifies_revoked_leaf_path": bool(report["verifies_revoked_leaf_path"]),
        "revoked_leaf_does_not_verify_as_active_path": bool(
            report["revoked_leaf_does_not_verify_as_active_path"]
        ),
        "active_membership_leaf_domain_checks_hold": bool(
            report["active_membership_leaf_domain_checks_hold"]
        ),
        "proof_size_model": report["proof_size_model"],
        "vector_commitment_target_model": report["vector_commitment_target_model"],
        "vector_commitment_target_opening_count": int(
            report["vector_commitment_target_opening_count"]
        ),
        "commitment_count_over_vector_commitment_target": float(
            report["commitment_count_over_vector_commitment_target"]
        ),
        "extra_commitments_over_vector_commitment_target": int(
            report["extra_commitments_over_vector_commitment_target"]
        ),
        "state_commitment_upgrade_required_for_verkle_claim": bool(
            report["state_commitment_upgrade_required_for_verkle_claim"]
        ),
        "paper_verkle_backend_claim_permitted": bool(
            report["paper_verkle_backend_claim_permitted"]
        ),
        "paper_verkle_proof_size_model_claim_permitted": bool(
            report["paper_verkle_proof_size_model_claim_permitted"]
        ),
        "production_verkle_vector_commitment": bool(
            report["production_verkle_vector_commitment"]
        ),
        "production_verkle_proof_size_claim_permitted": bool(
            report["production_verkle_proof_size_claim_permitted"]
        ),
        "leaf_index": int(report["leaf_index"]),
        "leaf_index_in_range": bool(report["leaf_index_in_range"]),
        "slot_probe": int(report["slot_probe"]),
        "slot_probe_in_range": bool(report["slot_probe_in_range"]),
        "expected_leaf_index": int(report["expected_leaf_index"]),
        "leaf_index_matches_identity_probe": bool(
            report["leaf_index_matches_identity_probe"]
        ),
        "layer_count": int(report["layer_count"]),
        "expected_layer_count": int(report["expected_layer_count"]),
        "layer_count_holds": bool(report["layer_count_holds"]),
        "path_index_count_holds": bool(report.get("path_index_count_holds", True)),
        "commitment_count": int(report["commitment_count"]),
        "expected_commitment_count": int(report["expected_commitment_count"]),
        "sibling_commitment_count": int(report["sibling_commitment_count"]),
        "path_metadata_bytes": int(report["path_metadata_bytes"]),
        "proof_size_bytes": int(report["proof_size_bytes"]),
        "branching_factor": int(report["branching_factor"]),
        "branching_holds": bool(report["branching_holds"]),
        "proof_shape_holds": bool(report["proof_shape_holds"]),
        "verifies_active_path": bool(report["verifies_active_path"]),
    }


def _lattice_verkle_fs_context_report(report):
    return {
        "scope": report["scope"],
        "paper_formula": report["paper_formula"],
        "coefficient_domain": report["coefficient_domain"],
        "coefficient_modulus": int(report["coefficient_modulus"]),
        "context_fields": list(report["context_fields"]),
        "parent_prefix_digits_bound": bool(report["parent_prefix_digits_bound"]),
        "level_bound": bool(report["level_bound"]),
        "child_index_bound": bool(report["child_index_bound"]),
        "child_commitment_bound": bool(report["child_commitment_bound"]),
        "deterministic_replay_holds": bool(report["deterministic_replay_holds"]),
        "child_commitment_changes_coefficient": bool(
            report["child_commitment_changes_coefficient"]
        ),
        "child_index_changes_coefficient": bool(
            report["child_index_changes_coefficient"]
        ),
        "level_context_available": bool(report["level_context_available"]),
        "level_changes_coefficient": bool(report["level_changes_coefficient"]),
        "parent_prefix_context_available": bool(
            report["parent_prefix_context_available"]
        ),
        "parent_prefix_changes_coefficient": bool(
            report["parent_prefix_changes_coefficient"]
        ),
        "base_coefficient": int(report["base_coefficient"]),
        "changed_child_coefficient": int(report["changed_child_coefficient"]),
        "changed_child_index_coefficient": int(
            report["changed_child_index_coefficient"]
        ),
        "changed_level_coefficient": int(report["changed_level_coefficient"]),
        "changed_prefix_coefficient": int(report["changed_prefix_coefficient"]),
        "all_checks_hold": bool(report["all_checks_hold"]),
    }


def _state_commitment_backend_report(report):
    return {
        "scope": report["scope"],
        "paper_object": report["paper_object"],
        "paper_security_assumption": report["paper_security_assumption"],
        "current_backend": report["current_backend"],
        "implemented_paper_claim_level": report["implemented_paper_claim_level"],
        "current_commitment_model": report["current_commitment_model"],
        "target_backend_family": report["target_backend_family"],
        "target_commitment_model": report["target_commitment_model"],
        "branching_factor": int(report["branching_factor"]),
        "height": int(report["height"]),
        "leaf_count": int(report["leaf_count"]),
        "commitment_bytes": int(report["commitment_bytes"]),
        "current_commitments_per_path": int(report["current_commitments_per_path"]),
        "vector_commitment_target_openings_per_path": int(
            report["vector_commitment_target_openings_per_path"]
        ),
        "extra_commitments_over_vector_commitment_target": int(
            report["extra_commitments_over_vector_commitment_target"]
        ),
        "commitment_count_over_vector_commitment_target": float(
            report["commitment_count_over_vector_commitment_target"]
        ),
        "implements_register_verify_revoke_state_semantics": bool(
            report["implements_register_verify_revoke_state_semantics"]
        ),
        "implements_position_binding_experiment": bool(
            report["implements_position_binding_experiment"]
        ),
        "verification_leaf_status": report["verification_leaf_status"],
        "revoked_state_leaf_status": report["revoked_state_leaf_status"],
        "active_leaf_domain": report["active_leaf_domain"],
        "revoked_leaf_domain": report["revoked_leaf_domain"],
        "active_revoked_leaf_domains_distinct": bool(
            report["active_revoked_leaf_domains_distinct"]
        ),
        "active_revoked_leaf_commitments_distinct": bool(
            report["active_revoked_leaf_commitments_distinct"]
        ),
        "revoked_leaf_represents_revocation_not_active_membership": bool(
            report["revoked_leaf_represents_revocation_not_active_membership"]
        ),
        "fiat_shamir_coefficient_context_report": _lattice_verkle_fs_context_report(
            report["fiat_shamir_coefficient_context_report"]
        ),
        "fiat_shamir_context_binds_parent_prefix": bool(
            report["fiat_shamir_context_binds_parent_prefix"]
        ),
        "fiat_shamir_context_checks_hold": bool(
            report["fiat_shamir_context_checks_hold"]
        ),
        "paper_verkle_backend_claim_permitted": bool(
            report["paper_verkle_backend_claim_permitted"]
        ),
        "paper_verkle_proof_size_model_claim_permitted": bool(
            report["paper_verkle_proof_size_model_claim_permitted"]
        ),
        "paper_verkle_security_assumption_matches_backend": bool(
            report["paper_verkle_security_assumption_matches_backend"]
        ),
        "research_reference_backend": bool(report["research_reference_backend"]),
        "production_verkle_vector_commitment": bool(
            report["production_verkle_vector_commitment"]
        ),
        "production_verkle_proof_size_claim_permitted": bool(
            report["production_verkle_proof_size_claim_permitted"]
        ),
        "paper_alignment_action": report["paper_alignment_action"],
        "verkle_security_claim_permitted": bool(
            report["verkle_security_claim_permitted"]
        ),
        "paper_alignment_options": list(report["paper_alignment_options"]),
        "all_checks_hold": bool(report["all_checks_hold"]),
        "caveat": report["caveat"],
    }


def _lattice_verkle_position_binding_report(report):
    return {
        "state_tree_kind": report["state_tree_kind"],
        "security_model": report["security_model"],
        "paper_assumption": report["paper_assumption"],
        "commitment_assumption": report["commitment_assumption"],
        "leaf_index": int(report["leaf_index"]),
        "slot_probe": int(report["slot_probe"]),
        "expected_leaf_index": int(report["expected_leaf_index"]),
        "leaf_index_matches_identity_probe": bool(
            report["leaf_index_matches_identity_probe"]
        ),
        "leaf_index_matches_identity": bool(report["leaf_index_matches_identity"]),
        "tampered_identity_leaf_index": int(report["tampered_identity_leaf_index"]),
        "verifies_active_path": bool(report["verifies_active_path"]),
        "rejects_tampered_y_id": bool(report["rejects_tampered_y_id"]),
        "rejects_tampered_identity": bool(report["rejects_tampered_identity"]),
        "rejects_tampered_root": bool(report["rejects_tampered_root"]),
        "position_binding_checks_hold": bool(report["position_binding_checks_hold"]),
    }


def _lattice_verkle_collision_resolution_report(report):
    return {
        "scope": report["scope"],
        "state_tree_kind": report["state_tree_kind"],
        "paper_requirement": report["paper_requirement"],
        "collision_policy": report["collision_policy"],
        "branching_factor": int(report["branching_factor"]),
        "height": int(report["height"]),
        "leaf_count": int(report["leaf_count"]),
        "initial_root": _bytes_hex(report["initial_root"]),
        "root_after_primary_insert": _bytes_hex(report["root_after_primary_insert"]),
        "root_after_collision_insert": _bytes_hex(report["root_after_collision_insert"]),
        "primary_identity_hex": _bytes_hex(report["primary_identity"]),
        "colliding_identity_hex": _bytes_hex(report["colliding_identity"]),
        "initial_leaf_index": int(report["initial_leaf_index"]),
        "colliding_initial_leaf_index": int(report["colliding_initial_leaf_index"]),
        "initial_indices_collide": bool(report["initial_indices_collide"]),
        "primary_assigned_leaf_index": int(report["primary_assigned_leaf_index"]),
        "colliding_assigned_leaf_index": int(report["colliding_assigned_leaf_index"]),
        "primary_slot_probe": int(report["primary_slot_probe"]),
        "colliding_slot_probe": int(report["colliding_slot_probe"]),
        "collision_uses_nonzero_probe": bool(report["collision_uses_nonzero_probe"]),
        "assigned_indices_distinct": bool(report["assigned_indices_distinct"]),
        "primary_path_verifies_before_collision_insert": bool(
            report["primary_path_verifies_before_collision_insert"]
        ),
        "primary_path_stale_after_collision_insert": bool(
            report["primary_path_stale_after_collision_insert"]
        ),
        "primary_refreshed_path_verifies_after_collision_insert": bool(
            report["primary_refreshed_path_verifies_after_collision_insert"]
        ),
        "colliding_path_verifies": bool(report["colliding_path_verifies"]),
        "duplicate_identity_rejected": bool(report["duplicate_identity_rejected"]),
        "active_leaf_count": int(report["active_leaf_count"]),
        "root_changes_on_primary_insert": bool(report["root_changes_on_primary_insert"]),
        "root_changes_on_collision_insert": bool(report["root_changes_on_collision_insert"]),
        "all_checks_hold": bool(report["all_checks_hold"]),
    }


def _root_transition_report(report):
    return {
        "label": report["label"],
        "before_root": _bytes_hex(report["before_root"]),
        "after_root": _bytes_hex(report["after_root"]),
        "root_changed": bool(report["root_changed"]),
    }


def _authentication_challenge_report(report):
    return {
        "scope": report["scope"],
        "paper_challenge": report["paper_challenge"],
        "nonce_hex": _bytes_hex(report["nonce"]),
        "root": _bytes_hex(report["root"]),
        "root_is_public_current": bool(report["root_is_public_current"]),
        "root_is_state_current": bool(report["root_is_state_current"]),
        "challenge_root_is_current": bool(report["challenge_root_is_current"]),
    }


def _authentication_nonce_sampling_report(report):
    return {
        "scope": report["scope"],
        "paper_statement": report["paper_statement"],
        "sampler": report["sampler"],
        "lambda_bits": int(report["lambda_bits"]),
        "nonce_bytes": int(report["nonce_bytes"]),
        "nonce_hex": _bytes_hex(report["nonce"]),
        "same_seed_reproducible": bool(report["same_seed_reproducible"]),
        "different_seed_distinct": bool(report["different_seed_distinct"]),
        "length_holds": bool(report["length_holds"]),
        "all_checks_hold": bool(report["all_checks_hold"]),
    }


def _random_oracle_instantiation_report(report):
    return {
        "scope": report["scope"],
        "implementation": report["implementation"],
        "implementation_language": report["implementation_language"],
        "hash_primitive_source": report["hash_primitive_source"],
        "third_party_crypto_dependency": bool(report["third_party_crypto_dependency"]),
        "sage_native_crypto_hash_available": bool(
            report["sage_native_crypto_hash_available"]
        ),
        "sage_native_crypto_hash_note": report["sage_native_crypto_hash_note"],
        "paper_oracles": list(report["paper_oracles"]),
        "h1_domain": report["h1_domain"],
        "h2_scalar_domain": report["h2_scalar_domain"],
        "encoding": report["encoding"],
        "h1_method": report["h1_method"],
        "h2_scalar_method": report["h2_scalar_method"],
        "active_h2_challenge_method": report["active_h2_challenge_method"],
        "active_h2_transcript_order": list(report["active_h2_transcript_order"]),
        "h1_dimension": int(report["h1_dimension"]),
        "h1_modulus": int(report["h1_modulus"]),
        "h1_sample": _zq_vector_report(report["h1_sample"], report["h1_modulus"]),
        "h1_parent": report["h1_parent"],
        "h1_base_ring": report["h1_base_ring"],
        "h1_output_is_sage_vector": bool(report["h1_output_is_sage_vector"]),
        "h1_base_ring_matches_zq": bool(report["h1_base_ring_matches_zq"]),
        "h1_dimension_matches": bool(report["h1_dimension_matches"]),
        "h1_coordinates_in_zq": bool(report["h1_coordinates_in_zq"]),
        "h1_deterministic": bool(report["h1_deterministic"]),
        "h1_distinct_domain_input_changes_output": bool(
            report["h1_distinct_domain_input_changes_output"]
        ),
        "framing_avoids_concat_ambiguity": bool(
            report["framing_avoids_concat_ambiguity"]
        ),
        "h2_scalar_raw_modulus": int(report["h2_scalar_raw_modulus"]),
        "h2_scalar_raw": int(report["h2_scalar_raw"]),
        "h2_scalar_centered": int(report["h2_scalar_centered"]),
        "h2_raw_is_sage_integer": bool(report["h2_raw_is_sage_integer"]),
        "h2_centered_is_sage_integer": bool(report["h2_centered_is_sage_integer"]),
        "challenge_space": report["challenge_space"],
        "challenge_space_instantiation": report["challenge_space_instantiation"],
        "challenge_space_cardinality": int(report["challenge_space_cardinality"]),
        "challenge_bound_B_c": int(report["challenge_bound_B_c"]),
        "delta_c_min": int(report["delta_c_min"]),
        "delta_c_min_formula": report["delta_c_min_formula"],
        "centered_space_has_expected_cardinality": bool(
            report["centered_space_has_expected_cardinality"]
        ),
        "paper_challenge_space_note": report["paper_challenge_space_note"],
        "h2_scalar_raw_in_modulus": bool(report["h2_scalar_raw_in_modulus"]),
        "h2_scalar_centered_in_c_lambda": bool(
            report["h2_scalar_centered_in_c_lambda"]
        ),
        "all_checks_hold": bool(report["all_checks_hold"]),
    }


def _setup_key_surface_report(report):
    return {
        "scope": report["scope"],
        "paper_setup_output": report["paper_setup_output"],
        "sage_setup_extensions": list(report["sage_setup_extensions"]),
        "public_parameter_fields": list(report["public_parameter_fields"]),
        "master_secret_fields": list(report["master_secret_fields"]),
        "public_parameter_matrix_A_dimensions": [
            int(value) for value in report["public_parameter_matrix_A_dimensions"]
        ],
        "public_parameter_matrix_G_dimensions": [
            int(value) for value in report["public_parameter_matrix_G_dimensions"]
        ],
        "public_parameter_contains_A": bool(report["public_parameter_contains_A"]),
        "public_parameter_contains_G": bool(report["public_parameter_contains_G"]),
        "public_parameter_G_matches_gadget_matrix": bool(
            report["public_parameter_G_matches_gadget_matrix"]
        ),
        "public_parameter_contains_q": bool(report["public_parameter_contains_q"]),
        "public_parameter_q": int(report["public_parameter_q"]),
        "public_parameter_q_matches_lattice_parameters": bool(
            report["public_parameter_q_matches_lattice_parameters"]
        ),
        "public_parameter_contains_lattice_params": bool(
            report["public_parameter_contains_lattice_params"]
        ),
        "public_parameter_contains_norm_and_sampler_bounds": bool(
            report["public_parameter_contains_norm_and_sampler_bounds"]
        ),
        "public_parameter_sigma": float(report["public_parameter_sigma"]),
        "public_parameter_sigma_matches_authentication_mask": bool(
            report["public_parameter_sigma_matches_authentication_mask"]
        ),
        "public_parameter_contains_hash_oracle_configuration": bool(
            report["public_parameter_contains_hash_oracle_configuration"]
        ),
        "public_parameter_contains_tree_parameters": bool(
            report["public_parameter_contains_tree_parameters"]
        ),
        "public_parameter_tree_shape_aliases_match": bool(
            report["public_parameter_tree_shape_aliases_match"]
        ),
        "public_parameter_b": int(report["public_parameter_b"]),
        "public_parameter_h": int(report["public_parameter_h"]),
        "public_parameter_contains_root": bool(report["public_parameter_contains_root"]),
        "public_parameter_contains_initial_root": bool(
            report["public_parameter_contains_initial_root"]
        ),
        "public_parameter_root0_matches_setup_root": bool(
            report["public_parameter_root0_matches_setup_root"]
        ),
        "public_parameter_rt0_matches_setup_root": bool(
            report["public_parameter_rt0_matches_setup_root"]
        ),
        "public_parameter_H1": dict(report["public_parameter_H1"]),
        "public_parameter_H2": dict(report["public_parameter_H2"]),
        "public_parameter_H1_descriptor_matches": bool(
            report["public_parameter_H1_descriptor_matches"]
        ),
        "public_parameter_H2_descriptor_matches": bool(
            report["public_parameter_H2_descriptor_matches"]
        ),
        "public_has_expected_fields": bool(report["public_has_expected_fields"]),
        "public_omits_trapdoor": bool(report["public_omits_trapdoor"]),
        "master_secret_is_trapdoor_only": bool(report["master_secret_is_trapdoor_only"]),
        "master_secret_contains_trapdoor": bool(report["master_secret_contains_trapdoor"]),
        "root_matches_state": bool(report["root_matches_state"]),
        "all_checks_hold": bool(report["all_checks_hold"]),
    }


def _verification_root_parameterization_report(report):
    return {
        "scope": report["scope"],
        "paper_verify_input": report["paper_verify_input"],
        "paper_challenge": report["paper_challenge"],
        "nonce_hex": _bytes_hex(report["nonce"]),
        "root": _bytes_hex(report["root"]),
        "root_is_public_current": bool(report["root_is_public_current"]),
        "root_is_state_current": bool(report["root_is_state_current"]),
        "root_is_current": bool(report["root_is_current"]),
        "explicit_root_verify_accepts": bool(report["explicit_root_verify_accepts"]),
        "current_root_verify_accepts": bool(report["current_root_verify_accepts"]),
        "paper_current_root_accepts": bool(report["paper_current_root_accepts"]),
        "current_root_wrapper_matches_explicit_when_current": bool(
            report["current_root_wrapper_matches_explicit_when_current"]
        ),
    }


def _negative_verification_report(report):
    return {
        "scope": report["scope"],
        "paper_properties": list(report["paper_properties"]),
        "valid_transcript_verifies": bool(report["valid_transcript_verifies"]),
        "wrong_nonce_hex": report["wrong_nonce_hex"],
        "wrong_nonce_search_bound": int(report["wrong_nonce_search_bound"]),
        "rejects_wrong_nonce": bool(report["rejects_wrong_nonce"]),
        "rejects_tampered_root": bool(report["rejects_tampered_root"]),
        "rejects_tampered_y_id": bool(report["rejects_tampered_y_id"]),
        "rejects_tampered_commitment": bool(report["rejects_tampered_commitment"]),
        "rejects_tampered_challenge": bool(report["rejects_tampered_challenge"]),
        "rejects_tampered_response": bool(report["rejects_tampered_response"]),
        "wrong_nonce_challenge_mismatch": bool(report["wrong_nonce_challenge_mismatch"]),
        "tampered_root_path_rejected": bool(report["tampered_root_path_rejected"]),
        "tampered_y_id_path_rejected": bool(report["tampered_y_id_path_rejected"]),
        "tampered_commitment_challenge_mismatch": bool(
            report["tampered_commitment_challenge_mismatch"]
        ),
        "tampered_commitment_equation_rejected": bool(
            report["tampered_commitment_equation_rejected"]
        ),
        "tampered_commitment_rejected_by_challenge_or_equation": bool(
            report["tampered_commitment_rejected_by_challenge_or_equation"]
        ),
        "tampered_challenge_mismatch": bool(report["tampered_challenge_mismatch"]),
        "tampered_response_equation_rejected": bool(
            report["tampered_response_equation_rejected"]
        ),
        "all_negative_checks_hold": bool(report["all_negative_checks_hold"]),
        "valid_report": _authentication_transcript_audit_report(report["valid_report"]),
        "wrong_nonce_report": _authentication_transcript_audit_report(
            report["wrong_nonce_report"]
        ),
        "tampered_root_report": _authentication_transcript_audit_report(
            report["tampered_root_report"]
        ),
        "tampered_y_id_report": _authentication_transcript_audit_report(
            report["tampered_y_id_report"]
        ),
        "tampered_commitment_report": _authentication_transcript_audit_report(
            report["tampered_commitment_report"]
        ),
        "tampered_challenge_report": _authentication_transcript_audit_report(
            report["tampered_challenge_report"]
        ),
        "tampered_response_report": _authentication_transcript_audit_report(
            report["tampered_response_report"]
        ),
    }


def _path_proof_size_bytes(path_proof, tree_params):
    if getattr(path_proof, "backend", None) == "lattice_linear_verkle_tree":
        vector_bytes = 16 + 8 * int(path_proof.lattice_params.n)
        commitment_count = tree_params.height * (tree_params.branching_factor - 1)
        return int(16 + tree_params.height * 8 + commitment_count * vector_bytes)
    commitment_count = tree_params.height * tree_params.branching_factor
    return int(16 + commitment_count * tree_params.commitment_bytes)


def _transcript_size_bytes(transcript, lattice_params, tree_params):
    return int(
        _path_proof_size_bytes(transcript.path_proof, tree_params)
        + len(_serialize_zq_vector(transcript.commitment))
        + 8
        + 8 * lattice_params.m
    )


def _credential_report(identity, credential, tree_params):
    return {
        "visibility": "experiment_secret_reproducibility_not_protocol_public",
        "paper_credential_fields": ["z_id", "Y_id", "pi_id"],
        "credential_public_components": ["Y_id", "pi_id"],
        "published_root_field": "rt",
        "protocol_public_fields": ["Y_id", "pi_id"],
        "contains_secret_z_id": True,
        "identity_hex": _bytes_hex(_as_bytes(identity)),
        "internal_registration_epoch_hex": _bytes_hex(credential.epoch),
        "internal_registration_epoch_scope": (
            "sage_internal_register_convention_for_H1_id_epoch_not_protocol_public"
        ),
        "sample_pre_algorithm": "sample_pre_mp12_gpv_klein",
        "root": _bytes_hex(credential.root),
        "y_id": _zq_vector_report(credential.y_id, credential.y_id.base_ring().order()),
        "z_id": _zq_vector_report(credential.z_id, credential.z_id.base_ring().order()),
        "z_id_norm_squared": int(credential.norm_squared),
        "beta": int(credential.beta),
        "path_proof_leaf_index": int(credential.path_proof.leaf_index),
        "path_proof_commitment_count": int(
            sum(len(layer) for layer in credential.path_proof.sibling_commitment_layers)
        ),
        "path_proof_size_bytes": _path_proof_size_bytes(credential.path_proof, tree_params),
        "sample_pre_parameter_report": _parameter_report(credential.parameter_report),
        "sample_pre_output_report": _sample_pre_output_report(credential.sample_pre_report),
    }


def _proof_refresh_public_data_report(refresh_data, tree_params):
    return {
        "visibility": "protocol_public_proof_refresh_data",
        "protocol_public_fields": ["Y_id", "pi_id", "rt"],
        "contains_secret_z_id": False,
        "contains_trapdoor": False,
        "identity_hex": _bytes_hex(refresh_data.identity),
        "root": _bytes_hex(refresh_data.root),
        "y_id": _zq_vector_report(refresh_data.y_id, refresh_data.y_id.base_ring().order()),
        "path_proof_leaf_index": int(refresh_data.path_proof.leaf_index),
        "path_proof_slot_probe": int(refresh_data.path_proof.slot_probe),
        "path_proof_commitment_count": int(
            sum(len(layer) for layer in refresh_data.path_proof.sibling_commitment_layers)
        ),
        "path_proof_size_bytes": _path_proof_size_bytes(refresh_data.path_proof, tree_params),
    }


def _transcript_report(transcript, lattice_params, tree_params, audit_report):
    return {
        "visibility": "protocol_public_authentication_transcript",
        "protocol_public_fields": ["pi_id", "w", "c", "s"],
        "contains_secret_z_id": False,
        "contains_mask_r": False,
        "commitment": _zq_vector_report(transcript.commitment, lattice_params.q),
        "challenge": int(transcript.challenge),
        "response": _integer_vector_report(transcript.response),
        "response_norm_squared": int(_zz_vector_norm_squared(transcript.response)),
        "transcript_size_bytes": _transcript_size_bytes(transcript, lattice_params, tree_params),
        "authentication_generation_report": _authentication_generation_audit_report(
            transcript.audit_report
        ),
        "authentication_transcript_report": _authentication_transcript_audit_report(audit_report),
    }


def _protocol_public_surface_audit(
    credential_reports,
    transcript_reports,
    proof_refresh_service_audit,
):
    credential_reports_label_secret = all(
        report["visibility"] == "experiment_secret_reproducibility_not_protocol_public"
        and bool(report["contains_secret_z_id"])
        for report in credential_reports.values()
    )
    credential_reports_match_paper_shape = all(
        report.get("paper_credential_fields") == ["z_id", "Y_id", "pi_id"]
        and report.get("credential_public_components") == ["Y_id", "pi_id"]
        and report.get("published_root_field") == "rt"
        and report.get("protocol_public_fields") == ["Y_id", "pi_id"]
        and report.get("internal_registration_epoch_scope")
        == "sage_internal_register_convention_for_H1_id_epoch_not_protocol_public"
        for report in credential_reports.values()
    )
    transcripts_are_public_only = all(
        report["visibility"] == "protocol_public_authentication_transcript"
        and not bool(report["contains_secret_z_id"])
        and not bool(report["contains_mask_r"])
        and "z_id" not in report
        and "mask_r" not in report
        for report in transcript_reports.values()
    )
    proof_refresh_public_only = bool(
        proof_refresh_service_audit["active_returns_public_data_only"]
    )

    return {
        "scope": "protocol_public_surface_vs_experiment_secret_data",
        "paper_credential_fields": ["z_id", "Y_id", "pi_id"],
        "credential_public_components": ["Y_id", "pi_id"],
        "published_root_field": "rt",
        "paper_public_proof_refresh_data": ["Y_id", "pi_id", "rt"],
        "paper_public_authentication_transcript": ["pi_id", "w", "c", "s"],
        "experiment_secret_fields": ["z_id", "internal_registration_epoch"],
        "credential_reports_label_secret_z_id": credential_reports_label_secret,
        "credential_reports_match_paper_credential_shape": credential_reports_match_paper_shape,
        "authentication_transcripts_are_public_only": transcripts_are_public_only,
        "proof_refresh_service_returns_public_data_only": proof_refresh_public_only,
        "public_surface_checks_hold": all(
            [
                credential_reports_label_secret,
                credential_reports_match_paper_shape,
                transcripts_are_public_only,
                proof_refresh_public_only,
            ]
        ),
        "note": "Credential reports include z_id and the internal registration epoch only for deterministic experiment reproducibility. Protocol public transcripts and proof-refresh data do not expose z_id, the internal epoch, or the mask r.",
    }


def _role_assumption_model_audit(
    credential_reports,
    transcript_reports,
    setup_key_surface_audit,
    protocol_public_surface_audit,
    proof_refresh_service_audit,
):
    """Audit the paper's logical GCS/UAV/ISM/ISV role boundaries."""
    credential_reports_are_local_secret = all(
        report["visibility"] == "experiment_secret_reproducibility_not_protocol_public"
        and bool(report["contains_secret_z_id"])
        and "z_id" in report
        for report in credential_reports.values()
    )
    credential_reports_omit_trapdoor = all(
        "trapdoor" not in report
        and "msk" not in report
        and "T_A" not in report
        for report in credential_reports.values()
    )
    transcripts_are_public_only = all(
        report["visibility"] == "protocol_public_authentication_transcript"
        and not bool(report["contains_secret_z_id"])
        and not bool(report["contains_mask_r"])
        and "z_id" not in report
        and "mask_r" not in report
        and "trapdoor" not in report
        for report in transcript_reports.values()
    )
    gcs_keeps_master_secret = bool(
        setup_key_surface_audit["master_secret_is_trapdoor_only"]
        and setup_key_surface_audit["master_secret_contains_trapdoor"]
        and setup_key_surface_audit["public_omits_trapdoor"]
    )
    ism_outputs_public_state_only = bool(
        proof_refresh_service_audit["active_returns_public_data_only"]
        and proof_refresh_service_audit["active_path_verifies"]
        and proof_refresh_service_audit["wrong_y_returns_bottom"]
        and proof_refresh_service_audit["revoked_identity_returns_bottom"]
    )
    isv_public_verification_surface = bool(transcripts_are_public_only)
    logical_role_model_checks_hold = all(
        [
            credential_reports_are_local_secret,
            credential_reports_omit_trapdoor,
            transcripts_are_public_only,
            gcs_keeps_master_secret,
            ism_outputs_public_state_only,
            isv_public_verification_surface,
        ]
    )

    return {
        "scope": "paper_system_roles_and_assumption_model",
        "paper_roles": ["GCS", "UAV", "ISM", "ISV"],
        "implementation_model": "single_process_sage_reference_with_logical_role_surfaces",
        "deployment_role_isolation_claim_permitted": False,
        "logical_role_model_checks_hold": logical_role_model_checks_hold,
        "roles": {
            "GCS": {
                "paper_responsibilities": [
                    "Setup",
                    "Register",
                    "credential_generation",
                    "master_secret_key_custody",
                ],
                "role_assumption": "fully_relied_upon_honestly_runs_setup_and_register",
                "secret_fields": ["msk = T_A"],
                "public_outputs": ["pp", "Y_id", "pi_id", "rt"],
                "checks_hold": gcs_keeps_master_secret
                and credential_reports_omit_trapdoor,
                "evidence": [
                    "setup_key_surface_audit",
                    "credentials.*.protocol_public_fields",
                ],
            },
            "UAV": {
                "paper_responsibilities": [
                    "stores_credential",
                    "proves_possession",
                    "does_not_run_trapdoor_operations",
                    "does_not_maintain_state_tree",
                ],
                "role_assumption": "honest_prover_does_not_disclose_credential",
                "local_secret_fields": ["z_id"],
                "public_outputs": ["tau = (pi_id, w, c, s)"],
                "checks_hold": credential_reports_are_local_secret
                and credential_reports_omit_trapdoor
                and transcripts_are_public_only,
                "evidence": [
                    "credentials.*.visibility",
                    "transcripts.*.visibility",
                    "protocol_public_surface_audit.authentication_transcripts_are_public_only",
                ],
            },
            "ISM": {
                "paper_responsibilities": [
                    "maintains_verkle_state",
                    "updates_root_on_register_and_revoke",
                    "publishes_current_root",
                ],
                "role_assumption": "honest_but_curious_state_manager",
                "secret_fields": [],
                "public_outputs": ["rt", "pi_id_refresh_data"],
                "checks_hold": ism_outputs_public_state_only,
                "evidence": [
                    "state_tree_reports.root_transitions",
                    "proof_refresh_service_audit",
                ],
            },
            "ISV": {
                "paper_responsibilities": [
                    "samples_or_accepts_rho",
                    "uses_current_rt",
                    "verifies_tau",
                ],
                "role_assumption": "honest_verifier",
                "secret_fields": [],
                "public_inputs": ["pp", "id", "Y_id", "rho", "rt", "tau"],
                "checks_hold": isv_public_verification_surface,
                "evidence": [
                    "authentication_challenge_audit",
                    "verification_root_parameterization_audit",
                    "protocol_public_surface_audit.authentication_transcripts_are_public_only",
                ],
            },
        },
        "co_location_caveat": (
            "LVCVerkleState stores experiment credentials next to the state tree for "
            "deterministic reproducibility; this is not a deployment role-isolation claim."
        ),
        "all_checks_hold": logical_role_model_checks_hold,
    }


def _paper_correctness_audit(credential_reports, transcript_reports, verification_results):
    credential_checks = {
        name: {
            "sample_pre_equation_holds": bool(
                report["sample_pre_output_report"]["equation_holds"]
            ),
            "credential_norm_bound_holds": int(report["z_id_norm_squared"]) <= int(
                report["beta"]
            )
            * int(report["beta"]),
        }
        for name, report in credential_reports.items()
    }
    transcript_checks = {}
    for name, report in transcript_reports.items():
        generation = report["authentication_generation_report"]
        verification = report["authentication_transcript_report"]
        transcript_checks[name] = {
            "commitment_equation_holds": bool(
                generation["commitment_equation_holds"]
            ),
            "response_relation_holds": bool(
                generation["response_relation_holds"]
            ),
            "response_norm_bound_holds": bool(
                generation["response_norm_bound_holds"]
                and verification["response_norm_bound_holds"]
            ),
            "path_proof_holds": bool(verification["path_proof_holds"]),
            "challenge_matches": bool(verification["challenge_matches"]),
            "verification_equation_holds": bool(verification["equation_holds"]),
            "verifies": bool(verification["verifies"]),
        }

    honest_verification_accepts = all(
        bool(verification_results[name])
        for name in [
            "uav_1_initial_accepts_before_root_update",
            "uav_1_refreshed_accepts_after_register_2",
        ]
    )
    all_credentials_correct = all(
        all(checks.values()) for checks in credential_checks.values()
    )
    all_transcripts_correct = all(
        all(checks.values()) for checks in transcript_checks.values()
    )

    return {
        "scope": "paper_correctness_honest_execution",
        "paper_statement": "Honest UAV credentials and transcripts satisfy A*z_id=Y_id, w=A*r, s=r+c*z_id, and A*s=w+c*Y_id mod q, so Verify accepts.",
        "credential_checks": credential_checks,
        "transcript_checks": transcript_checks,
        "honest_verification_accepts": honest_verification_accepts,
        "all_credentials_correct": all_credentials_correct,
        "all_transcripts_correct": all_transcripts_correct,
        "all_checks_hold": all(
            [
                all_credentials_correct,
                all_transcripts_correct,
                honest_verification_accepts,
            ]
        ),
    }


def _authentication_freshness_model_audit(
    nonce_sampling_audit,
    challenge_reports,
    negative_verification_audit,
    stale_root_verify_parameterization_report,
    refreshed_root_verify_parameterization_report,
    verification_results,
):
    """Audit the paper's freshness boundary for rho and rt."""
    challenge_roots_current = all(
        report["challenge_root_is_current"] for report in challenge_reports
    )
    same_challenge_replay_accepts_stateless_verify = bool(
        verification_results["uav_1_refreshed_accepts_after_register_2"]
    )
    wrong_nonce_rejected = bool(negative_verification_audit["rejects_wrong_nonce"])
    wrong_root_rejected = bool(negative_verification_audit["rejects_tampered_root"])
    stale_root_rejected_by_current_wrapper = bool(
        not stale_root_verify_parameterization_report["current_root_verify_accepts"]
        and not stale_root_verify_parameterization_report["root_is_current"]
    )
    refreshed_root_accepts = bool(
        refreshed_root_verify_parameterization_report["explicit_root_verify_accepts"]
        and refreshed_root_verify_parameterization_report["root_is_current"]
    )
    nonce_sampling_checks_hold = bool(
        nonce_sampling_audit["length_holds"]
        and nonce_sampling_audit["same_seed_reproducible"]
        and nonce_sampling_audit["different_seed_distinct"]
    )

    return {
        "scope": "authentication_freshness_and_replay_boundary",
        "paper_statement": "The ISV samples a fresh rho and current rt; Verify checks the transcript against that local challenge context.",
        "paper_challenge": "(rho, rt)",
        "verify_input": "Verify(pp,id,Y_id,rho,rt,tau)",
        "replay_boundary": (
            "A transcript for the same rho and rt remains a valid mathematical "
            "transcript under stateless Verify; direct replay prevention is "
            "provided by the optional VerifierSession cache."
        ),
        "scheme_verify_is_stateless": True,
        "verifier_nonce_reuse_cache_implemented": True,
        "verifier_replay_cache_backend": "VerifierSession.used_challenges",
        "freshness_assumption_explicit": True,
        "same_challenge_replay_accepts_stateless_verify": (
            same_challenge_replay_accepts_stateless_verify
        ),
        "wrong_nonce_rejected": wrong_nonce_rejected,
        "wrong_root_rejected": wrong_root_rejected,
        "stale_root_rejected_by_current_wrapper": stale_root_rejected_by_current_wrapper,
        "fresh_current_root_accepts": refreshed_root_accepts,
        "challenge_roots_current_when_issued": challenge_roots_current,
        "nonce_sampling_checks_hold": nonce_sampling_checks_hold,
        "nonce_lambda_bits": int(nonce_sampling_audit["lambda_bits"]),
        "all_checks_hold": all(
            [
                same_challenge_replay_accepts_stateless_verify,
                wrong_nonce_rejected,
                wrong_root_rejected,
                stale_root_rejected_by_current_wrapper,
                refreshed_root_accepts,
                challenge_roots_current,
                nonce_sampling_checks_hold,
            ]
        ),
    }


def _paper_scheme_io_audit(
    setup_key_surface_audit,
    credential_reports,
    transcript_reports,
    verification_results,
    root_transition_reports,
    final_state_tree_report,
    revocation_current_credential_surface_audit,
    checks,
    paper_algorithm_audit,
):
    """Audit the formal paper Section 2 algorithm I/O surfaces."""
    credential_shape_holds = all(
        report["paper_credential_fields"] == ["z_id", "Y_id", "pi_id"]
        and report["credential_public_components"] == ["Y_id", "pi_id"]
        and report["published_root_field"] == "rt"
        for report in credential_reports.values()
    )
    transcript_shape_holds = all(
        report["protocol_public_fields"] == ["pi_id", "w", "c", "s"]
        and report["visibility"] == "protocol_public_authentication_transcript"
        and not report["contains_secret_z_id"]
        and not report["contains_mask_r"]
        for report in transcript_reports.values()
    )

    algorithms = [
        {
            "name": "Setup",
            "paper_input": "1^lambda",
            "paper_output": "pp=(A,beta,sigma,H1,H2,b,h,rt0), msk=T_A",
            "sage_entrypoint": "setup_lvc_verkle",
            "evidence": [
                "setup_key_surface_audit",
                "parameters.trap_gen_parameter_report",
                "random_oracle_instantiation_audit",
            ],
            "checks_hold": bool(
                setup_key_surface_audit["public_omits_trapdoor"]
                and setup_key_surface_audit["master_secret_is_trapdoor_only"]
                and setup_key_surface_audit["public_parameter_H1_descriptor_matches"]
                and setup_key_surface_audit["public_parameter_H2_descriptor_matches"]
                and setup_key_surface_audit["public_parameter_rt0_matches_setup_root"]
                and checks["all_trap_gen_relations"]
                and checks["all_random_oracles"]
            ),
        },
        {
            "name": "Register",
            "paper_input": "pp, msk, id",
            "paper_output": "cred_id=(z_id,Y_id,pi_id), current root rt",
            "sage_entrypoint": "register_lvc_verkle_by_identity",
            "evidence": [
                "credentials",
                "state_tree_reports.root_transitions.register_1",
                "state_tree_reports.root_transitions.register_2",
                "sample_pre_input_validation_audit",
            ],
            "checks_hold": bool(
                credential_shape_holds
                and checks["register_identity_only_api_uav_1"]
                and checks["register_identity_only_api_uav_2"]
                and checks["all_sample_pre_outputs"]
                and checks["state_root_changes_register_1"]
                and checks["state_root_changes_register_2"]
            ),
        },
        {
            "name": "Authenticate",
            "paper_input": "cred_id=(z_id,Y_id,pi_id), challenge=(rho,rt)",
            "paper_output": "tau=(pi_id,w,c,s)",
            "sage_entrypoint": "authenticate_lvc_verkle_challenge",
            "evidence": [
                "transcripts",
                "authentication_challenge_audit",
                "authentication_rejection_sampling_audit",
            ],
            "checks_hold": bool(
                transcript_shape_holds
                and checks["all_authentication_challenge_binding"]
                and checks["all_authentication_transcripts"]
            ),
        },
        {
            "name": "Verify",
            "paper_input": "pp,id,Y_id,rho,rt,tau",
            "paper_output": "1 if all checks pass, otherwise 0",
            "sage_entrypoint": "verify_lvc_verkle_at_root",
            "evidence": [
                "verification_results",
                "verification_root_parameterization_audit",
                "negative_verification_audit",
            ],
            "checks_hold": bool(
                checks["all_verification_results"]
                and checks["all_verify_root_parameterization"]
                and checks["all_negative_verification_semantics"]
            ),
        },
        {
            "name": "Revoke",
            "paper_input": "id",
            "paper_output": "new published root rt",
            "sage_entrypoint": "revoke_lvc_verkle",
            "evidence": [
                "state_tree_reports.root_transitions.revoke_1",
                "revocation_current_credential_surface_audit",
                "state_tree_reports.final_state",
            ],
            "checks_hold": bool(
                root_transition_reports["revoke_1"]["root_changed"]
                and final_state_tree_report["revoked_leaf_count"] >= 1
                and revocation_current_credential_surface_audit[
                    "current_credential_removed"
                ]
                and revocation_current_credential_surface_audit[
                    "state_marks_identity_inactive"
                ]
                and checks["state_revoked_path_rejects_after_revoke"]
            ),
        },
    ]
    all_algorithm_io_surfaces_hold = all(
        algorithm["checks_hold"] for algorithm in algorithms
    )

    return {
        "scope": "formal_paper_section_2_algorithm_io",
        "paper_source": "The Proposed LVC-Verkle Scheme, Section 2",
        "purpose": "Bind the Sage reference entrypoints and report evidence to the formal five-algorithm scheme interface.",
        "algorithm_count": len(algorithms),
        "algorithm_names": [algorithm["name"] for algorithm in algorithms],
        "algorithms": algorithms,
        "credential_shape_holds": credential_shape_holds,
        "transcript_shape_holds": transcript_shape_holds,
        "paper_algorithm_audit_passes": bool(paper_algorithm_audit["all_passed"]),
        "verification_results": verification_results,
        "all_algorithm_io_surfaces_hold": all_algorithm_io_surfaces_hold,
        "all_checks_hold": bool(
            all_algorithm_io_surfaces_hold and paper_algorithm_audit["all_passed"]
        ),
    }


def _security_parameter_audit(credentials, auth_parameter_report, lattice_asymptotic_report, checks):
    sample_pre_entries = {}
    for label, credential in credentials.items():
        sample_pre_entries[label] = {
            "sigma_bound_holds": bool(credential.parameter_report["passes_recommended_bound"]),
            "paper_beta_bound_holds": bool(credential.sample_pre_report["paper_beta_bound_holds"]),
            "sampled_output_norm_bound_holds": bool(credential.sample_pre_report["norm_bound_holds"]),
            "sigma_over_recommended": float(credential.sample_pre_report["sigma_over_recommended"]),
            "beta_over_recommended": float(credential.sample_pre_report["beta_over_recommended"]),
        }

    all_sigma_bounds_hold = all(
        entry["sigma_bound_holds"] for entry in sample_pre_entries.values()
    )
    all_paper_beta_bounds_hold = all(
        entry["paper_beta_bound_holds"] for entry in sample_pre_entries.values()
    )
    all_sampled_output_bounds_hold = all(
        entry["sampled_output_norm_bound_holds"] for entry in sample_pre_entries.values()
    )
    response_beta_bound_holds = bool(auth_parameter_report["passes_recommended_bound"])
    q_bound_holds = bool(auth_parameter_report["q_bound_holds"])
    mask_alpha_bound_holds = bool(auth_parameter_report["alpha_dominates_sqrt_log_m"])
    lattice_growth_bound_holds = bool(lattice_asymptotic_report["all_checks_hold"])
    all_asymptotic_parameter_bounds_hold = all(
        [
            lattice_growth_bound_holds,
            all_sigma_bounds_hold,
            all_paper_beta_bounds_hold,
            mask_alpha_bound_holds,
            response_beta_bound_holds,
            q_bound_holds,
        ]
    )

    return {
        "scope": "paper_parameter_section_formulas",
        "parameter_set_status": (
            "paper_asymptotic_bounds_hold"
            if all_asymptotic_parameter_bounds_hold
            else "selected_parameters_do_not_satisfy_all_paper_bounds"
        ),
        "all_asymptotic_parameter_bounds_hold": all_asymptotic_parameter_bounds_hold,
        "all_sampled_output_bounds_hold": all_sampled_output_bounds_hold,
        "sample_pre": {
            "all_sigma_bounds_hold": all_sigma_bounds_hold,
            "all_paper_beta_bounds_hold": all_paper_beta_bounds_hold,
            "credentials": sample_pre_entries,
            "sigma_formula": "sigma_pre >= max_gso_norm * omega_factor",
            "beta_formula": "beta >= sigma_pre * sqrt(m) * omega_factor",
        },
        "lattice_growth": {
            "bound_holds": lattice_growth_bound_holds,
            "formula": lattice_asymptotic_report["formula"],
            "delta_estimate": float(lattice_asymptotic_report["delta_estimate"]),
            "n_delta_proxy": float(lattice_asymptotic_report["n_delta_proxy"]),
            "ceil_log_q_base2": int(lattice_asymptotic_report["ceil_log_q_base2"]),
            "n_delta_over_ceil_log_q_base2": float(
                lattice_asymptotic_report["n_delta_over_ceil_log_q_base2"]
            ),
            "log_q_interpretation": lattice_asymptotic_report["log_q_interpretation"],
        },
        "authentication": {
            "response_beta_bound_holds": response_beta_bound_holds,
            "q_bound_holds": q_bound_holds,
            "beta_response_over_recommended": float(
                auth_parameter_report["beta_response_over_recommended"]
            ),
            "q_over_recommended": float(auth_parameter_report["q_over_recommended"]),
            "mask_alpha_bound_holds": mask_alpha_bound_holds,
            "alpha_sigma_mask": float(auth_parameter_report["alpha_sigma_mask"]),
            "sqrt_log_m": float(auth_parameter_report["sqrt_log_m"]),
            "alpha_over_sqrt_log_m": float(
                auth_parameter_report["alpha_over_sqrt_log_m"]
            ),
            "sigma_mask_formula": auth_parameter_report["sigma_mask_formula"],
            "alpha_formula": auth_parameter_report["alpha_formula"],
            "response_beta_formula": auth_parameter_report["response_beta_formula"],
            "q_bound_formula": auth_parameter_report["q_bound_formula"],
        },
        "algorithmic_checks_still_pass": bool(checks["all_checks"]),
        "note": "A parameter set may pass the lifecycle checks while failing the paper parameter formulas.",
    }


def _conformance_item(name, paper_requirement, implementation_status, evidence, passed, caveat=None):
    item = {
        "name": name,
        "paper_requirement": paper_requirement,
        "implementation_status": implementation_status,
        "evidence": evidence,
        "passed": bool(passed),
    }
    if caveat is not None:
        item["caveat"] = caveat

    return item


def _paper_conformance_report(
    checks,
    paper_algorithm_audit,
    paper_scheme_io_audit,
    authentication_freshness_model_audit,
    security_parameter_audit,
    paper_protocol_clarification_audit,
):
    final_parameter_bounds_hold = bool(
        security_parameter_audit["all_asymptotic_parameter_bounds_hold"]
    )
    algorithmic_checks_hold = bool(checks["all_checks"])
    claim_boundaries = [
        "The sampler is deterministic for experiments and is not constant-time.",
        "Parameters come from the JSON config.",
        "Distributional proofs remain in the paper.",
        "Security-game oracles are outside this implementation.",
    ]

    matrix = [
        _conformance_item(
            "setup_trapgen",
            "Setup runs TrapGen to obtain A and T_A.",
            "implemented_experimental_mp12_g_trapdoor_with_ternary_R_quality_audit",
            [
                "parameters.trap_gen_parameter_report",
                "checks.trap_gen_quality",
                "checks.all_trap_gen_relations",
            ],
            checks["all_trap_gen_relations"],
        ),
        _conformance_item(
            "random_oracles",
            "Setup chooses H1 and H2.",
            "implemented_domain_separated_shake256_random_oracle_instantiation",
            ["random_oracle_instantiation_audit", "checks.all_random_oracles"],
            checks["all_random_oracles"],
        ),
        _conformance_item(
            "sample_pre",
            "Register samples z_id with A*z_id = Y_id mod q and ||z_id|| <= beta.",
            "implemented_experimental_mp12_gpv_klein_style_sampler",
            [
                "credentials.*.sample_pre_output_report",
                "sample_pre_diversity_audit",
                "checks.all_sample_pre_outputs",
                "checks.all_sample_pre_diversity_semantics",
            ],
            checks["all_sample_pre_outputs"]
            and checks["all_sample_pre_diversity_semantics"],
            caveat=claim_boundaries[0],
        ),
        _conformance_item(
            "state_commitment",
            "Register/Verify/Revoke use a position-binding Verkle commitment.",
            "implemented_lattice_linear_verkle_tree_with_Zq_vector_nodes",
            [
                "state_tree_reports.*",
                "state_tree_collision_resolution_audit",
                "state_commitment_backend_audit",
                "checks.all_state_tree_position_binding",
                "checks.all_state_tree_semantics",
            ],
            checks["all_state_tree_position_binding"]
            and checks["all_state_tree_semantics"],
        ),
        _conformance_item(
            "five_algorithms",
            "Setup/Register/Authenticate/Verify/Revoke lifecycle follows the paper.",
            "implemented_sage_lifecycle_api",
            ["paper_algorithm_audit", "checks.all_paper_algorithm_audit"],
            checks["all_paper_algorithm_audit"] and paper_algorithm_audit["all_passed"],
        ),
        _conformance_item(
            "formal_scheme_io",
            "The Sage entrypoints expose the formal paper Section 2 input/output surfaces.",
            "implemented_formal_paper_section_2_algorithm_io_audit",
            ["paper_scheme_io_audit", "checks.paper_scheme_io_audit"],
            checks["paper_scheme_io_audit"]
            and paper_scheme_io_audit["all_checks_hold"],
        ),
        _conformance_item(
            "register_identity_only_api",
            "Register is callable as Register(pp, msk, id), matching the paper algorithm input.",
            "implemented_register_lvc_verkle_by_identity_wrapper",
            [
                "checks.register_identity_only_api_uav_1",
                "checks.register_identity_only_api_uav_2",
            ],
            checks["register_identity_only_api_uav_1"]
            and checks["register_identity_only_api_uav_2"],
        ),
        _conformance_item(
            "correctness",
            "Honest credentials and transcripts satisfy the paper correctness equations and Verify accepts.",
            "implemented_paper_correctness_audit",
            ["paper_correctness_audit", "checks.all_paper_correctness"],
            checks["all_paper_correctness"],
        ),
        _conformance_item(
            "protocol_public_surface",
            "Public registration and authentication outputs do not expose z_id or mask r.",
            "implemented_public_surface_audit_with_experiment_secret_labels",
            ["protocol_public_surface_audit", "checks.all_protocol_public_surface"],
            checks["all_protocol_public_surface"],
        ),
        _conformance_item(
            "system_roles_and_assumption_model",
            "GCS, UAV, ISM, and ISV follow the logical responsibilities and visibility assumptions in the paper.",
            "implemented_logical_role_surface_audit_not_deployment_isolation",
            ["role_assumption_model_audit", "checks.role_assumption_model_logical_surface"],
            checks["role_assumption_model_logical_surface"],
        ),
        _conformance_item(
            "authentication_challenge_binding",
            "Authenticate uses the ISV challenge (rho, rt) with rt equal to the current root.",
            "implemented_explicit_authentication_challenge_object",
            ["authentication_challenge_audit", "checks.all_authentication_challenge_binding"],
            checks["all_authentication_challenge_binding"],
        ),
        _conformance_item(
            "authentication_freshness_model",
            "Freshness uses verifier-selected rho and the current root rt.",
            "implemented_freshness_boundary_audit_with_verifier_session_cache",
            [
                "authentication_freshness_model_audit",
                "checks.auth_freshness_model_boundary",
            ],
            checks["auth_freshness_model_boundary"]
            and authentication_freshness_model_audit["all_checks_hold"],
            caveat="Verify is stateless; VerifierSession rejects repeated challenges.",
        ),
        _conformance_item(
            "authentication_nonce_sampling",
            "The ISV samples rho from {0,1}^lambda.",
            "implemented_reproducible_domain_separated_lambda_bit_nonce_sampler",
            ["authentication_nonce_sampling_audit", "checks.all_authentication_challenge_binding"],
            checks["all_authentication_challenge_binding"],
        ),
        _conformance_item(
            "verify_explicit_root",
            "Verify takes rt explicitly as in Verify(pp,id,Y_id,rho,rt,tau), and experiments check membership under the supplied current root.",
            "implemented_explicit_root_verify_api_with_current_root_wrapper",
            ["verification_root_parameterization_audit", "checks.all_verify_root_parameterization"],
            checks["all_verify_root_parameterization"],
        ),
        _conformance_item(
            "negative_verification",
            "Verify rejects nonce, root, identity, challenge, commitment, and response tampering.",
            "implemented_negative_verification_audit",
            ["negative_verification_audit", "checks.all_negative_verification_semantics"],
            checks["all_negative_verification_semantics"],
        ),
        _conformance_item(
            "malformed_transcript_rejection",
            "Verify outputs 0 for malformed tau inputs rather than accepting or crashing.",
            "implemented_authentication_transcript_input_validation_audit",
            [
                "authentication_transcript_input_validation_audit",
                "checks.verify_rejects_malformed_transcripts",
            ],
            checks["verify_rejects_malformed_transcripts"],
        ),
        _conformance_item(
            "parameter_formulas",
            "Parameters satisfy SamplePre, response, and SIS lower-bound formulas.",
            security_parameter_audit["parameter_set_status"],
            ["security_parameter_audit"],
            final_parameter_bounds_hold,
            caveat=claim_boundaries[1],
        ),
        _conformance_item(
            "paper_protocol_conventions",
            "The implementation records the protocol conventions used by the Sage reference.",
            "sage_protocol_conventions_are_machine_readable",
            ["paper_protocol_clarification_audit"],
            paper_protocol_clarification_audit["all_items_have_sage_evidence"],
        ),
    ]

    required_implemented_items_hold = all(
        item["passed"]
        for item in matrix
        if item["name"] != "parameter_formulas"
    )
    paper_experiment_support_permitted = bool(
        algorithmic_checks_hold
        and required_implemented_items_hold
        and paper_algorithm_audit["all_passed"]
    )

    return {
        "scope": "paper_to_sage_conformance_matrix",
        "academic_open_source_status": "research_reference",
        "paper_experiment_support_status": (
            "supports_paper_algorithms"
            if paper_experiment_support_permitted
            else "paper_experiment_support_incomplete"
        ),
        "paper_experiment_support_permitted": paper_experiment_support_permitted,
        "proof_obligations_are_out_of_scope_for_code": True,
        "security_game_oracle_behavior_excluded": True,
        "implemented_security_game_oracles": [],
        "all_algorithmic_conformance_checks_hold": algorithmic_checks_hold,
        "required_implemented_items_hold": required_implemented_items_hold,
        "final_parameter_bounds_hold": final_parameter_bounds_hold,
        "production_crypto_claim_permitted": False,
        "matrix": matrix,
        "claim_boundaries": claim_boundaries,
        "claim_boundary_count": int(len(claim_boundaries)),
        "open_implementation_gaps": [],
        "open_implementation_gap_count": int(0),
        "audit_complete": True,
        "note": "The report covers implementation checks; proofs are separate.",
    }


def _proof_refresh_audit(
    stale_path_report,
    refreshed_path_report,
    stale_verify,
    refreshed_verify,
    root_before_update,
    root_after_update,
):
    stale_path_rejected = not bool(stale_path_report["verifies_active_path"])
    refreshed_path_accepts = bool(refreshed_path_report["verifies_active_path"])
    stale_transcript_rejected = not bool(stale_verify)
    refreshed_transcript_accepts = bool(refreshed_verify)

    return {
        "scope": "dynamic_root_path_proof_refresh",
        "protocol_assumption": "UAVs need a current pi_id path proof after unrelated root updates.",
        "root_changed": root_before_update != root_after_update,
        "stale_path_rejected_under_new_root": stale_path_rejected,
        "refreshed_path_accepts_under_new_root": refreshed_path_accepts,
        "stale_transcript_rejected_under_new_root": stale_transcript_rejected,
        "refreshed_transcript_accepts_under_new_root": refreshed_transcript_accepts,
        "proof_refresh_required": (root_before_update != root_after_update) and stale_path_rejected,
        "proof_refresh_service_restores_authentication": (
            refreshed_path_accepts and refreshed_transcript_accepts
        ),
        "all_checks_hold": all(
            [
                root_before_update != root_after_update,
                stale_path_rejected,
                refreshed_path_accepts,
                stale_transcript_rejected,
                refreshed_transcript_accepts,
            ]
        ),
    }


def _proof_refresh_service_audit(
    active_refresh_data,
    wrong_y_refresh_data,
    revoked_refresh_data,
    identity,
    y_id,
    root,
    tree_params,
):
    active_returns_public_data = (
        active_refresh_data is not None
        and hasattr(active_refresh_data, "y_id")
        and hasattr(active_refresh_data, "path_proof")
        and hasattr(active_refresh_data, "root")
        and not hasattr(active_refresh_data, "z_id")
        and not hasattr(active_refresh_data, "credential")
        and not hasattr(active_refresh_data, "trapdoor")
    )
    active_root_is_current = (
        active_refresh_data is not None
        and active_refresh_data.root == root
    )
    active_path_verifies = (
        active_refresh_data is not None
        and verify_verkle_path(
            identity,
            y_id,
            active_refresh_data.path_proof,
            root,
            tree_params,
        )
    )
    wrong_y_returns_bottom = wrong_y_refresh_data is None
    revoked_returns_bottom = revoked_refresh_data is None

    return {
        "scope": "public_proof_refresh_service",
        "paper_assumption": "UAVs can obtain a current pi_id for the published root rt without learning new secrets.",
        "service_output": "(Y_id, pi_id, rt) or bottom",
        "active_refresh_data": (
            _proof_refresh_public_data_report(active_refresh_data, tree_params)
            if active_refresh_data is not None
            else None
        ),
        "active_returns_public_data_only": active_returns_public_data,
        "active_root_is_current": active_root_is_current,
        "active_path_verifies": active_path_verifies,
        "wrong_y_returns_bottom": wrong_y_returns_bottom,
        "revoked_identity_returns_bottom": revoked_returns_bottom,
        "all_checks_hold": all(
            [
                active_returns_public_data,
                active_root_is_current,
                active_path_verifies,
                wrong_y_returns_bottom,
                revoked_returns_bottom,
            ]
        ),
        "note": "This is a public path-proof refresh service for dynamic roots; it does not issue or recompute z_id.",
    }


def _revocation_current_credential_surface_audit(
    state,
    identity,
    revoked_credential,
    revoked_refresh_data,
):
    identity = _as_bytes(identity)
    current_credential_removed = identity not in state.credentials_by_identity
    history = state.credential_history_by_identity.get(identity, [])
    history_preserves_revoked_credential = any(
        credential is revoked_credential for credential in history
    )
    state_marks_identity_inactive = not identity_active_in_state(state, identity)
    proof_refresh_returns_bottom = revoked_refresh_data is None

    return {
        "scope": "revocation_current_credential_surface",
        "paper_statement": "Revoke marks an identity inactive and publishes a new root; revoked credentials are not current active credentials.",
        "identity_hex": _bytes_hex(identity),
        "current_credential_removed": current_credential_removed,
        "history_preserves_revoked_credential": history_preserves_revoked_credential,
        "history_count": int(len(history)),
        "state_marks_identity_inactive": state_marks_identity_inactive,
        "proof_refresh_returns_bottom": proof_refresh_returns_bottom,
        "all_checks_hold": all(
            [
                current_credential_removed,
                history_preserves_revoked_credential,
                state_marks_identity_inactive,
                proof_refresh_returns_bottom,
            ]
        ),
        "note": "The Sage state keeps credential history for reproducibility but removes revoked identities from the current credential map.",
    }


def _paper_step(label, passed, evidence, note=None):
    step = {
        "label": label,
        "passed": bool(passed),
        "evidence": evidence,
    }
    if note is not None:
        step["note"] = note

    return step


def _paper_algorithm_audit(checks, verification_results):
    algorithms = {
        "setup": {
            "paper_algorithm": "Setup",
            "steps": [
                _paper_step(
                    "choose lattice, norm, sampling, and tree parameters",
                    True,
                    ["parameters.lattice", "parameters.authentication", "parameters.state_tree"],
                ),
                _paper_step(
                    "run TrapGen to obtain A and T_A",
                    checks["all_trap_gen_relations"],
                    ["parameters.trap_gen_parameter_report", "checks.all_trap_gen_relations"],
                ),
                _paper_step(
                    "instantiate H1 and H2 random oracles",
                    True,
                    ["implementation_status.challenge_space_instantiation", "reference/sage/test_random_oracles.sage"],
                    note="H1/H2 are domain-separated SHAKE256 random-oracle instantiations.",
                ),
                _paper_step(
                    "initialize empty state tree root rt0",
                    True,
                    ["roots.initial", "parameters.state_tree"],
                    note="Current state tree is the lattice-linear Verkle tree over Z_q^n vectors.",
                ),
            ],
        },
        "register": {
            "paper_algorithm": "Register",
            "steps": [
                _paper_step(
                    "accept paper input Register(pp, msk, id)",
                    checks["register_identity_only_api_uav_1"]
                    and checks["register_identity_only_api_uav_2"],
                    [
                        "checks.register_identity_only_api_uav_1",
                        "checks.register_identity_only_api_uav_2",
                    ],
                    note="The internal epoch is domain-separated by identity to instantiate Y_id = H1(id || epoch).",
                ),
                _paper_step(
                    "compute Y_id = H1(id || epoch)",
                    True,
                    ["credentials.uav_1_refreshed.y_id", "credentials.uav_2.y_id"],
                ),
                _paper_step(
                    "sample short z_id with A*z_id = Y_id mod q",
                    checks["all_sample_pre_outputs"],
                    ["credentials.*.sample_pre_output_report", "checks.all_sample_pre_outputs"],
                    note="Sampler is the current experimental MP12 GPV/Klein-style SamplePre path.",
                ),
                _paper_step(
                    "insert (id, Y_id), generate pi_id, and update root",
                    checks["state_root_changes_register_1"] and checks["state_root_changes_register_2"],
                    ["state_tree_reports.root_transitions.register_1", "state_tree_reports.root_transitions.register_2"],
                ),
                _paper_step(
                    "resolve finite experimental leaf-index collisions by deterministic slot probing",
                    all(
                        [
                            checks["state_tree_collision_initial_indices_collide"],
                            checks["state_tree_collision_uses_nonzero_probe"],
                            checks["state_tree_collision_assigned_indices_distinct"],
                            checks["state_tree_collision_paths_verify"],
                        ]
                    ),
                    ["state_tree_collision_resolution_audit"],
                    note="This keeps the finite tree experiment from aborting on identity-index collisions.",
                ),
                _paper_step(
                    "bind pi_id to the registered position and Y_id",
                    checks["all_state_tree_position_binding"],
                    [
                        "state_tree_reports.uav_1_initial_position_binding",
                        "state_tree_reports.uav_1_refreshed_position_binding_after_register_2",
                    ],
                    note="This is checked against the lattice-linear Verkle path proof.",
                ),
                _paper_step(
                    "credential contains z_id, Y_id, pi_id",
                    checks["state_refreshed_path_accepts_after_register_2"],
                    ["credentials.uav_1_refreshed", "state_tree_reports.uav_1_refreshed_path_after_register_2"],
                ),
                _paper_step(
                    "obtain current pi_id from a public proof-refresh service after root changes",
                    checks["all_proof_refresh_semantics"],
                    ["proof_refresh_service_audit", "proof_refresh_audit"],
                    note="The service returns only public (Y_id, pi_id, rt) data; the UAV keeps z_id locally.",
                ),
            ],
        },
        "authenticate": {
            "paper_algorithm": "Authenticate",
            "steps": [
                _paper_step(
                    "receive explicit ISV challenge (rho, rt)",
                    checks["all_authentication_challenge_binding"],
                    ["authentication_challenge_audit"],
                    note="The Sage challenge object binds each authentication to the current published root.",
                ),
                _paper_step(
                    "sample mask r and compute w = A*r mod q",
                    True,
                    [
                        "transcripts.uav_1_initial.authentication_generation_report",
                        "transcripts.uav_1_refreshed.authentication_generation_report",
                    ],
                    note="The sampled r vector is not retained in the public report; only sampler metadata and mask norm are recorded.",
                ),
                _paper_step(
                    "compute Fiat-Shamir challenge c = H2(Y_id || w || rho || rt || id)",
                    checks["all_authentication_transcripts"],
                    ["transcripts.*.authentication_transcript_report.challenge_matches"],
                ),
                _paper_step(
                    "compute response s and enforce ||s|| <= beta'",
                    checks["response_norm_bound_uav_1_initial"] and checks["response_norm_bound_uav_1_refreshed"],
                    ["transcripts.*.authentication_transcript_report.response_norm_bound_holds"],
                ),
                _paper_step(
                    "output tau = (pi_id, w, c, s)",
                    checks["all_authentication_transcripts"],
                    ["transcripts.uav_1_initial", "transcripts.uav_1_refreshed"],
                ),
            ],
        },
        "verify": {
            "paper_algorithm": "Verify",
            "steps": [
                _paper_step(
                    "take rt explicitly in Verify(pp,id,Y_id,rho,rt,tau)",
                    checks["all_verify_root_parameterization"],
                    ["verification_root_parameterization_audit"],
                    note="The high-level Sage API now has explicit-root and current-root Verify entrypoints.",
                ),
                _paper_step(
                    "verify path proof under current root",
                    checks["all_authentication_transcripts"],
                    ["transcripts.*.authentication_transcript_report.path_proof_holds"],
                ),
                _paper_step(
                    "recompute challenge and compare",
                    checks["all_authentication_transcripts"],
                    ["transcripts.*.authentication_transcript_report.challenge_matches"],
                ),
                _paper_step(
                    "check A*s = w + c*Y_id mod q and ||s|| <= beta'",
                    checks["all_authentication_transcripts"],
                    ["transcripts.*.authentication_transcript_report.equation_holds", "checks.all_bounds"],
                ),
                _paper_step(
                    "reject nonce, root, identity, challenge, commitment, and response tampering",
                    checks["all_negative_verification_semantics"],
                    ["negative_verification_audit"],
                ),
                _paper_step(
                    "accept valid transcript and reject stale/revoked transcript",
                    checks["all_verification_results"],
                    ["verification_results"],
                ),
            ],
        },
        "revoke": {
            "paper_algorithm": "Revoke",
            "steps": [
                _paper_step(
                    "mark id revoked in the state tree",
                    checks["state_final_revoked_count"],
                    ["state_tree_reports.final_state.revoked_leaf_count"],
                ),
                _paper_step(
                    "publish a new root",
                    checks["state_root_changes_revoke_1"],
                    ["state_tree_reports.root_transitions.revoke_1"],
                ),
                _paper_step(
                    "reject old active proof under revoked root",
                    checks["state_revoked_path_rejects_after_revoke"],
                    ["state_tree_reports.uav_1_path_after_revoke", "verification_results.uav_1_rejects_after_revoke"],
                ),
            ],
        },
    }

    for algorithm in algorithms.values():
        algorithm["passed"] = all(step["passed"] for step in algorithm["steps"])

    return {
        "scope": "paper_section_2_five_algorithm_lifecycle",
        "all_passed": all(algorithm["passed"] for algorithm in algorithms.values()),
        "algorithms": algorithms,
        "implementation_notes": [
            "SamplePre uses the MP12 GPV/Klein-style sampler.",
            "Challenges use the centered scalar space C_lambda.",
        ],
    }


def _config_section(config, name):
    if name not in config or not isinstance(config[name], dict):
        raise ValueError("configuration must contain object section '%s'" % name)
    return config[name]


def _validate_allowed_keys(section, allowed_keys, section_name):
    unknown_keys = sorted([key for key in section if key not in allowed_keys])
    if unknown_keys:
        raise ValueError(
            "configuration section '%s' contains unknown keys: %s"
            % (section_name, ", ".join(unknown_keys))
        )


def _validate_optional_string_field(section, section_name, name):
    if name in section and not isinstance(section[name], str):
        raise ValueError(
            "configuration section '%s' field '%s' must be a string"
            % (section_name, name)
        )


def _validate_integer_field(section, section_name, name, minimum=None):
    if name not in section:
        return

    value = section[name]
    if isinstance(value, bool) or not isinstance(value, (int, Integer)):
        raise ValueError(
            "configuration section '%s' field '%s' must be an integer"
            % (section_name, name)
        )
    if minimum is not None and value < minimum:
        raise ValueError(
            "configuration section '%s' field '%s' must be >= %s"
            % (section_name, name, minimum)
        )


def _validate_number_field(section, section_name, name, positive=False):
    if name not in section:
        return

    value = section[name]
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError(
            "configuration section '%s' field '%s' must be a number"
            % (section_name, name)
        )
    if not isfinite(float(value)):
        raise ValueError(
            "configuration section '%s' field '%s' must be finite"
            % (section_name, name)
        )
    if positive and value <= 0:
        raise ValueError(
            "configuration section '%s' field '%s' must be > 0"
            % (section_name, name)
        )


def _validate_odd_integer_field(section, section_name, name):
    if name not in section:
        return

    if ZZ(section[name]) % 2 == 0:
        raise ValueError(
            "configuration section '%s' field '%s' must be an odd challenge_modulus for centered scalar challenges"
            % (section_name, name)
        )


def _validate_experiment_config_types(lattice, sample_pre, tree, authentication):
    for field in ["n", "m_bar"]:
        _validate_integer_field(lattice, "lattice", field, minimum=1)
    for field in ["q", "base"]:
        _validate_integer_field(lattice, "lattice", field, minimum=2)

    for field in ["beta", "tail_cutoff"]:
        _validate_integer_field(sample_pre, "sample_pre", field, minimum=1)
    for field in ["sigma_pre", "omega_factor"]:
        _validate_number_field(sample_pre, "sample_pre", field, positive=True)

    _validate_integer_field(tree, "tree", "branching_factor", minimum=2)
    _validate_integer_field(tree, "tree", "height", minimum=1)

    _validate_integer_field(authentication, "authentication", "challenge_modulus", minimum=3)
    _validate_odd_integer_field(authentication, "authentication", "challenge_modulus")
    for field in ["beta_response", "max_attempts", "nonce_bytes", "mask_tail_cutoff"]:
        _validate_integer_field(authentication, "authentication", field, minimum=1)
    for field in ["sigma_mask", "omega_factor"]:
        _validate_number_field(authentication, "authentication", field, positive=True)


def _validate_experiment_config(config):
    _validate_allowed_keys(config, EXPERIMENT_TOP_LEVEL_KEYS, "top_level")
    _validate_optional_string_field(config, "top_level", "description")
    if config.get("format") != EXPERIMENT_CONFIG_FORMAT:
        raise ValueError(
            "configuration 'format' must be '%s'" % EXPERIMENT_CONFIG_FORMAT
        )
    if "name" not in config or not isinstance(config["name"], str) or not config["name"]:
        raise ValueError("configuration must contain non-empty string 'name'")
    lattice = _config_section(config, "lattice")
    sample_pre = _config_section(config, "sample_pre")
    tree = _config_section(config, "tree")
    authentication = _config_section(config, "authentication")
    _validate_allowed_keys(lattice, LATTICE_CONFIG_KEYS, "lattice")
    _validate_allowed_keys(
        sample_pre,
        SAMPLE_PRE_CONFIG_KEYS,
        "sample_pre",
    )
    _validate_allowed_keys(tree, TREE_CONFIG_KEYS, "tree")
    _validate_allowed_keys(
        authentication,
        AUTHENTICATION_CONFIG_KEYS,
        "authentication",
    )
    _validate_experiment_config_types(lattice, sample_pre, tree, authentication)


def _required_value(section, section_name, name):
    if name not in section:
        raise ValueError("configuration section '%s' missing '%s'" % (section_name, name))
    return section[name]


def _canonical_json_sha256_hex(value):
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode("utf-8")).hexdigest()


def _file_sha256_hex(path):
    digest = sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(8192)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _load_json_schema(path):
    with open(path, "r") as handle:
        return json.load(handle)


def _schema_object_keys(schema_object):
    return set(schema_object.get("properties", {}).keys())


def _schema_required_keys(schema_object):
    return set(schema_object.get("required", []))


def _schema_challenge_modulus_requires_odd(auth_schema):
    challenge_schema = auth_schema.get("properties", {}).get("challenge_modulus", {})
    return challenge_schema.get("not", {}).get("multipleOf") == 2


def _schema_optional_metadata_fields_are_strings(schema_object):
    properties = schema_object.get("properties", {})
    return all(
        properties[field].get("type") == "string"
        for field in ["description"]
        if field in properties
    )


def _schema_refers_to(schema_property, definition_name):
    return schema_property.get("$ref") == "#/$defs/%s" % definition_name


def _schema_numeric_bound_constraints_match(defs):
    positive_integer_matches = (
        defs["positiveInteger"].get("type") == "integer"
        and defs["positiveInteger"].get("minimum") == 1
    )
    positive_number_matches = (
        defs["positiveNumber"].get("type") == "number"
        and defs["positiveNumber"].get("exclusiveMinimum") == 0
    )
    lattice = defs["lattice"]["properties"]
    sample_pre = defs["sample_pre"]["properties"]
    tree = defs["tree"]["properties"]
    authentication = defs["authentication"]["properties"]

    return all(
        [
            positive_integer_matches,
            positive_number_matches,
            _schema_refers_to(lattice["n"], "positiveInteger"),
            lattice["q"].get("type") == "integer",
            lattice["q"].get("minimum") == 2,
            lattice["base"].get("type") == "integer",
            lattice["base"].get("minimum") == 2,
            _schema_refers_to(lattice["m_bar"], "positiveInteger"),
            _schema_refers_to(sample_pre["beta"], "positiveInteger"),
            _schema_refers_to(sample_pre["sigma_pre"], "positiveNumber"),
            _schema_refers_to(sample_pre["omega_factor"], "positiveNumber"),
            _schema_refers_to(sample_pre["tail_cutoff"], "positiveInteger"),
            tree["branching_factor"].get("type") == "integer",
            tree["branching_factor"].get("minimum") == 2,
            _schema_refers_to(tree["height"], "positiveInteger"),
            authentication["challenge_modulus"].get("type") == "integer",
            authentication["challenge_modulus"].get("minimum") == 3,
            _schema_refers_to(authentication["sigma_mask"], "positiveNumber"),
            _schema_refers_to(authentication["omega_factor"], "positiveNumber"),
            _schema_refers_to(authentication["beta_response"], "positiveInteger"),
            _schema_refers_to(authentication["max_attempts"], "positiveInteger"),
            _schema_refers_to(authentication["nonce_bytes"], "positiveInteger"),
            _schema_refers_to(authentication["mask_tail_cutoff"], "positiveInteger"),
        ]
    )


def _schema_alignment_audit():
    schema = _load_json_schema(EXPERIMENT_CONFIG_SCHEMA_PATH)
    defs = schema.get("$defs", {})
    implementation_section_keys = {
        "lattice": LATTICE_CONFIG_KEYS,
        "sample_pre": SAMPLE_PRE_CONFIG_KEYS,
        "tree": TREE_CONFIG_KEYS,
        "authentication": AUTHENTICATION_CONFIG_KEYS,
    }
    section_key_matches = {
        name: sorted(_schema_object_keys(defs[name]))
        == sorted(implementation_section_keys[name])
        for name in implementation_section_keys
    }
    section_required_matches = {
        name: sorted(_schema_required_keys(defs[name]))
        == sorted(implementation_section_keys[name])
        for name in implementation_section_keys
    }
    schema_additional_properties_disabled = all(
        [
            schema.get("additionalProperties") is False,
            defs["lattice"].get("additionalProperties") is False,
            defs["sample_pre"].get("additionalProperties") is False,
            defs["tree"].get("additionalProperties") is False,
            defs["authentication"].get("additionalProperties") is False,
        ]
    )
    format_matches = (
        schema.get("properties", {}).get("format", {}).get("const")
        == EXPERIMENT_CONFIG_FORMAT
    )
    top_level_keys_match = sorted(_schema_object_keys(schema)) == sorted(
        EXPERIMENT_TOP_LEVEL_KEYS
    )
    top_level_required_match = sorted(_schema_required_keys(schema)) == sorted(
        ["format", "name", "lattice", "sample_pre", "tree", "authentication"]
    )
    challenge_modulus_odd_constraint_matches = _schema_challenge_modulus_requires_odd(
        defs["authentication"]
    )
    optional_metadata_string_constraints_match = (
        _schema_optional_metadata_fields_are_strings(schema)
    )
    numeric_bound_constraints_match = _schema_numeric_bound_constraints_match(defs)

    return {
        "scope": "explicit_json_config_schema_alignment",
        "schema_path": EXPERIMENT_CONFIG_SCHEMA_PATH,
        "schema_sha256": _file_sha256_hex(EXPERIMENT_CONFIG_SCHEMA_PATH),
        "format_matches_schema_const": format_matches,
        "top_level_keys_match_schema": top_level_keys_match,
        "top_level_required_keys_match_schema": top_level_required_match,
        "section_keys_match_schema": section_key_matches,
        "section_required_keys_match_schema": section_required_matches,
        "schema_additional_properties_disabled": schema_additional_properties_disabled,
        "challenge_modulus_odd_constraint_matches_schema": (
            challenge_modulus_odd_constraint_matches
        ),
        "optional_metadata_string_constraints_match_schema": (
            optional_metadata_string_constraints_match
        ),
        "numeric_bound_constraints_match_schema": numeric_bound_constraints_match,
        "manual_validation_backend": "sage_reference_manual_json_validation",
        "third_party_jsonschema_dependency": False,
        "all_checks_hold": all(
            [
                format_matches,
                top_level_keys_match,
                top_level_required_match,
                schema_additional_properties_disabled,
                challenge_modulus_odd_constraint_matches,
                optional_metadata_string_constraints_match,
                numeric_bound_constraints_match,
                all(section_key_matches.values()),
                all(section_required_matches.values()),
            ]
        ),
    }


def _setup_params_from_config(config):
    _validate_experiment_config(config)
    lattice = _config_section(config, "lattice")
    sample_pre = _config_section(config, "sample_pre")
    tree = _config_section(config, "tree")
    authentication = _config_section(config, "authentication")

    auth_kwargs = {
        "challenge_modulus": _required_value(
            authentication,
            "authentication",
            "challenge_modulus",
        ),
        "sigma_mask": _required_value(authentication, "authentication", "sigma_mask"),
        "beta_response": _required_value(
            authentication,
            "authentication",
            "beta_response",
        ),
        "max_attempts": _required_value(
            authentication,
            "authentication",
            "max_attempts",
        ),
        "nonce_bytes": _required_value(
            authentication,
            "authentication",
            "nonce_bytes",
        ),
    }

    return LVCVerkleSetupParameters(
        lattice_params=MP12GadgetParameters(
            n=_required_value(lattice, "lattice", "n"),
            q=_required_value(lattice, "lattice", "q"),
            base=_required_value(lattice, "lattice", "base"),
            m_bar=_required_value(lattice, "lattice", "m_bar"),
        ),
        beta=_required_value(sample_pre, "sample_pre", "beta"),
        sigma_pre=_required_value(sample_pre, "sample_pre", "sigma_pre"),
        tree_params=VerkleTreeParameters(
            branching_factor=_required_value(tree, "tree", "branching_factor"),
            height=_required_value(tree, "tree", "height"),
        ),
        auth_params=AuthenticationParameters(**auth_kwargs),
        omega_factor=_required_value(sample_pre, "sample_pre", "omega_factor"),
        auth_omega_factor=_required_value(
            authentication,
            "authentication",
            "omega_factor",
        ),
        sample_pre_tail_cutoff=_required_value(
            sample_pre,
            "sample_pre",
            "tail_cutoff",
        ),
        mask_tail_cutoff=_required_value(
            authentication,
            "authentication",
            "mask_tail_cutoff",
        ),
    )


def load_experiment_config(path):
    with open(path, "r") as handle:
        config = json.load(handle)
    if not isinstance(config, dict):
        raise ValueError("experiment configuration must be a JSON object")
    _validate_experiment_config(config)
    return config


def _configuration_report(config, config_path):
    return {
        "format": config.get("format", EXPERIMENT_CONFIG_FORMAT),
        "name": config.get("name", None),
        "schema_path": EXPERIMENT_CONFIG_SCHEMA_PATH,
        "schema_sha256": _file_sha256_hex(EXPERIMENT_CONFIG_SCHEMA_PATH),
        "schema_alignment_audit": _schema_alignment_audit(),
        "source_path": None if config_path is None else os.path.abspath(config_path),
        "config_canonical_sha256": _canonical_json_sha256_hex(config),
        "explicit_config_required": True,
    }


def run_experiment(config=None, config_path=None, strict_parameters=False):
    if config is None:
        raise ValueError(
            "run_experiment requires an explicit JSON configuration; "
            "see --help or reference/configs/nist_experiment.json"
        )

    seeds = {
        "setup": [b"experiment-setup-v1"],
        "register_1": [b"experiment-register-uav-001"],
        "register_2": [b"experiment-register-uav-002"],
        "auth_1": [b"experiment-auth-uav-001-root-1"],
        "auth_1_refreshed": [b"experiment-auth-uav-001-root-2"],
        "auth_1_fresh_challenge": [b"experiment-auth-uav-001-fresh-challenge"],
        "nonce_1": [b"experiment-nonce-uav-001-root-1"],
        "nonce_1_refreshed": [b"experiment-nonce-uav-001-root-2"],
        "nonce_1_fresh_challenge": [b"experiment-nonce-uav-001-fresh-challenge"],
    }
    identities = [b"UAV-EXP-001", b"UAV-EXP-002"]

    setup_params = _setup_params_from_config(config)
    pp, msk, state = setup_lvc_verkle(setup_params, seeds["setup"])
    initial_root = pp.root
    sampler_parameter_audit = sampler_parameter_audit_report(
        pp,
        parameter_set_label=config.get("name"),
        explicit_config_required=True,
    )
    setup_key_surface_audit = setup_key_surface_report(pp, msk, state)
    trap_gen_report = mp12_trap_gen_parameter_report(pp.A, msk.trapdoor, pp.lattice_params)
    trap_gen_multi_seed = trap_gen_multi_seed_audit(
        pp.lattice_params,
        [b"experiment"],
    )
    lattice_asymptotic_report = paper_lattice_asymptotic_parameter_report(pp.lattice_params)
    auth_parameter_report = authentication_parameter_report(
        pp.lattice_params,
        pp.auth_params,
        pp.beta,
        omega_factor=pp.auth_omega_factor,
    )
    parameter_preflight = _parameter_preflight_report(
        state.sample_pre_context.parameter_report,
        auth_parameter_report,
    )
    if strict_parameters and not parameter_preflight["all_paper_parameter_bounds_hold"]:
        raise ValueError("parameter preflight failed in strict mode")
    random_oracle_audit = random_oracle_instantiation_report(
        pp.lattice_params,
        pp.auth_params,
    )

    credential_1, root_after_register_1 = register_lvc_verkle_by_identity(
        pp,
        msk,
        state,
        identities[0],
        seeds["register_1"],
    )
    register_identity_only_epoch_1 = registration_epoch_for_identity(identities[0])
    register_identity_only_api_1 = credential_1.epoch == register_identity_only_epoch_1
    credential_1_initial_path_proof = credential_1.path_proof
    credential_1_initial_position_binding_report = lattice_verkle_position_binding_report(
        identities[0],
        credential_1.y_id,
        credential_1_initial_path_proof,
        root_after_register_1,
        pp.tree_params,
    )
    nonce_sampling_audit = authentication_nonce_sampling_report(
        pp.auth_params,
        seeds["nonce_1"],
    )
    challenge_1 = issue_sampled_authentication_challenge(pp, seeds["nonce_1"])
    challenge_1_report = authentication_challenge_report(pp, state, challenge_1)
    transcript_1 = authenticate_lvc_verkle_challenge(
        pp,
        credential_1,
        identities[0],
        challenge_1,
        seeds["auth_1"],
    )
    verify_1 = verify_lvc_verkle(
        pp,
        identities[0],
        credential_1.y_id,
        challenge_1.nonce,
        transcript_1,
    )

    credential_2, root_after_register_2 = register_lvc_verkle_by_identity(
        pp,
        msk,
        state,
        identities[1],
        seeds["register_2"],
    )
    register_identity_only_epoch_2 = registration_epoch_for_identity(identities[1])
    register_identity_only_api_2 = credential_2.epoch == register_identity_only_epoch_2
    stale_verify_1 = verify_lvc_verkle(
        pp,
        identities[0],
        credential_1.y_id,
        challenge_1.nonce,
        transcript_1,
    )
    credential_1_stale_path_report = lattice_verkle_path_report(
        identities[0],
        credential_1.y_id,
        credential_1.path_proof,
        root_after_register_2,
        pp.tree_params,
    )
    active_proof_refresh_data = proof_refresh_service(
        pp,
        state,
        identities[0],
        credential_1.y_id,
    )
    wrong_y_proof_refresh_data = proof_refresh_service(
        pp,
        state,
        identities[0],
        _tamper_zq_vector_first_coordinate(credential_1.y_id),
    )
    credential_1 = apply_proof_refresh_to_credential(
        pp,
        credential_1,
        active_proof_refresh_data,
    )
    credential_1_refreshed_path_report = lattice_verkle_path_report(
        identities[0],
        credential_1.y_id,
        credential_1.path_proof,
        root_after_register_2,
        pp.tree_params,
    )
    credential_1_refreshed_position_binding_report = lattice_verkle_position_binding_report(
        identities[0],
        credential_1.y_id,
        credential_1.path_proof,
        root_after_register_2,
        pp.tree_params,
    )
    refreshed_challenge_1 = issue_sampled_authentication_challenge(
        pp,
        seeds["nonce_1_refreshed"],
    )
    refreshed_challenge_1_report = authentication_challenge_report(
        pp,
        state,
        refreshed_challenge_1,
    )
    refreshed_transcript_1 = authenticate_lvc_verkle_challenge(
        pp,
        credential_1,
        identities[0],
        refreshed_challenge_1,
        seeds["auth_1_refreshed"],
    )
    refreshed_verify_1 = verify_lvc_verkle(
        pp,
        identities[0],
        credential_1.y_id,
        refreshed_challenge_1.nonce,
        refreshed_transcript_1,
    )
    stale_root_verify_parameterization_report = verification_root_parameterization_report(
        pp,
        state,
        identities[0],
        credential_1.y_id,
        challenge_1,
        transcript_1,
    )
    refreshed_root_verify_parameterization_report = verification_root_parameterization_report(
        pp,
        state,
        identities[0],
        credential_1.y_id,
        refreshed_challenge_1,
        refreshed_transcript_1,
    )
    negative_verification_audit = authentication_negative_verification_report(
        pp.A,
        pp.lattice_params,
        pp.tree_params,
        identities[0],
        credential_1.y_id,
        refreshed_challenge_1.nonce,
        root_after_register_2,
        refreshed_transcript_1,
        pp.auth_params,
    )
    transcript_input_validation_audit = authentication_transcript_input_validation_audit(
        pp.A,
        pp.lattice_params,
        pp.tree_params,
        identities[0],
        credential_1.y_id,
        refreshed_challenge_1.nonce,
        root_after_register_2,
        refreshed_transcript_1,
        pp.auth_params,
    )
    transcript_1_report = authentication_transcript_report(
        pp.A,
        pp.lattice_params,
        pp.tree_params,
        identities[0],
        credential_1.y_id,
        challenge_1.nonce,
        root_after_register_1,
        transcript_1,
        pp.auth_params,
    )
    refreshed_transcript_1_report = authentication_transcript_report(
        pp.A,
        pp.lattice_params,
        pp.tree_params,
        identities[0],
        credential_1.y_id,
        refreshed_challenge_1.nonce,
        root_after_register_2,
        refreshed_transcript_1,
        pp.auth_params,
    )
    authentication_rejection_sampling_audit = authentication_rejection_sampling_path_audit(
        pp.A,
        pp.lattice_params,
        credential_1,
        identities[0],
        refreshed_challenge_1.nonce,
        root_after_register_2,
        pp.auth_params,
        [b"auth-rejection-sampling-audit"],
        tail_cutoff=pp.mask_tail_cutoff,
        omega_factor=pp.auth_omega_factor,
    )

    root_after_revoke_1 = revoke_lvc_verkle(pp, msk, state, identities[0])
    revoked_proof_refresh_data = proof_refresh_service(
        pp,
        state,
        identities[0],
        credential_1.y_id,
    )
    credential_1_revoked_path_report = lattice_verkle_path_report(
        identities[0],
        credential_1.y_id,
        credential_1.path_proof,
        root_after_revoke_1,
        pp.tree_params,
    )
    final_state_tree_report = lattice_verkle_tree_state_report(state.state_tree)
    revoked_verify_1 = verify_lvc_verkle(
        pp,
        identities[0],
        credential_1.y_id,
        refreshed_challenge_1.nonce,
        refreshed_transcript_1,
    )
    verification_results = {
        "uav_1_initial_accepts_before_root_update": bool(verify_1),
        "uav_1_stale_rejects_after_register_2": bool(not stale_verify_1),
        "uav_1_refreshed_accepts_after_register_2": bool(refreshed_verify_1),
        "uav_1_rejects_after_revoke": bool(not revoked_verify_1),
    }
    proof_refresh_audit = _proof_refresh_audit(
        credential_1_stale_path_report,
        credential_1_refreshed_path_report,
        stale_verify_1,
        refreshed_verify_1,
        root_after_register_1,
        root_after_register_2,
    )
    proof_refresh_service_audit = _proof_refresh_service_audit(
        active_proof_refresh_data,
        wrong_y_proof_refresh_data,
        revoked_proof_refresh_data,
        identities[0],
        credential_1.y_id,
        root_after_register_2,
        pp.tree_params,
    )
    revocation_current_credential_surface_audit = (
        _revocation_current_credential_surface_audit(
            state,
            identities[0],
            credential_1,
            revoked_proof_refresh_data,
        )
    )
    paper_protocol_clarification_audit = paper_protocol_clarification_report(
        pp,
        random_oracle_audit,
        auth_parameter_report,
        lattice_asymptotic_report,
        proof_refresh_service_audit,
    )
    credential_reports = {
        "uav_1_refreshed": _credential_report(identities[0], credential_1, pp.tree_params),
        "uav_2": _credential_report(identities[1], credential_2, pp.tree_params),
    }
    transcript_reports = {
        "uav_1_initial": _transcript_report(
            transcript_1,
            pp.lattice_params,
            pp.tree_params,
            transcript_1_report,
        ),
        "uav_1_refreshed": _transcript_report(
            refreshed_transcript_1,
            pp.lattice_params,
            pp.tree_params,
            refreshed_transcript_1_report,
        ),
    }
    paper_correctness_audit = _paper_correctness_audit(
        credential_reports,
        transcript_reports,
        verification_results,
    )
    authentication_freshness_model_audit = _authentication_freshness_model_audit(
        nonce_sampling_audit,
        [challenge_1_report, refreshed_challenge_1_report],
        negative_verification_audit,
        stale_root_verify_parameterization_report,
        refreshed_root_verify_parameterization_report,
        verification_results,
    )
    sample_pre_diversity_audits = {
        "uav_1_refreshed": sample_pre_diversity_audit(
            pp.A,
            msk.trapdoor,
            pp.lattice_params,
            credential_1.y_id,
            pp.sigma_pre,
            pp.beta,
            [b"experiment", b"uav-1-refreshed", identities[0], credential_1.epoch],
            omega_factor=pp.omega_factor,
            tail_cutoff=pp.sample_pre_tail_cutoff,
        ),
        "uav_2": sample_pre_diversity_audit(
            pp.A,
            msk.trapdoor,
            pp.lattice_params,
            credential_2.y_id,
            pp.sigma_pre,
            pp.beta,
            [b"experiment", b"uav-2", identities[1], credential_2.epoch],
            omega_factor=pp.omega_factor,
            tail_cutoff=pp.sample_pre_tail_cutoff,
        ),
    }
    sample_pre_input_validation = sample_pre_input_validation_audit(
        pp.A,
        msk.trapdoor,
        pp.lattice_params,
        pp.sigma_pre,
        [b"experiment", b"sample-pre-input-validation"],
        tail_cutoff=pp.sample_pre_tail_cutoff,
    )
    sample_pre_coset_audit_1 = credential_1.sample_pre_report[
        "sampler_trace_report"
    ]["coset_decomposition_report"]
    sample_pre_coset_audit_2 = credential_2.sample_pre_report[
        "sampler_trace_report"
    ]["coset_decomposition_report"]
    protocol_public_surface_audit = _protocol_public_surface_audit(
        credential_reports,
        transcript_reports,
        proof_refresh_service_audit,
    )
    role_assumption_model_audit = _role_assumption_model_audit(
        credential_reports,
        transcript_reports,
        setup_key_surface_audit,
        protocol_public_surface_audit,
        proof_refresh_service_audit,
    )
    state_tree_collision_resolution_audit = lattice_verkle_collision_resolution_report(
        VerkleTreeParameters(branching_factor=2, height=1),
        pp.lattice_params,
    )
    state_commitment_backend_audit = lattice_verkle_state_commitment_backend_report(
        state.state_tree
    )
    root_transition_reports = {
        "register_1": root_transition_report(initial_root, root_after_register_1, "register_1"),
        "register_2": root_transition_report(root_after_register_1, root_after_register_2, "register_2"),
        "revoke_1": root_transition_report(root_after_register_2, root_after_revoke_1, "revoke_1"),
    }
    credential_1_norm_ok = credential_1.norm_squared <= credential_1.beta * credential_1.beta
    credential_2_norm_ok = credential_2.norm_squared <= credential_2.beta * credential_2.beta
    transcript_1_norm_ok = _zz_vector_norm_squared(transcript_1.response) <= (
        pp.auth_params.beta_response * pp.auth_params.beta_response
    )
    refreshed_transcript_1_norm_ok = _zz_vector_norm_squared(refreshed_transcript_1.response) <= (
        pp.auth_params.beta_response * pp.auth_params.beta_response
    )
    checks = {
        "random_oracle_h1_coordinates_in_zq": bool(
            random_oracle_audit["h1_coordinates_in_zq"]
        ),
        "random_oracle_h1_output_sage_vector": bool(
            random_oracle_audit["h1_output_is_sage_vector"]
        ),
        "random_oracle_h1_base_ring_zq": bool(
            random_oracle_audit["h1_base_ring_matches_zq"]
        ),
        "random_oracle_h1_dimension_matches": bool(
            random_oracle_audit["h1_dimension_matches"]
        ),
        "random_oracle_h1_deterministic": bool(
            random_oracle_audit["h1_deterministic"]
        ),
        "random_oracle_h1_domain_input_separation": bool(
            random_oracle_audit["h1_distinct_domain_input_changes_output"]
        ),
        "random_oracle_h2_raw_sage_integer": bool(
            random_oracle_audit["h2_raw_is_sage_integer"]
        ),
        "random_oracle_h2_centered_sage_integer": bool(
            random_oracle_audit["h2_centered_is_sage_integer"]
        ),
        "random_oracle_framing_avoids_concat_ambiguity": bool(
            random_oracle_audit["framing_avoids_concat_ambiguity"]
        ),
        "random_oracle_h2_scalar_raw_in_modulus": bool(
            random_oracle_audit["h2_scalar_raw_in_modulus"]
        ),
        "random_oracle_h2_scalar_centered_in_c_lambda": bool(
            random_oracle_audit["h2_scalar_centered_in_c_lambda"]
        ),
        "random_oracle_centered_space_cardinality": bool(
            random_oracle_audit["centered_space_has_expected_cardinality"]
        ),
        "trap_gen_a_bar_relation": bool(trap_gen_report["a_bar_relation_holds"]),
        "trap_gen_tail_relation": bool(trap_gen_report["tail_relation_holds"]),
        "trap_gen_trapdoor_relation": bool(trap_gen_report["trapdoor_relation_holds"]),
        "trap_gen_gadget_kernel_relation": bool(trap_gen_report["gadget_kernel_relation_holds"]),
        "trap_gen_gadget_decomposition": bool(
            trap_gen_report["gadget_decomposition_audit"]["all_checks_hold"]
        ),
        "trap_gen_kernel_basis_full_rank": bool(trap_gen_report["kernel_basis_full_rank"]),
        "trap_gen_kernel_basis_relation": bool(trap_gen_report["kernel_basis_relation_holds"]),
        "trap_gen_r_entries_ternary": bool(trap_gen_report["r_entries_are_ternary"]),
        "trap_gen_r_shape": bool(trap_gen_report["r_has_expected_shape"]),
        "trap_gen_quality": bool(trap_gen_report["trapdoor_quality_checks_hold"]),
        "trap_gen_non_production_distribution": bool(
            not trap_gen_report["production_trapgen_claim_permitted"]
            and not trap_gen_report["a_bar_uniformity_claim_permitted"]
            and not trap_gen_report["r_distribution_claim_permitted"]
        ),
        "trap_gen_multi_seed_reproducible": bool(
            trap_gen_multi_seed["same_seed_reproducible"]
        ),
        "trap_gen_multi_seed_distinct": bool(
            trap_gen_multi_seed["different_seed_distinct"]
        ),
        "trap_gen_multi_seed_relations": bool(
            trap_gen_multi_seed["all_relations_hold"]
        ),
        "trap_gen_multi_seed_quality": bool(
            trap_gen_multi_seed["all_quality_checks_hold"]
        ),
        "setup_key_surface_public_fields": bool(setup_key_surface_audit["public_has_expected_fields"]),
        "setup_key_surface_public_omits_trapdoor": bool(setup_key_surface_audit["public_omits_trapdoor"]),
        "setup_key_surface_msk_contains_trapdoor": bool(setup_key_surface_audit["master_secret_contains_trapdoor"]),
        "setup_key_surface_public_G": bool(setup_key_surface_audit["public_parameter_G_matches_gadget_matrix"]),
        "setup_key_surface_public_q": bool(setup_key_surface_audit["public_parameter_q_matches_lattice_parameters"]),
        "setup_key_surface_root_matches_state": bool(setup_key_surface_audit["root_matches_state"]),
        "setup_key_surface_root0_matches_setup_root": bool(setup_key_surface_audit["public_parameter_root0_matches_setup_root"]),
        "setup_key_surface_rt0_matches_setup_root": bool(setup_key_surface_audit["public_parameter_rt0_matches_setup_root"]),
        "setup_key_surface_tree_shape_aliases": bool(setup_key_surface_audit["public_parameter_tree_shape_aliases_match"]),
        "setup_key_surface_h1_descriptor": bool(setup_key_surface_audit["public_parameter_H1_descriptor_matches"]),
        "setup_key_surface_h2_descriptor": bool(setup_key_surface_audit["public_parameter_H2_descriptor_matches"]),
        "setup_key_surface_sigma_alias": bool(
            setup_key_surface_audit[
                "public_parameter_sigma_matches_authentication_mask"
            ]
        ),
        "sample_pre_bound_uav_1": bool(credential_1.parameter_report["passes_recommended_bound"]),
        "sample_pre_bound_uav_2": bool(credential_2.parameter_report["passes_recommended_bound"]),
        "sample_pre_equation_uav_1": bool(credential_1.sample_pre_report["equation_holds"]),
        "sample_pre_equation_uav_2": bool(credential_2.sample_pre_report["equation_holds"]),
        "sample_pre_norm_bound_uav_1": bool(credential_1.sample_pre_report["norm_bound_holds"]),
        "sample_pre_norm_bound_uav_2": bool(credential_2.sample_pre_report["norm_bound_holds"]),
        "sample_pre_algorithmic_checks_uav_1": bool(
            credential_1.sample_pre_report["all_algorithmic_checks_hold"]
        ),
        "sample_pre_algorithmic_checks_uav_2": bool(
            credential_2.sample_pre_report["all_algorithmic_checks_hold"]
        ),
        "sample_pre_trace_uav_1": bool(
            credential_1.sample_pre_report["sampler_trace_all_checks_hold"]
        ),
        "sample_pre_trace_uav_2": bool(
            credential_2.sample_pre_report["sampler_trace_all_checks_hold"]
        ),
        "sample_pre_window_mass_audit_uav_1": bool(
            credential_1.sample_pre_report["sampler_trace_report"][
                "all_window_mass_bounds_valid"
            ]
            and credential_1.sample_pre_report[
                "finite_window_mass_heuristic_lower_bound"
            ]
            is not None
        ),
        "sample_pre_window_mass_audit_uav_2": bool(
            credential_2.sample_pre_report["sampler_trace_report"][
                "all_window_mass_bounds_valid"
            ]
            and credential_2.sample_pre_report[
                "finite_window_mass_heuristic_lower_bound"
            ]
            is not None
        ),
        "sample_pre_coset_uav_1": bool(sample_pre_coset_audit_1["all_checks_hold"]),
        "sample_pre_coset_uav_2": bool(sample_pre_coset_audit_2["all_checks_hold"]),
        "sample_pre_input_validation": bool(
            sample_pre_input_validation["all_checks_hold"]
        ),
        "sample_pre_diversity_equations_uav_1": bool(
            sample_pre_diversity_audits["uav_1_refreshed"]["all_equations_hold"]
        ),
        "sample_pre_diversity_equations_uav_2": bool(
            sample_pre_diversity_audits["uav_2"]["all_equations_hold"]
        ),
        "sample_pre_diversity_norm_bounds_uav_1": bool(
            sample_pre_diversity_audits["uav_1_refreshed"]["all_norm_bounds_hold"]
        ),
        "sample_pre_diversity_norm_bounds_uav_2": bool(
            sample_pre_diversity_audits["uav_2"]["all_norm_bounds_hold"]
        ),
        "sample_pre_diversity_distinct_uav_1": bool(
            sample_pre_diversity_audits["uav_1_refreshed"]["produces_distinct_preimages"]
        ),
        "sample_pre_diversity_distinct_uav_2": bool(
            sample_pre_diversity_audits["uav_2"]["produces_distinct_preimages"]
        ),
        "sample_pre_diversity_deterministic_uav_1": bool(
            sample_pre_diversity_audits["uav_1_refreshed"][
                "deterministic_reproducibility_checked"
            ]
        ),
        "sample_pre_diversity_deterministic_uav_2": bool(
            sample_pre_diversity_audits["uav_2"][
                "deterministic_reproducibility_checked"
            ]
        ),
        "credential_norm_bound_uav_1": bool(credential_1_norm_ok),
        "credential_norm_bound_uav_2": bool(credential_2_norm_ok),
        "paper_correctness_credentials": bool(
            paper_correctness_audit["all_credentials_correct"]
        ),
        "paper_correctness_transcripts": bool(
            paper_correctness_audit["all_transcripts_correct"]
        ),
        "paper_correctness_honest_verify_accepts": bool(
            paper_correctness_audit["honest_verification_accepts"]
        ),
        "register_identity_only_api_uav_1": bool(register_identity_only_api_1),
        "register_identity_only_api_uav_2": bool(register_identity_only_api_2),
        "auth_response_parameter_bound": bool(auth_parameter_report["passes_recommended_bound"]),
        "sampler_parameter_audit": bool(sampler_parameter_audit["all_checks_hold"]),
        "response_norm_bound_uav_1_initial": bool(transcript_1_norm_ok),
        "response_norm_bound_uav_1_refreshed": bool(refreshed_transcript_1_norm_ok),
        "auth_transcript_uav_1_initial": bool(transcript_1_report["verifies"]),
        "auth_transcript_uav_1_refreshed": bool(refreshed_transcript_1_report["verifies"]),
        "auth_generation_algorithmic_uav_1_initial": bool(
            transcript_1.audit_report["all_algorithmic_checks_hold"]
        ),
        "auth_generation_algorithmic_uav_1_refreshed": bool(
            refreshed_transcript_1.audit_report["all_algorithmic_checks_hold"]
        ),
        "auth_transcript_algorithmic_uav_1_initial": bool(
            transcript_1_report["all_algorithmic_checks_hold"]
        ),
        "auth_transcript_algorithmic_uav_1_refreshed": bool(
            refreshed_transcript_1_report["all_algorithmic_checks_hold"]
        ),
        "auth_rejection_sampling_path": bool(
            authentication_rejection_sampling_audit["all_checks_hold"]
        ),
        "state_root_changes_register_1": bool(root_transition_reports["register_1"]["root_changed"]),
        "state_root_changes_register_2": bool(root_transition_reports["register_2"]["root_changed"]),
        "state_root_changes_revoke_1": bool(root_transition_reports["revoke_1"]["root_changed"]),
        "state_stale_path_rejects_after_register_2": bool(
            not credential_1_stale_path_report["verifies_active_path"]
        ),
        "state_refreshed_path_accepts_after_register_2": bool(
            credential_1_refreshed_path_report["verifies_active_path"]
        ),
        "state_position_binding_uav_1_initial": bool(
            credential_1_initial_position_binding_report["position_binding_checks_hold"]
        ),
        "state_position_binding_uav_1_refreshed": bool(
            credential_1_refreshed_position_binding_report["position_binding_checks_hold"]
        ),
        "state_revoked_path_rejects_after_revoke": bool(
            not credential_1_revoked_path_report["verifies_active_path"]
        ),
        "state_revocation_removes_current_credential": bool(
            revocation_current_credential_surface_audit[
                "current_credential_removed"
            ]
        ),
        "state_revocation_preserves_credential_history": bool(
            revocation_current_credential_surface_audit[
                "history_preserves_revoked_credential"
            ]
        ),
        "state_final_active_count": final_state_tree_report["active_leaf_count"] == 1,
        "state_final_revoked_count": final_state_tree_report["revoked_leaf_count"] == 1,
        "state_tree_collision_initial_indices_collide": bool(
            state_tree_collision_resolution_audit["initial_indices_collide"]
        ),
        "state_tree_collision_uses_nonzero_probe": bool(
            state_tree_collision_resolution_audit["collision_uses_nonzero_probe"]
        ),
        "state_tree_collision_assigned_indices_distinct": bool(
            state_tree_collision_resolution_audit["assigned_indices_distinct"]
        ),
        "state_tree_collision_paths_verify": bool(
            state_tree_collision_resolution_audit[
                "primary_refreshed_path_verifies_after_collision_insert"
            ]
            and state_tree_collision_resolution_audit["colliding_path_verifies"]
        ),
        "state_tree_collision_duplicate_identity_rejected": bool(
            state_tree_collision_resolution_audit["duplicate_identity_rejected"]
        ),
        "state_commitment_backend_audited": bool(
            state_commitment_backend_audit["all_checks_hold"]
        ),
        "state_commitment_backend_matches_paper_verkle": bool(
            state_commitment_backend_audit["current_backend"]
            == "lattice_linear_verkle_tree"
            and state_commitment_backend_audit["paper_verkle_backend_claim_permitted"]
            and state_commitment_backend_audit[
                "paper_verkle_proof_size_model_claim_permitted"
            ]
            and state_commitment_backend_audit[
                "paper_verkle_security_assumption_matches_backend"
            ]
            and state_commitment_backend_audit["paper_alignment_action"]
            == "paper_verkle_claim_matches_lattice_linear_verkle_reference_backend"
        ),
        "proof_refresh_required_after_register_2": bool(
            proof_refresh_audit["proof_refresh_required"]
        ),
        "proof_refresh_service_restores_authentication": bool(
            proof_refresh_audit["proof_refresh_service_restores_authentication"]
        ),
        "proof_refresh_service_public_data_only": bool(
            proof_refresh_service_audit["active_returns_public_data_only"]
        ),
        "proof_refresh_service_path_verifies": bool(
            proof_refresh_service_audit["active_path_verifies"]
        ),
        "proof_refresh_service_rejects_wrong_y": bool(
            proof_refresh_service_audit["wrong_y_returns_bottom"]
        ),
        "proof_refresh_service_rejects_revoked_identity": bool(
            proof_refresh_service_audit["revoked_identity_returns_bottom"]
        ),
        "negative_verify_valid_accepts": bool(
            negative_verification_audit["valid_transcript_verifies"]
        ),
        "negative_verify_rejects_wrong_nonce": bool(
            negative_verification_audit["rejects_wrong_nonce"]
        ),
        "negative_verify_rejects_tampered_root": bool(
            negative_verification_audit["rejects_tampered_root"]
        ),
        "negative_verify_rejects_tampered_y_id": bool(
            negative_verification_audit["rejects_tampered_y_id"]
        ),
        "negative_verify_rejects_tampered_commitment": bool(
            negative_verification_audit["rejects_tampered_commitment"]
        ),
        "negative_verify_rejects_tampered_challenge": bool(
            negative_verification_audit["rejects_tampered_challenge"]
        ),
        "negative_verify_rejects_tampered_response": bool(
            negative_verification_audit["rejects_tampered_response"]
        ),
        "verify_rejects_malformed_transcripts": bool(
            transcript_input_validation_audit["all_checks_hold"]
        ),
        "auth_challenge_initial_current_root": bool(
            challenge_1_report["challenge_root_is_current"]
        ),
        "auth_challenge_refreshed_current_root": bool(
            refreshed_challenge_1_report["challenge_root_is_current"]
        ),
        "auth_nonce_sampling_lambda_length": bool(
            nonce_sampling_audit["length_holds"]
        ),
        "auth_nonce_sampling_reproducible": bool(
            nonce_sampling_audit["same_seed_reproducible"]
        ),
        "auth_nonce_sampling_distinct_seeds": bool(
            nonce_sampling_audit["different_seed_distinct"]
        ),
        "auth_freshness_model_boundary": bool(
            authentication_freshness_model_audit["all_checks_hold"]
            and authentication_freshness_model_audit["freshness_assumption_explicit"]
            and authentication_freshness_model_audit["scheme_verify_is_stateless"]
            and authentication_freshness_model_audit[
                "verifier_nonce_reuse_cache_implemented"
            ]
        ),
        "verify_explicit_old_root_accepts_old_transcript": bool(
            stale_root_verify_parameterization_report["explicit_root_verify_accepts"]
        ),
        "verify_current_root_rejects_old_transcript": bool(
            not stale_root_verify_parameterization_report["current_root_verify_accepts"]
        ),
        "verify_old_root_not_current": bool(
            not stale_root_verify_parameterization_report["root_is_current"]
        ),
        "verify_refreshed_explicit_root_accepts": bool(
            refreshed_root_verify_parameterization_report["explicit_root_verify_accepts"]
        ),
        "verify_refreshed_root_is_current": bool(
            refreshed_root_verify_parameterization_report["root_is_current"]
        ),
        "verify_current_wrapper_matches_explicit_current_root": bool(
            refreshed_root_verify_parameterization_report[
                "current_root_wrapper_matches_explicit_when_current"
            ]
        ),
        "public_surface_credentials_label_secret": bool(
            protocol_public_surface_audit["credential_reports_label_secret_z_id"]
        ),
        "public_surface_transcripts_public_only": bool(
            protocol_public_surface_audit["authentication_transcripts_are_public_only"]
        ),
        "public_surface_proof_refresh_public_only": bool(
            protocol_public_surface_audit["proof_refresh_service_returns_public_data_only"]
        ),
        "role_assumption_model_logical_surface": bool(
            role_assumption_model_audit["logical_role_model_checks_hold"]
        ),
        "paper_protocol_clarifications_have_sage_evidence": bool(
            paper_protocol_clarification_audit["all_items_have_sage_evidence"]
        ),
        "all_verification_results": all(verification_results.values()),
    }
    checks["all_trap_gen_relations"] = all(
        checks[name]
        for name in [
            "trap_gen_a_bar_relation",
            "trap_gen_tail_relation",
            "trap_gen_trapdoor_relation",
            "trap_gen_gadget_kernel_relation",
            "trap_gen_gadget_decomposition",
            "trap_gen_kernel_basis_full_rank",
            "trap_gen_kernel_basis_relation",
            "trap_gen_r_entries_ternary",
            "trap_gen_r_shape",
            "trap_gen_quality",
            "trap_gen_non_production_distribution",
            "trap_gen_multi_seed_reproducible",
            "trap_gen_multi_seed_distinct",
            "trap_gen_multi_seed_relations",
            "trap_gen_multi_seed_quality",
            "setup_key_surface_public_fields",
            "setup_key_surface_public_omits_trapdoor",
            "setup_key_surface_msk_contains_trapdoor",
            "setup_key_surface_public_G",
            "setup_key_surface_public_q",
            "setup_key_surface_root_matches_state",
            "setup_key_surface_root0_matches_setup_root",
            "setup_key_surface_rt0_matches_setup_root",
            "setup_key_surface_tree_shape_aliases",
            "setup_key_surface_h1_descriptor",
            "setup_key_surface_h2_descriptor",
            "setup_key_surface_sigma_alias",
        ]
    )
    checks["all_sample_pre_outputs"] = all(
        checks[name]
        for name in [
            "sample_pre_bound_uav_1",
            "sample_pre_bound_uav_2",
            "sample_pre_equation_uav_1",
            "sample_pre_equation_uav_2",
            "sample_pre_norm_bound_uav_1",
            "sample_pre_norm_bound_uav_2",
            "sample_pre_algorithmic_checks_uav_1",
            "sample_pre_algorithmic_checks_uav_2",
            "sample_pre_trace_uav_1",
            "sample_pre_trace_uav_2",
            "sample_pre_window_mass_audit_uav_1",
            "sample_pre_window_mass_audit_uav_2",
            "sample_pre_coset_uav_1",
            "sample_pre_coset_uav_2",
            "sample_pre_input_validation",
        ]
    )
    checks["all_sample_pre_diversity_semantics"] = all(
        checks[name]
        for name in [
            "sample_pre_diversity_equations_uav_1",
            "sample_pre_diversity_equations_uav_2",
            "sample_pre_diversity_norm_bounds_uav_1",
            "sample_pre_diversity_norm_bounds_uav_2",
            "sample_pre_diversity_distinct_uav_1",
            "sample_pre_diversity_distinct_uav_2",
            "sample_pre_diversity_deterministic_uav_1",
            "sample_pre_diversity_deterministic_uav_2",
        ]
    )
    checks["all_bounds"] = all(
        checks[name]
        for name in [
            "sample_pre_bound_uav_1",
            "sample_pre_bound_uav_2",
            "sample_pre_norm_bound_uav_1",
            "sample_pre_norm_bound_uav_2",
            "credential_norm_bound_uav_1",
            "credential_norm_bound_uav_2",
            "auth_response_parameter_bound",
            "response_norm_bound_uav_1_initial",
            "response_norm_bound_uav_1_refreshed",
        ]
    )
    checks["all_authentication_transcripts"] = all(
        checks[name]
        for name in [
            "auth_transcript_uav_1_initial",
            "auth_transcript_uav_1_refreshed",
            "auth_generation_algorithmic_uav_1_initial",
            "auth_generation_algorithmic_uav_1_refreshed",
            "auth_transcript_algorithmic_uav_1_initial",
            "auth_transcript_algorithmic_uav_1_refreshed",
            "auth_rejection_sampling_path",
        ]
    )
    checks["all_paper_correctness"] = all(
        checks[name]
        for name in [
            "paper_correctness_credentials",
            "paper_correctness_transcripts",
            "paper_correctness_honest_verify_accepts",
        ]
    )
    checks["all_state_tree_semantics"] = all(
        checks[name]
        for name in [
            "state_root_changes_register_1",
            "state_root_changes_register_2",
            "state_root_changes_revoke_1",
            "state_stale_path_rejects_after_register_2",
            "state_refreshed_path_accepts_after_register_2",
            "state_position_binding_uav_1_initial",
            "state_position_binding_uav_1_refreshed",
            "state_revoked_path_rejects_after_revoke",
            "state_revocation_removes_current_credential",
            "state_revocation_preserves_credential_history",
            "state_final_active_count",
            "state_final_revoked_count",
            "state_tree_collision_initial_indices_collide",
            "state_tree_collision_uses_nonzero_probe",
            "state_tree_collision_assigned_indices_distinct",
            "state_tree_collision_paths_verify",
            "state_tree_collision_duplicate_identity_rejected",
            "state_commitment_backend_audited",
            "state_commitment_backend_matches_paper_verkle",
        ]
    )
    checks["all_state_tree_position_binding"] = all(
        checks[name]
        for name in [
            "state_position_binding_uav_1_initial",
            "state_position_binding_uav_1_refreshed",
        ]
    )
    checks["all_proof_refresh_semantics"] = all(
        checks[name]
        for name in [
            "proof_refresh_required_after_register_2",
            "proof_refresh_service_restores_authentication",
            "proof_refresh_service_public_data_only",
            "proof_refresh_service_path_verifies",
            "proof_refresh_service_rejects_wrong_y",
            "proof_refresh_service_rejects_revoked_identity",
        ]
    )
    checks["all_negative_verification_semantics"] = all(
        checks[name]
        for name in [
            "negative_verify_valid_accepts",
            "negative_verify_rejects_wrong_nonce",
            "negative_verify_rejects_tampered_root",
            "negative_verify_rejects_tampered_y_id",
            "negative_verify_rejects_tampered_commitment",
            "negative_verify_rejects_tampered_challenge",
            "negative_verify_rejects_tampered_response",
            "verify_rejects_malformed_transcripts",
        ]
    )
    checks["all_authentication_challenge_binding"] = all(
        checks[name]
        for name in [
            "auth_challenge_initial_current_root",
            "auth_challenge_refreshed_current_root",
            "auth_nonce_sampling_lambda_length",
            "auth_nonce_sampling_reproducible",
            "auth_nonce_sampling_distinct_seeds",
            "auth_freshness_model_boundary",
        ]
    )
    checks["all_verify_root_parameterization"] = all(
        checks[name]
        for name in [
            "verify_explicit_old_root_accepts_old_transcript",
            "verify_current_root_rejects_old_transcript",
            "verify_old_root_not_current",
            "verify_refreshed_explicit_root_accepts",
            "verify_refreshed_root_is_current",
            "verify_current_wrapper_matches_explicit_current_root",
        ]
    )
    checks["all_protocol_public_surface"] = all(
        checks[name]
        for name in [
            "public_surface_credentials_label_secret",
            "public_surface_transcripts_public_only",
            "public_surface_proof_refresh_public_only",
        ]
    )
    checks["all_random_oracles"] = all(
        checks[name]
        for name in [
            "random_oracle_h1_coordinates_in_zq",
            "random_oracle_h1_output_sage_vector",
            "random_oracle_h1_base_ring_zq",
            "random_oracle_h1_dimension_matches",
            "random_oracle_h1_deterministic",
            "random_oracle_h1_domain_input_separation",
            "random_oracle_h2_raw_sage_integer",
            "random_oracle_h2_centered_sage_integer",
            "random_oracle_framing_avoids_concat_ambiguity",
            "random_oracle_h2_scalar_raw_in_modulus",
            "random_oracle_h2_scalar_centered_in_c_lambda",
            "random_oracle_centered_space_cardinality",
        ]
    )
    paper_algorithm_audit = _paper_algorithm_audit(checks, verification_results)
    checks["all_paper_algorithm_audit"] = paper_algorithm_audit["all_passed"]
    paper_scheme_io_audit = _paper_scheme_io_audit(
        setup_key_surface_audit,
        credential_reports,
        transcript_reports,
        verification_results,
        root_transition_reports,
        final_state_tree_report,
        revocation_current_credential_surface_audit,
        checks,
        paper_algorithm_audit,
    )
    checks["paper_scheme_io_audit"] = paper_scheme_io_audit["all_checks_hold"]
    checks["all_checks"] = all(checks.values())
    security_parameter_audit = _security_parameter_audit(
        {
            "uav_1_refreshed": credential_1,
            "uav_2": credential_2,
        },
        auth_parameter_report,
        lattice_asymptotic_report,
        checks,
    )
    paper_conformance_report = _paper_conformance_report(
        checks,
        paper_algorithm_audit,
        paper_scheme_io_audit,
        authentication_freshness_model_audit,
        security_parameter_audit,
        paper_protocol_clarification_audit,
    )

    return {
        "configuration": _configuration_report(config, config_path),
        "implementation_status": {
            "language": "SageMath",
            "challenge_space_instantiation": "centered_scalar_experimental",
            "state_tree": "lattice_linear_verkle_tree",
            "sample_pre": "mp12_gpv_klein_style_experimental",
        },
        "seeds_hex": {name: _seed_report(parts) for name, parts in seeds.items()},
        "parameters": {
            "lattice": {
                "n": int(pp.lattice_params.n),
                "q": int(pp.lattice_params.q),
                "base": int(pp.lattice_params.base),
                "k": int(pp.lattice_params.k),
                "m_bar": int(pp.lattice_params.m_bar),
                "w": int(pp.lattice_params.w),
                "m": int(pp.lattice_params.m),
                "beta": int(pp.beta),
                "sigma_pre": float(pp.sigma_pre),
                "omega_factor": float(pp.omega_factor),
                "sample_pre_omega_factor": float(pp.omega_factor),
                "sample_pre_tail_cutoff": int(pp.sample_pre_tail_cutoff),
            },
            "trap_gen_parameter_report": _trap_gen_parameter_report(trap_gen_report),
            "trap_gen_multi_seed_audit": _trap_gen_multi_seed_audit_report(
                trap_gen_multi_seed
            ),
            "lattice_asymptotic_parameter_report": _paper_lattice_asymptotic_parameter_report(
                lattice_asymptotic_report
            ),
            "state_tree": {
                "branching_factor": int(pp.tree_params.branching_factor),
                "height": int(pp.tree_params.height),
                "leaf_count": int(pp.tree_params.leaf_count()),
                "commitment_bytes": int(pp.tree_params.commitment_bytes),
            },
            "authentication": {
                "challenge_modulus": int(pp.auth_params.challenge_modulus),
                "challenge_bound_B_c": int(pp.auth_params.challenge_bound()),
                "delta_c_min": int(pp.auth_params.delta_c_min()),
                "sigma_mask": float(pp.auth_params.sigma_mask),
                "omega_factor": float(pp.auth_omega_factor),
                "authentication_omega_factor": float(pp.auth_omega_factor),
                "beta_response": int(pp.auth_params.beta_response),
                "max_attempts": int(pp.auth_params.max_attempts),
                "nonce_bytes": int(pp.auth_params.nonce_bytes),
                "nonce_lambda_bits": int(8 * pp.auth_params.nonce_bytes),
                "mask_tail_cutoff": int(pp.mask_tail_cutoff),
            },
            "authentication_parameter_report": _authentication_parameter_report(auth_parameter_report),
            "parameter_preflight": parameter_preflight,
            "sampler_parameter_audit": _sampler_parameter_audit_report(
                sampler_parameter_audit
            ),
        },
        "roots": {
            "initial": _bytes_hex(initial_root),
            "after_register_1": _bytes_hex(root_after_register_1),
            "after_register_2": _bytes_hex(root_after_register_2),
            "after_revoke_1": _bytes_hex(root_after_revoke_1),
        },
        "state_tree_reports": {
            "final_state": _lattice_verkle_tree_state_report(final_state_tree_report),
            "root_transitions": {
                name: _root_transition_report(report)
                for name, report in root_transition_reports.items()
            },
            "uav_1_initial_path": _lattice_verkle_path_report(
                lattice_verkle_path_report(
                    identities[0],
                    credential_1.y_id,
                    credential_1_initial_path_proof,
                    root_after_register_1,
                    pp.tree_params,
                )
            ),
            "uav_1_initial_position_binding": _lattice_verkle_position_binding_report(
                credential_1_initial_position_binding_report
            ),
            "uav_1_stale_path_after_register_2": _lattice_verkle_path_report(
                credential_1_stale_path_report
            ),
            "uav_1_refreshed_path_after_register_2": _lattice_verkle_path_report(
                credential_1_refreshed_path_report
            ),
            "uav_1_refreshed_position_binding_after_register_2": _lattice_verkle_position_binding_report(
                credential_1_refreshed_position_binding_report
            ),
            "uav_1_path_after_revoke": _lattice_verkle_path_report(
                credential_1_revoked_path_report
            ),
        },
        "state_tree_collision_resolution_audit": _lattice_verkle_collision_resolution_report(
            state_tree_collision_resolution_audit
        ),
        "state_commitment_backend_audit": _state_commitment_backend_report(
            state_commitment_backend_audit
        ),
        "credentials": credential_reports,
        "sample_pre_diversity_audit": {
            name: _sample_pre_diversity_audit_report(audit)
            for name, audit in sample_pre_diversity_audits.items()
        },
        "sample_pre_input_validation_audit": _sample_pre_input_validation_audit_report(
            sample_pre_input_validation
        ),
        "transcripts": transcript_reports,
        "verification_results": verification_results,
        "proof_refresh_audit": proof_refresh_audit,
        "proof_refresh_service_audit": proof_refresh_service_audit,
        "revocation_current_credential_surface_audit": (
            revocation_current_credential_surface_audit
        ),
        "authentication_challenge_audit": {
            "nonce_sampling": _authentication_nonce_sampling_report(nonce_sampling_audit),
            "initial": _authentication_challenge_report(challenge_1_report),
            "refreshed": _authentication_challenge_report(refreshed_challenge_1_report),
            "all_challenges_bind_current_root": bool(
                checks["all_authentication_challenge_binding"]
            ),
        },
        "authentication_freshness_model_audit": authentication_freshness_model_audit,
        "authentication_rejection_sampling_audit": (
            _authentication_rejection_sampling_path_audit_report(
                authentication_rejection_sampling_audit
            )
        ),
        "verification_root_parameterization_audit": {
            "stale_initial_challenge": _verification_root_parameterization_report(
                stale_root_verify_parameterization_report
            ),
            "refreshed_current_challenge": _verification_root_parameterization_report(
                refreshed_root_verify_parameterization_report
            ),
            "all_checks_hold": bool(checks["all_verify_root_parameterization"]),
        },
        "negative_verification_audit": _negative_verification_report(
            negative_verification_audit
        ),
        "authentication_transcript_input_validation_audit": (
            _authentication_transcript_input_validation_audit_report(
                transcript_input_validation_audit
            )
        ),
        "protocol_public_surface_audit": protocol_public_surface_audit,
        "role_assumption_model_audit": role_assumption_model_audit,
        "paper_correctness_audit": paper_correctness_audit,
        "random_oracle_instantiation_audit": _random_oracle_instantiation_report(
            random_oracle_audit
        ),
        "setup_key_surface_audit": _setup_key_surface_report(setup_key_surface_audit),
        "paper_protocol_clarification_audit": paper_protocol_clarification_audit,
        "paper_algorithm_audit": paper_algorithm_audit,
        "paper_scheme_io_audit": paper_scheme_io_audit,
        "security_parameter_audit": security_parameter_audit,
        "paper_conformance_report": paper_conformance_report,
        "checks": checks,
    }


def _usage():
    return """Usage:
  sage reference/sage/run_lvc_experiment.sage --help
  sage reference/sage/run_lvc_experiment.sage --config CONFIG_JSON --output REPORT_JSON
  sage reference/sage/run_lvc_experiment.sage --strict-parameters --config CONFIG_JSON --output REPORT_JSON
  sage reference/sage/run_lvc_experiment.sage CONFIG_JSON REPORT_JSON

The script requires an explicit JSON config.

JSON Schema:
  reference/configs/schemas/experiment_config.schema.json

Example:
  sage reference/sage/run_lvc_experiment.sage \\
    --config reference/configs/nist_experiment.json \\
    --output output/lvc_experiment_report.json

Config shape:
  authentication.challenge_modulus must be odd.

  {
    "format": "lvc_verkle_experiment_config_v1",
    "name": "descriptive_name",
    "lattice": {"n": 3, "q": 2147483647, "base": 2, "m_bar": 5},
    "sample_pre": {"beta": 9000000, "sigma_pre": 250000, "omega_factor": 0.0001, "tail_cutoff": 12},
    "tree": {"branching_factor": 4, "height": 3},
    "authentication": {
      "challenge_modulus": 3,
      "sigma_mask": 21000000,
      "omega_factor": 1.08,
      "beta_response": 250000000,
      "max_attempts": 1024,
      "nonce_bytes": 32,
      "mask_tail_cutoff": 12
    }
  }
"""


def _parse_cli_args(argv):
    if len(argv) == 1 or "--help" in argv[1:] or "-h" in argv[1:]:
        return None, None, False, True

    config_path = None
    output_path = None
    strict_parameters = False
    positional = []
    index = 1
    while index < len(argv):
        arg = argv[index]
        if arg == "--config":
            index += 1
            if index >= len(argv):
                raise ValueError("--config requires a path")
            config_path = argv[index]
        elif arg == "--output":
            index += 1
            if index >= len(argv):
                raise ValueError("--output requires a path")
            output_path = argv[index]
        elif arg == "--strict-parameters":
            strict_parameters = True
        elif arg.startswith("--"):
            raise ValueError("unknown option '%s'" % arg)
        else:
            positional.append(arg)
        index += 1

    if positional:
        if config_path is not None:
            raise ValueError("use either --config or positional CONFIG_JSON, not both")
        config_path = positional[0]
        if len(positional) > 1:
            if output_path is not None:
                raise ValueError("output path specified twice")
            output_path = positional[1]
        if len(positional) > 2:
            raise ValueError("too many positional arguments")

    if config_path is None:
        raise ValueError("missing required CONFIG_JSON")

    return config_path, output_path, strict_parameters, False


def main():
    try:
        config_path, output_path, strict_parameters, wants_help = _parse_cli_args(sys.argv)
    except ValueError as error:
        sys.stderr.write(str(error) + "\n\n")
        sys.stderr.write(_usage())
        raise SystemExit(2)

    if wants_help:
        print(_usage())
        return

    config = load_experiment_config(config_path)
    report = run_experiment(config, config_path, strict_parameters=strict_parameters)
    output = json.dumps(report, indent=2, sort_keys=True)

    if output_path is not None:
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        with open(output_path, "w") as handle:
            handle.write(output)
            handle.write("\n")
    else:
        print(output)


if not globals().get("LVC_EXPERIMENT_NO_MAIN", False):
    main()
