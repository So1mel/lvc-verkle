import json
import os
import sys
import time


LVC_EXPERIMENT_NO_MAIN = True
load("reference/sage/run_lvc_experiment.sage")


def _hex(value):
    return _as_bytes(value).hex()


def run_core_lifecycle(config_path, strict_parameters=False):
    config = load_experiment_config(config_path)
    setup_params = _setup_params_from_config(config)
    started_at = time.time()

    pp, msk, state = setup_lvc_verkle(setup_params, [b"core-lifecycle-setup"])
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
    root0 = pp.root

    id1 = b"UAV-CORE-001"
    id2 = b"UAV-CORE-002"

    cred1, root1 = register_lvc_verkle_by_identity(
        pp,
        msk,
        state,
        id1,
        [b"core-register-uav-001"],
    )

    challenge1 = issue_sampled_authentication_challenge(
        pp,
        [b"core-nonce-uav-001-root-1"],
    )
    tau1 = authenticate_lvc_verkle_challenge(
        pp,
        cred1,
        id1,
        challenge1,
        [b"core-auth-uav-001-root-1"],
    )
    verify1 = verify_lvc_verkle_challenge(pp, id1, cred1.y_id, challenge1, tau1)

    cred2, root2 = register_lvc_verkle_by_identity(
        pp,
        msk,
        state,
        id2,
        [b"core-register-uav-002"],
    )
    refreshed_cred1 = refresh_lvc_verkle_credential(pp, state, id1)

    challenge2 = issue_sampled_authentication_challenge(
        pp,
        [b"core-nonce-uav-001-root-2"],
    )
    tau2 = authenticate_lvc_verkle_challenge(
        pp,
        refreshed_cred1,
        id1,
        challenge2,
        [b"core-auth-uav-001-root-2"],
    )
    verify2 = verify_lvc_verkle_challenge(
        pp,
        id1,
        refreshed_cred1.y_id,
        challenge2,
        tau2,
    )

    root3 = revoke_lvc_verkle(pp, msk, state, id1)
    revoked_rejects = not verify_lvc_verkle(
        pp,
        id1,
        refreshed_cred1.y_id,
        challenge2.nonce,
        tau2,
    )

    return {
        "mode": "core_lifecycle_no_diversity_or_input_validation_audits",
        "config_path": os.path.abspath(config_path),
        "config_name": config["name"],
        "elapsed_seconds": time.time() - started_at,
        "parameters": {
            "n": int(setup_params.lattice_params.n),
            "q": int(setup_params.lattice_params.q),
            "m": int(setup_params.lattice_params.m),
            "m_bar": int(setup_params.lattice_params.m_bar),
            "gadget_width": int(setup_params.lattice_params.w),
            "challenge_modulus": int(setup_params.auth_params.challenge_modulus),
            "nonce_bytes": int(setup_params.auth_params.nonce_bytes),
            "sample_pre_omega_factor": float(setup_params.omega_factor),
            "authentication_omega_factor": float(setup_params.auth_omega_factor),
            "sample_pre_tail_cutoff": int(setup_params.sample_pre_tail_cutoff),
            "mask_tail_cutoff": int(setup_params.mask_tail_cutoff),
        },
        "parameter_preflight": parameter_preflight,
        "roots": {
            "setup": _hex(root0),
            "after_register_1": _hex(root1),
            "after_register_2": _hex(root2),
            "after_revoke_1": _hex(root3),
        },
        "verification": {
            "uav_1_accepts_before_second_register": bool(verify1),
            "uav_1_accepts_after_refresh": bool(verify2),
            "uav_1_rejects_after_revoke": bool(revoked_rejects),
        },
        "checks": {
            "root_changes_on_register_1": root0 != root1,
            "root_changes_on_register_2": root1 != root2,
            "root_changes_on_revoke": root2 != root3,
            "all_checks": bool(
                verify1
                and verify2
                and revoked_rejects
                and root0 != root1
                and root1 != root2
                and root2 != root3
            ),
        },
    }


def _usage():
    return """Usage:
  sage reference/sage/run_core_lifecycle.sage --config CONFIG_JSON --output REPORT_JSON
  sage reference/sage/run_core_lifecycle.sage --strict-parameters --config CONFIG_JSON --output REPORT_JSON
  sage reference/sage/run_core_lifecycle.sage CONFIG_JSON REPORT_JSON
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
            output_path = positional[1]
        if len(positional) > 2:
            raise ValueError("too many positional arguments")

    if config_path is None:
        raise ValueError("missing required CONFIG_JSON")

    return config_path, output_path, strict_parameters, False


def main():
    try:
        config_path, output_path, strict_parameters, show_help = _parse_cli_args(sys.argv)
        if show_help:
            print(_usage())
            return

        report = run_core_lifecycle(
            config_path,
            strict_parameters=strict_parameters,
        )
        encoded = json.dumps(
            report,
            indent=2,
            sort_keys=True,
            default=lambda value: int(value),
        )
        if output_path is None:
            print(encoded)
            return

        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        with open(output_path, "w") as handle:
            handle.write(encoded)
            handle.write("\n")
    except ValueError as error:
        print("error: %s" % error, file=sys.stderr)
        print(_usage(), file=sys.stderr)
        sys.exit(2)


if "LVC_CORE_LIFECYCLE_NO_MAIN" not in globals():
    main()
