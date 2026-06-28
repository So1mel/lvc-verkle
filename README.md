# LVC-Verkle Sage Implementation

[中文](README.zh-CN.md) | English

SageMath implementation of the LVC-Verkle UAV authentication scheme.

Implemented algorithms:

- `Setup`
- `Register`
- `Authenticate`
- `Verify`
- `Revoke`

The implementation lives in `reference/sage/lvc_lattice.sage`. Experiment
parameters are supplied through JSON files under `reference/configs/`.

## Requirements

- SageMath 10.x
- `sage` available in the shell

Check the local Sage environment:

```sh
sage reference/sage/sanity_check.sage
```

## Tests

Run the test suite:

```sh
./run_demo.sh
```

Equivalent command:

```sh
sage reference/sage/run_all_tests.sage
```

## Experiments

Run the lifecycle experiment:

```sh
sage reference/sage/run_lvc_experiment.sage \
  --strict-parameters \
  --config reference/configs/nist_experiment.json \
  --output output/nist_q2147483647_full_experiment_report.json
```

Run the parameter sweep:

```sh
sage reference/sage/run_parameter_sweep.sage \
  --strict-parameters \
  --config reference/configs/nist_sweep.json \
  --output output/nist_q2147483647_sweep_report.json
```

Run only the core lifecycle:

```sh
sage reference/sage/run_core_lifecycle.sage \
  --strict-parameters \
  --config reference/configs/nist_experiment.json \
  --output output/nist_q2147483647_core_lifecycle_report.json
```

The checked-in NIST-style profile uses:

```text
n = 3
q = 2147483647
nonce_bytes = 32
sample_pre.omega_factor = 0.0001
authentication.omega_factor = 1.08
```

## Files

- `reference/sage/lvc_lattice.sage`: scheme implementation
- `reference/sage/run_all_tests.sage`: test entrypoint
- `reference/sage/run_lvc_experiment.sage`: lifecycle experiment
- `reference/sage/run_parameter_sweep.sage`: parameter sweep
- `reference/sage/run_core_lifecycle.sage`: short lifecycle run
- `reference/configs/nist_experiment.json`: lifecycle parameters
- `reference/configs/nist_sweep.json`: sweep parameters
- `reference/configs/schemas/`: local JSON schemas

## License

MIT. See `LICENSE`.
