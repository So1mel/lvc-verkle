# LVC-Verkle Sage Reference

SageMath reference implementation for the LVC-Verkle UAV authentication scheme.

Implemented algorithms:

- `Setup`
- `Register`
- `Authenticate`
- `Verify`
- `Revoke`

## Requirements

- SageMath 10.x available as `sage`

Check the environment:

```sh
sage reference/sage/sanity_check.sage
```

## Quick Run

Run the core smoke test:

```sh
./run_demo.sh
```

Equivalent command:

```sh
sage reference/sage/run_all_tests.sage
```

## Run An Experiment

The experiment script requires an explicit JSON config:

```sh
sage reference/sage/run_lvc_experiment.sage \
  --config reference/configs/nist_experiment.json \
  --output output/lvc_experiment_report.json
```

Parameter sweep:

```sh
sage reference/sage/run_parameter_sweep.sage \
  --config reference/configs/nist_sweep.json \
  --output output/lvc_parameter_sweep.json
```

The provided config is a NIST-style Sage experiment profile using
`q = 8380417` and 256-bit nonces. It is intended for paper experiments, not
deployment.

## Files

- `reference/sage/lvc_lattice.sage`: core implementation
- `reference/sage/run_all_tests.sage`: core tests
- `reference/sage/run_lvc_experiment.sage`: lifecycle experiment
- `reference/sage/run_parameter_sweep.sage`: parameter sweep
- `reference/configs/nist_experiment.json`: experiment config
- `reference/configs/nist_sweep.json`: sweep config
- `reference/configs/schemas/`: local JSON schemas

## License

MIT. See `LICENSE`.
