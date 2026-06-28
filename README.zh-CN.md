# LVC-Verkle Sage 实现

中文 | [English](README.md)

这是 LVC-Verkle 无人机认证方案的 SageMath 实现。

已实现算法：

- `Setup`
- `Register`
- `Authenticate`
- `Verify`
- `Revoke`

核心代码在 `reference/sage/lvc_lattice.sage`。实验参数通过
`reference/configs/` 下的 JSON 文件传入。

## 环境

- SageMath 10.x
- 命令行可直接运行 `sage`

检查 Sage 环境：

```sh
sage reference/sage/sanity_check.sage
```

## 测试

运行测试：

```sh
./run_demo.sh
```

等价命令：

```sh
sage reference/sage/run_all_tests.sage
```

## 实验

运行生命周期实验：

```sh
sage reference/sage/run_lvc_experiment.sage \
  --strict-parameters \
  --config reference/configs/nist_experiment.json \
  --output output/nist_q2147483647_full_experiment_report.json
```

运行参数 sweep：

```sh
sage reference/sage/run_parameter_sweep.sage \
  --strict-parameters \
  --config reference/configs/nist_sweep.json \
  --output output/nist_q2147483647_sweep_report.json
```

只跑核心生命周期：

```sh
sage reference/sage/run_core_lifecycle.sage \
  --strict-parameters \
  --config reference/configs/nist_experiment.json \
  --output output/nist_q2147483647_core_lifecycle_report.json
```

当前 NIST 风格参数：

```text
n = 3
q = 2147483647
nonce_bytes = 32
sample_pre.omega_factor = 0.0001
authentication.omega_factor = 1.08
```

## 文件

- `reference/sage/lvc_lattice.sage`：方案实现
- `reference/sage/run_all_tests.sage`：测试入口
- `reference/sage/run_lvc_experiment.sage`：生命周期实验
- `reference/sage/run_parameter_sweep.sage`：参数 sweep
- `reference/sage/run_core_lifecycle.sage`：核心生命周期实验
- `reference/configs/nist_experiment.json`：生命周期参数
- `reference/configs/nist_sweep.json`：sweep 参数
- `reference/configs/schemas/`：本地 JSON schema

## 许可证

MIT，见 `LICENSE`。
