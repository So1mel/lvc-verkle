# LVC-Verkle Sage 参考实现

这是 LVC-Verkle 无人机认证方案的 SageMath 参考实现。

已实现算法：

- `Setup`
- `Register`
- `Authenticate`
- `Verify`
- `Revoke`


## 环境要求

- SageMath 10.x，并且命令行中可以直接运行 `sage`

检查环境：

```sh
sage reference/sage/sanity_check.sage
```

## 快速运行

运行核心功能测试：

```sh
./run_demo.sh
```

等价命令：

```sh
sage reference/sage/run_all_tests.sage
```

## 运行实验

生命周期实验需要显式传入 JSON 参数：

```sh
sage reference/sage/run_lvc_experiment.sage \
  --config reference/configs/nist_experiment.json \
  --output output/lvc_experiment_report.json
```

参数 sweep：

```sh
sage reference/sage/run_parameter_sweep.sage \
  --config reference/configs/nist_sweep.json \
  --output output/lvc_parameter_sweep.json
```

当前默认配置是 NIST 风格的 Sage 实验参数，使用 `q = 8380417` 和
256-bit nonce。它用于论文实验，不是部署参数。

## 文件结构

- `reference/sage/lvc_lattice.sage`：核心实现
- `reference/sage/run_all_tests.sage`：核心测试
- `reference/sage/run_lvc_experiment.sage`：生命周期实验
- `reference/sage/run_parameter_sweep.sage`：参数 sweep
- `reference/configs/nist_experiment.json`：实验参数
- `reference/configs/nist_sweep.json`：sweep 参数
- `reference/configs/schemas/`：本地 JSON schema

## 许可证

MIT，见 `LICENSE`。
