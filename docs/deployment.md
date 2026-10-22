# 两台本地平台：参考工作台部署

当前可部署的是参考工作台。完整 PoSt Prove/Verify、优化 Rust/NTT/CUDA 后端和正式性能任务均未交付；D1–D6 尚待确认。以下命令不会启动正式采集，也不会远程操作用户机器。

## 环境与依赖

核心要求 CPython 3.12，仅用标准库。云端已用 3.12.14 运行。精确平台规格不要从 i5/i9 或 GPU 型号简称推断；两个 `configs/platform-*.json` 保留 null，等本地 preflight 输出再核实。

核心测试可不安装绘图依赖：

```bash
python -m unittest discover -s tests -p test_algebra.py -v
python -m unittest discover -s tests -p test_fold.py -v
python -m unittest discover -s tests -p test_parameters.py -v
python -m unittest discover -s tests -p test_encoding.py -v
python -m unittest discover -s tests -p test_backend.py -v
python -m unittest discover -s tests -p test_cli.py -v
python -m unittest discover -s tests -p test_release.py -v
python -m unittest discover -s tests -p test_export_preview.py -v
```

可选绘图环境（在独立虚拟环境内）：

```bash
python -m venv .venv
# Linux/macOS:
. .venv/bin/activate
# Windows PowerShell 使用 .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-plot.lock
python -m unittest discover -s tests -v
```

`requirements-plot.lock` 固定已测试的直接和传递依赖版本，`pyproject.toml` 同步这些版本。云端 `uv lock` 无法通过网络代理读取 PyPI，因此未完成下载包哈希锁定或全新环境安装验证。不能声称 offline wheelhouse 或可复现构建已经完成；下次允许联网的环境需保存对应 wheel 哈希并验证干净安装。没有扩大网络权限或生成凭据。

核心 wheel 已在云端用现有 setuptools 离线构建，并在独立安装目录完成两例正确性 smoke test。这不验证可选绘图依赖的全新安装。

Libertine/newtx 字体包需在绘图平台具备。当前云环境未找到，只有显式标注 fallback 的预览；`--publication` 不会静默替换字体。参考 `docs/a-group.md` 的字体门槛和 PPT/PDF 限制。

## 平台 1 和平台 2

在每台机器单独解压源代码包或正常 clone 已核实公开仓库，然后运行以下任一脚本。脚本记录实际环境，输出路径自动分开；不会上传任何日志。

```bash
bash scripts/run_local.sh
```

Windows PowerShell：

```powershell
powershell -NoProfile -File scripts/run_local.ps1
```

PowerShell 路径未在本云 Linux 环境执行，必须在用户实际 Windows 平台验证。用户若采用其它 OS，先运行 Python 通用命令，不假设 WSL、CUDA、驱动或显存容量。

手动等价命令：

```bash
python -m damascus_a preflight --output runs/platform-1/preflight.json
python -m damascus_a correctness --d 2 --k 2 --cases 4 --output runs/platform-1/correctness
python -m damascus_a preflight --output runs/platform-2/preflight.json
python -m damascus_a correctness --d 2 --k 2 --cases 4 --output runs/platform-2/correctness
```

分别在对应机器执行各自那两条，不能在同一机器运行两组后冒充两台平台。`preflight` 不采集 hostname、用户名、GPU UUID 或序列号。RSS 是进程生命周期高水位；当前不采集运行期 GPU 显存。VRAM 预检容量与峰值显存是不同指标。

## 后端与实验门槛

只有 `cpu-reference` 可执行。请求 `gpu` 默认立即报错；显式 `--allow-cpu-fallback` 才转换成 CPU，并将 requested、actual、fallback、reason 写日志。没有声称 GPU 加速有效，更没有 CPU/GPU 秒数比较。

`python -m damascus_a benchmark` 非零退出。完整协议部署前需批准文件codec、wire/FS、认证seed与deadline适配、具体安全参数，以及是否采用任何论文改动。正式性能采集还需用户确认平台就绪；本工具不能通过修改一个布尔值变成经审定协议。

## 打包与敏感数据隔离

```bash
python scripts/package_release.py --manifest artifacts/release-files.json --output artifacts/damascus-fold-audit-source.tar.gz
```

脚本仅打包明确允许的源码/测试/文档/夹具/许可证，拒绝符号链接与明显凭据模式，并生成逐文件 SHA-256 清单。它不代替人工审查。排除原始论文、Drive定位信息、旧源码、runs/、outputs/、原始服务器日志及秘密配置。仓库已公开，未发表实现可能与研究关联；公开发布范围已由用户确认，仍维持这些排除项。

原始论文只在本地可信副本存在时校验：`python scripts/verify_sources.py`。公开源码包不携带原论文，所以未手动材料化时该命令返回 `not_materialized` 和非零退出，属于预期状态。
