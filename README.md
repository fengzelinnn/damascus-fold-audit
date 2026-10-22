# Damascus Fold Audit — 论文协议与 A 组实验工作台

此仓库实现冻结论文的完整 CPU 参考执行路径：Setup、合法文件登记、EpochInit、Prove、规范序列化、完整前缀 Fiat–Shamir、Verify，以及外部证据验证接口和持久 epoch 接收登记。文件使用已确认的流式 32 字节三值编码，折叠公式、奇偶检查、整数终端范数和全部 k 个 opening 坐标均按现稿实现。

**执行正确性已经可测；存储时间保证仍需要经审定的安全参数及真实外部认证/时间条件。** 当前没有经批准的具体安全参数配置，所有协议入口默认严格拒绝；只有显式 `policy='correctness'` / `--correctness-only` 执行小规模测试并保留完整参数审计。测试证据适配器标为 `TEST_ONLY`，不提供可信时间。没有正式性能结果，也没有 GPU 算术后端。

## 已实现与对应说明

- [完整协议与编码规范](docs/full-protocol.md)：实际 API、wire/挑战、完整 Verify、外部证据边界。
- [可行性结论](docs/feasibility.md)：现稿充分条件要求 `log2(q)>M²+7+log2(B)`；它不是协议固有下界，`q>2beta_ext` 也不证明 SIS 安全。
- [逐式对应](docs/protocol-correspondence.md)、[原实现独立审计](docs/legacy-audit.md)、[剩余决策](docs/design.md)。没有采用候选提取界或分块协议。
- [A1–A5 数据与绘图](docs/a-group.md)、[ADJ21/ePoSt 来源](docs/baselines.md)、[部署](docs/deployment.md)、[已执行验证](docs/validation.md)。

## 本地运行

核心只需 Python 3.12，无第三方运行依赖。在仓库目录执行：

```bash
python -m damascus_a preflight --output runs/local-preflight.json
python -m damascus_a protocol-correctness --correctness-only --epochs 2 --output runs/local-protocol
python -m damascus_a correctness --d 2 --k 2 --cases 4 --output runs/local-algebra
```

完整协议运行生成真实 proof、registration、context、测试证据二进制，以及逐阶段 JSON/CSV 和本地重放登记；每个新 epoch 从原始文件重新开始。完整 Verify 包含最后 opening 和持久接收检查。日志明确是 `correctness_test`，缓存状态为未控制，不能送入论文图表。目录已存在时拒绝覆盖。

```bash
python -m unittest tests.test_protocol tests.test_file_codec tests.test_wire tests.test_transcript tests.test_environment -v
python -m pip install -r requirements-plot.lock
python -m unittest discover -s tests -v
python -m damascus_a.plotting --output outputs/a-group-empty
```

完整测试集包含可选绘图测试。绘图依赖版本已固定；网络代理阻碍了全新环境下载验证及 wheel 哈希锁定，详见部署说明。`--backend gpu` 默认报错，仅显式 `--allow-cpu-fallback` 才运行 CPU 并记录原因。`benchmark` 命令保持关闭。

## 实验与公开内容边界

A1 使用实际序列化字节；A2 分解完整 Verify；A3 使用连续新 epoch；A4 分开记录两台实际平台的资源与失败；A5 区分安全语义、参数、来源和硬件。空白版式和醒目标记的测试夹具不是论文结果。Libertine/newtx 缺失时只生成明确标注 fallback 的预览，publication 导出拒绝。

i5 + RTX 4060 Ti 和 i9 + RTX 3070 平台的确切 CPU/RAM/VRAM/OS 尚未知。没有在用户机器运行或开展跨地域部署。正式性能采集继续等待两台平台及所需协议条件就绪。

公开内容仅含项目代码、测试、文档、依赖许可和测试夹具；排除论文原件、原始机器日志、敏感配置及旧源码快照。冻结论文哈希见 [manifest](sources/paper/manifest.json)。项目许可证待所有者选择；保留的依赖许可见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
