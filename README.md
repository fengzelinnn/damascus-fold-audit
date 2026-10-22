# Damascus Fold Audit — A 组参考工作台

此仓库提供冻结论文的**可行性检查、独立算术参考实现和 A 组实验工具**。它尚不是完整、可用于存储保证的 Damascus Fold 部署实现。没有正式性能结果，没有已经审定的安全参数。

当前已实现原稿两阶段折叠、奇偶一致性检查、整数终端范数与全部模块坐标 opening 的数学路径。测试使用显式挑战和已给定 ternary 见证。文件 codec、canonical protocol wire、Fiat–Shamir 实例、认证 epoch/时限/重放接口仍待决定；不能把数学测试当成完整 Prove/Verify。

## 先看这些文件

- [可行性结论](docs/feasibility.md)：现稿充分条件要求 `log2(q)>M²+7+log2(B)`；这不是协议固有下界。`q>2beta_ext` 不证明 SIS 安全。
- [最小设计及待确认项](docs/design.md)：D1–D6 的边界，不擅自采用候选提取界或分块。
- [源码与论文逐式对应](docs/protocol-correspondence.md)及[旧实现独立审计](docs/legacy-audit.md)。
- [A1–A5 数据与绘图](docs/a-group.md)、[ADJ21/ePoSt 来源](docs/baselines.md)、[部署命令与限制](docs/deployment.md)。

## 本地运行

核心只需 Python 3.12，无第三方运行依赖。在仓库目录执行：

```bash
python -m unittest discover -s tests -v
python -m damascus_a preflight --output runs/local-preflight.json
python -m damascus_a correctness --d 2 --k 2 --cases 4 --output runs/local-correctness
```

全部测试包含可选绘图测试；若尚未安装绘图依赖，先运行 `python -m pip install -r requirements-plot.lock`，或使用部署文档中的核心测试命令。当前云环境已有这些依赖；新环境安装因网络代理限制未验证。

正确性运行输出原始 JSON/CSV，明确 `data_kind=correctness_test`；它们不能送入论文图表。新建不同输出目录进行重复运行，防止覆盖。

```bash
python -m damascus_a validate --d 2 --T 4 --k 2 --q 257
python -m damascus_a.plotting --output outputs/a-group-empty
```

第一条会正确拒绝不满足现稿模数界的输入。参数检查器即使没有发现攻击也只报告安全性待审。GPU 实现尚未提供；`--backend gpu` 默认报错，只有显式 `--allow-cpu-fallback` 才会运行 CPU，并记录原因。`benchmark` 命令保持关闭。

## 数据与发布约束

A1 统计真实 wire 字节；A2 包括完整 Verify 的最后 opening；A3 使用连续新 epoch；A4 记录两个实际平台的资源与失败；A5 分开语义、参数、来源和硬件。空白版式和醒目标记的测试夹具不是论文结果。Libertine/newtx 字体缺失时预览标记 fallback，publication 导出拒绝。

计划中的 i5 + RTX 4060 Ti 和 i9 + RTX 3070 平台，其确切 CPU/RAM/VRAM/OS 尚未核实。没有在用户机器运行，没有跨地域部署。正式性能采集需另行满足协议和平台门槛。

公开仓库只含本项目代码、测试、文档、依赖许可和测试夹具；论文原件、原始机器日志、敏感配置及旧源码快照均排除。论文原始 SHA-256 见 [manifest](sources/paper/manifest.json)。项目自身许可证尚待所有者选择；依赖许可见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
