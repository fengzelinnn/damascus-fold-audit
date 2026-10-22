# Damascus Fold A：隔离实现设计与待确认事项

日期：2026-10-22。仅以 `sources/paper/manifest.json` 指定的原始 main.tex/PDF 为论文依据。当前范围是可行性、确定公式的参考内核、正确性测试和 A 组实验工具；正式性能采集等待两台本地平台准备。

## 已确定约束

- 原 BPoSt 目录、分支、提交保持不变。新项目为 `/workspace/damascus-fold-a`，本地分支 `local/damascus-a`。
- 现稿 `beta0=1`, `T>=4` 且为二次幂，`N0=n0=2^d`。保留四孩子提取界、原始 L/R 定义、奇偶检查、整数终端范数。
- 先用 Python 任意精度整数实现独立数学参考内核，避免把固定 CRT 当成现稿模数。此内核不代表最终优化 Rust/CUDA 性能。
- 不复用旧图，不读取其像素或矢量取数；不分析 B 组。没有跨地域部署或付费资源。
- 仅进行真实小规模单元/差分测试；任何布局夹具必须标为 `fixture`，禁止成为论文数据。
- 原论文与旧源码快照只保留本地并从上传清单排除。只提交本项目代码、测试、配置模板、文档及来源哈希。

## 最小模块

1. `parameters.py`：按现稿验证数学条件；输出界、位宽、明显 SIS 攻击筛查和未审定状态。通过不等式不等于安全。
2. `algebra.py`：模 q 负循环卷积、模块内积、乘当前环变量、奇偶拆分。见 main.tex 551–571。
3. `fold.py`：给定测试挑战序列的 RoundProve/公开 RoundUpdate 和终端检查。整数见证不做模约简；公开项使用规范剩余类。此数学内核不冒充已认证 epoch 的完整协议。
4. `encoding.py`：可独立测试的严格长度前缀与整数编码原语；最终 wire profile、文件 codec、哈希 suite 未批准前不封装成可用于论文的 protocol。
5. `backend.py`、`telemetry.py`、`cli.py`：显式 CPU reference/GPU 请求与 fallback 原因；真实测试日志；正式 benchmark 默认关闭。
6. `aggregate.py`、`plotting.py`：独立日志验证与聚合、A1–A5 图形脚本、空白可编辑 PPT 和矢量 PDF；没有数据即显示没有数据。
7. 两平台预检与运行脚本：读取实际 CPU/RAM/GPU/OS，不能填入未核实规格。无远程执行。

## 核心正确性验收

向量阶段 L=<fL,gR>、R=<fR,gL>，witness fL+x fR、generator gL+x^-1 gR。
多项式阶段 L=<fe,go>、R=<fo,ge>（L 内不含 Y），检查 odd(Ctilde)=L+R；witness fe+y fo、generator ge+(Y/y)go；承诺 E+(Y/y)L+yR。
每个阶段与直接重算 commitment 独立比对；终环 Y=-1 必须正确处理。反例包括交换 L/R、漏 Y、损坏奇偶项、维度错误、非规范剩余类、错误整数 opening 与超范数值。

## 必须由用户确认后才能进入完整部署协议的选择

| 编号 | 待确认的具体问题 | 建议与当前处理 |
|---|---|---|
| D1 | 原始字节如何映射到 ternary 系数；字节顺序、padding、原长绑定 | 可选逐 bit 映射 0/1（每 byte 8 系数）或每 byte 6 个平衡三进制系数；不默认选，不处理真实文件 |
| D2 | canonical wire profile 和 Fiat–Shamir 哈希实例 | 提议带版本/类型/长度的二进制格式与 SHAKE256 无偏取值到 1..T；当前只做原语测试，协议格式待批准 |
| D3 | 具体安全参数、目标安全位数、k、q，以及全 indexed levels 的攻击筛查 | 不给未核实安全配置；参数验证器永远不声称安全 |
| D4 | 是否改用两孩子返回父证书候选，或固定深度全块分块 | 两者均改变待确认边界；只报告可行性，不修改或采用 |
| D5 | certified seed、epoch deadline、可信接收时间、重放状态的本地实验适配 | 论文需要外部认证上下文；不能用 prover 自报时间/布尔值替代认证 |
| D6 | 两平台确切 CPU/RAM/VRAM/OS 与最终基准构建 | 等本地预检，不假设；GPU实现需参数确定后进行差分验证 |

用户手动创建并明确确认公开发布到 `fengzelinnn/damascus-fold-audit`。首次通过 Contents API 新建 README.md 曾被拒绝：403 `Resource not accessible by integration`。用户随后确认现有连接器授权已调整；再次只读核实身份、public、默认 main、空仓库与分支后，获准的一次重试成功。第一阶段源码已正常提交至 [788c0942c613eac75c616847f9856dc53f4690a6](https://github.com/fengzelinnn/damascus-fold-audit/commit/788c0942c613eac75c616847f9856dc53f4690a6)，71 个文件的目录树与本地已测试提交 `fc02477c89350bb5d070e5e5842a817ccc3febdb` 完全一致；没有强推或覆盖用户文件。较早的离线阶段包保留当时 403 的历史状态，本段为恢复发布后的状态更新。公开实现可能关联未发表研究，原论文、Drive定位信息、原始日志、服务器配置及旧源码均排除。

## A 组图及实验

| 图 | 采集内容 | 布局 |
|---|---|---|
| A1 | 真实序列化完整 proof、每轮 record、registration 的字节数；记录 codec/wire/profile | 文件字节数—序列化字节折线，完整proof/单轮/注册分线或分面 |
| A2 | 完整 Verify 的解析与上下文、挑战、generator replay、commitment/parity、norm、opening；total包围全部 | 冷启动/缓存分组堆叠柱，显式计时剩余项 |
| A3 | 每次从注册文件开始的新 certified epoch，真实 setup 与逐次 prove/verify | 横轴审计次数，纵轴 (setup+累计prove+verify)/次数；单独标明是否摊销setup |
| A4 | 每平台每规模的 peak RSS、采样VRAM、成功/超时/OOM/参数拒绝 | 两平台分面，资源曲线及失败标记；显存采样峰值不伪称精确峰值 |
| A5 | ADJ21 公开低存储PoR与ePoSt的协议/参数/保证/已发表数据/本地实测来源 | 语义与来源先分组；不同硬件不按秒数混排 |

全部灰度、线型与纹理区分；最终使用 Libertine + newtx 数学字体。缺字体时预览显式标注 fallback，publication 导出必须失败关闭。
