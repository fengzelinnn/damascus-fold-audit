# Damascus Fold A：完整参考协议设计与部署边界

日期：2026-10-22。论文依据仍为 sources/paper/manifest.json 冻结的原始 main.tex/PDF。当前已实现从原始字节注册到 epoch 证明、完整公开验证和一次性准入的 CPU Python 参考流程；显式 correctness 策略可以执行，默认 strict 策略因尚无获批安全参数而拒绝。完整工程路径不等于部署就绪，也不是正式性能结果。

## 保持的约束

- 原 BPoSt 目录、分支和提交不变；隔离项目位于 /workspace/damascus-fold-a。
- 保留 β₀=1、二次幂 T≥4、N₀=n₀=2ᵈ、四孩子提取界、原始 L/R 定义、奇偶检查和整数终端范数。没有采用两孩子候选或独立分块证明。
- Python 任意精度整数内核独立实现现稿公式。没有移植旧固定 CRT、旧源码或旧计时；没有实现面向现稿参数的优化 Rust/CUDA 后端。
- 不复用旧图、不取其像素/矢量数据、不分析 B 组；没有跨地域部署或付费资源。
- 正确性运行与 fixture 不能成为论文性能数据；正式采集仍未授权。两台本地平台规格必须通过预检获得。
- 原论文、旧源码快照、私有定位信息、真实日志及服务器配置保留本地并排除上传；本次文档更新不执行发布。

## 已实现的完整执行路径

| 模块 | 当前能力与边界 |
|---|---|
| parameters.py | 现稿充分不等式、模数状态及明显 SIS 攻击审计；通过不等式不等于安全审定。 |
| algebra.py、fold.py | 负循环环/模块算术、分阶段折叠、公开生成元重放、parity、整数 norm 和全部 k 坐标 opening；保留显式测试挑战 API。 |
| codecs.py、file_codec.py | 显式 FileCodec 合约、descriptor 一致性和规范编码像检查；已实现用户批准的 Ternary32Codec。 |
| protocol_types.py、encoding.py、wire.py | 不可变公共类型及完整 DF-wire-v1：严格版本/类型/长度 framing、规范整数/剩余类、记录索引、资源预检。 |
| transcript.py | DF-SHAKE256-v1：完整规范 context、完整有序前缀及当前交叉项的域分离输入；无偏取值到 1…T。标识摘要不替代挑战输入。 |
| environment.py | 抽象 epoch/完整 proof 接收证据验证接口、结果绑定检查和 SQLite 原子持久化准入账本；没有默认接受的认证提供者。 |
| protocol.py | setup、register_bytes/register_encoded、epoch_init、prove_epoch、verify_published、verify；默认 strict 拒绝，显式 correctness 保留完整参数审计。 |
| protocol_artifacts.py | 从实际 wire bytes 分账完整 proof、逐轮记录与整数opening，另列 registration/context/外部证据；不等于网络流量测量。 |
| backend.py、telemetry.py、cli.py | CPU reference 路径及诊断/实验接口；GPU 未实现，默认请求报错，显式 fallback 必须记录实际 CPU 与原因。 |
| aggregate.py、plotting.py、平台脚本 | 独立日志验证、A1–A5 图与导出、两平台预检；缺数据或部署依赖时不填造数据。 |

Setup 默认用系统随机源逐系数采样生成元，分配前执行资源预检与参数审计；注入采样器仅作显式测试工具。Register 验证 codec descriptor、原始长度、三值系数/形状及完整规范往返，再计算初始承诺。每次 EpochInit/Prove 从原始登记见证和生成元开始，不接续上一 epoch 的终态。

注册 wire 包含完整参数和初始生成元；proof 仅包含32字节上下文标识、恰好 d 个有索引记录及有符号整数终值，不重复 g₀。完整 context 和外部证据单独列为实际对象，不能视为免费的网络开销。

Verify 严格解析 proof，校验外部 context 与完整 proof 发布证据，重建全部生成元和承诺，每轮先检查奇部再派生多项式挑战，最后检查未经模约减的整数 norm 和全部 k 坐标终值等式。verify_published 可重复历史验证；verify 在所有检查成功后才原子准入，错误证明不消耗 epoch。准入键绑定 registration 与 epoch，改变 seed/deadline 不产生新名额。

## 已批准的 Ternary32Codec

用户已批准该三值 codec 实例，条件是不改变冻结论文的折叠公式、提取界或安全/性能主张。它具体化现稿公开 codec 参数，不将被注释的论文示例当作生效规范。

- 顺序块最多32字节，以 unsigned big-endian 整数解释。
- r 字节块恰好用 c(r)=min{c:3ᶜ≥2⁸ʳ} 个三进制位，即 ceil(log₃256ʳ)；c(0)=0，c(32)=162。
- 三进制位低位在前；数字 0/1/2 映射到系数 0/1/−1，不足的高位补零。
- 尾块按实际 r 编码；各块按文件顺序串接，以 polynomial_index·n+degree 排列，整个见证余量补零至 M=4ᵈ。
- 所需系数为 162·floor(ℓ/32)+c(ℓ mod 32)。容量不足、超出 r 字节值域的剩余码字、非零全局 padding 均拒绝。
- 使用 file_codec.py 中完整 TERNARY32_DESCRIPTOR，pp.codec 与实现必须逐字匹配；descriptor 与原始长度 ℓ 一起进入完整 context 绑定。
- 注入性包含登记长度：不同长度的全零字节可能产生相同 padded witness，但 ℓ 不同。省略 ℓ 后不能声称 witness 单独区分所有变长文件。

32字节只是局部编码转换块，不是独立 commitment、epoch 或证明分块。iterencode 最多把32字节转换成整数；encode 仍物化整个 N×n 见证，decode 仍物化原始字节，不由此推导 GB 级内存或性能可行性。

## 核心正确性与验证边界

向量阶段 L=〈fL,gR〉、R=〈fR,gL〉；见证 fL+x·fR，生成元 gL+x⁻¹·gR。

多项式阶段 L=〈fe,go〉、R=〈fo,ge〉，L 内不含 Y；检查 odd(C̃)=L+R；见证 fe+y·fo，生成元 ge+(Y/y)·go，承诺 E+(Y/y)·L+y·R。终环 Y=−1 仍按负循环环处理。

测试覆盖独立承诺重算、非零奇部、交换 L/R、漏 Y、形状/剩余类错误、完整 context/prefix 替换、整数 alias/超范数、全部 k 坐标、记录顺序、接收证据替换和准入竞争。codec 专项覆盖独立三进制 oracle、32字节边界、前导零、空文件、容量、非法码字和短读/EOF。集成测试结果由验证文档维护，本设计不把正确性测试转换成安全结论。

## 决策状态与剩余依赖

| 编号 | 当前状态 | 保留边界 |
|---|---|---|
| D1：文件 codec | Ternary32Codec 已批准并实现；不再待选逐bit或逐byte候选 | 保留 descriptor/ℓ 绑定与合法编码像检查。 |
| D2：wire/Fiat–Shamir | DF-wire-v1、DF-SHAKE256-v1 已实现 | 全 context/prefix 与规范解析属于版本契约；未知 suite 拒绝。 |
| D3：具体安全参数 | 尚无获批 profile；strict 默认拒绝 | q>2β_ext、素性筛查或测试通过不能代替各 indexed levels 的安全评审。 |
| D4：两孩子提取/独立证明分块 | 未采用 | 不把32字节 codec 转换块误记为协议分块。 |
| D5：认证与接收证据 | 接口、绑定校验和持久化准入已实现；生产 provider 未配置 | 需要真实证书及同一时间/顺序域的完整 proof 认证及时接收证据。 |
| D6：硬件/GPU/正式采集 | 规格待预检；新 GPU 未实现；正式采集未授权 | 参考诊断不标为优化 Rust/CUDA 或论文测量。 |

外部接口可检查证据绑定，不能仅靠签名、当前时钟或调用方布尔值证明 cutoff 信息边界、seed 条件均匀性及存储时间安全。deadline 由 provider 定义其 opaque 值和边界语义；测试 provider 只验证接口行为。

## A 组图及实验契约

| 图 | 采集内容 | 布局 |
|---|---|---|
| A1 | 实际序列化 proof/每轮record/registration；另列 context/外部证据，记录 codec/wire/profile | 文件字节数—序列化字节折线，按对象分线或分面 |
| A2 | 完整 Verify 的解析与上下文、挑战、generator replay、commitment/parity、norm、opening；total 包围全部，含 other | 冷启动/缓存分组堆叠柱 |
| A3 | 每次从原始注册开始的新认证 epoch，真实 setup 与逐次 prove/verify | (setup+累计prove+verify)/次数；明确摊销范围 |
| A4 | 每平台每规模的 peak RSS、采样VRAM、成功/超时/OOM/参数拒绝 | 两平台分面，资源曲线及失败标记 |
| A5 | ADJ21 公开低存储PoR与ePoSt的协议/参数/保证/已发表数据/实测来源 | 语义与来源先分组；不同硬件不按秒数混排 |

完整验证及互斥阶段计时接口已实现；当前数值只用于明确标记的正确性诊断，不证明存储时间安全或正式性能。图形使用灰度、线型及纹理；最终使用 Libertine + newtx 数学字体。缺字体时预览标注 fallback，publication 导出失败关闭。

## 发布边界

用户此前已批准公开目标仓库 fengzelinnn/damascus-fold-audit。第一阶段发布及权限恢复属于已记录历史；本次新增实现的审查、集成测试和正常 fast-forward 发布由主流程统一执行。原论文、Drive 定位信息、原始日志、服务器配置及旧源码始终排除。本次文档任务没有 commit、push 或远端修改。
