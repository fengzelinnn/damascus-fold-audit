# 指定 legacy commit 的独立只读审查

审查对象：[fengzelinnn/damascus000@4066112c7663201c412562df9be6b87497a3ec32](https://github.com/fengzelinnn/damascus000/commit/4066112c7663201c412562df9be6b87497a3ec32)。审查日：2026-10-22。论文对照：冻结的 [main.tex](../sources/paper/main.tex)，SHA-256：481a41f1bb3c7dd0f971d6cee87151242910214fda3315887778b48dc9da9bd0。

范围：通过 GitHub connector 以完整 commit ref 获取18个必要源码文件；逐个比对 Git blob SHA-1。未执行、编译或测试旧代码，未运行性能采集，未访问 B 组日志或废弃图，未修改旧仓库，未创建远端或 push。源码快照在 [sources/legacy](../sources/legacy/)，仅用于证据，不是新实现来源。代码行号全部对应该 commit；论文行号对应上述冻结版本。

## 结论

| 问题 | 确定结论 | 主要证据 |
|---|---|---|
| 是否真实 Rust/NTT/CRT | 有真实算术实现；不是仅生成模拟时长的脚本。但不能证明任何历史运行或性能数字 | ntt.rs:112–223,400–426；benchmark:199–259 |
| Verify 是否漏最终 opening | CSV/summary 只加总逐轮 update；final opening 在计时外。Criterion 路径完全不调用 final opening | benchmark:83–92,255–259,342–362 |
| GPU OFF 是否可靠 | 此 commit 已修复折叠调用链；初始注册仍固定允许 GPU。GPU ON 也可能回退 CPU | prover.rs:83–90；sis.rs:130–131,179–187；ntt.rs:157–182 |
| 13-byte codec 与 β₀=1 | 不一致。旧系数取 0…2¹⁰⁴−1，不是三元系数 | config.rs:8；io.rs:51–54；field.rs:65–70；paper:403–407 |
| 完整 transcript 前缀 | 未实现现稿完整 context/prefix；旧 challenge 只哈希当前承诺、本对交叉项等 | transcript.rs:7–19,42–62；paper:448,520–530 |
| 1…T 小标量挑战 | 未实现。旧 challenge 为 hash 模 q 后拒零 | transcript.rs:50–74；paper:403–405 |
| 整数 terminal norm | 未实现。旧 opening 是 Fp，final verifier 没有 norm check | prover.rs:33,133–137；verifier.rs:122–133；paper:611–623 |
| odd(C)=L+R | 旧 verifier 丢弃 odd。但旧 L 含 Y，不能直接附加该等式 | prover.rs:233–263,408–418；verifier.rs:89–103；paper:561–571 |
| canonical 编码 | Fp 反序列化将任意16-byte值模 q，允许同一元素多种编码 | field.rs:121–127；paper:586,612 |

该 commit 的结果即使来自真实执行，也不能直接标为现稿协议的实现结果。它实现了较早的折叠算术原型。这不等价于“全部历史数据都是 simulation”，也不是对现稿安全证明的完整审查。

## 1. 真实算术路径与证据边界

- [Cargo.toml](../sources/legacy/Cargo.toml):1–27 声明 Rust crate、bincode、blake3、rayon、num-bigint 和 Criterion。
- [field.rs](../sources/legacy/src/algebra/field.rs):12,16–20,41–62,229–257 使用 u128 域元素、q=2¹¹²−75 的实际 limb 乘法、伪梅森约减及 BigUint hash-to-field。
- [poly.rs](../sources/legacy/src/algebra/poly.rs):134–140 按开关选择 NTT/CRT 或朴素负循环卷积。
- [ntt.rs](../sources/legacy/src/algebra/ntt.rs):123–154 将长度 n 多项式补零到2n，对8个辅助素数建立 NTT 计划；210–219 做两次 forward NTT、逐点乘法、inverse NTT 和 a[i]−a[i+n] 负循环归约；185–192、400–426 以 CRT 重构回 q。
- [sis.rs](../sources/legacy/src/commitment/sis.rs):146–166 实际计算生成元与见证的环乘之和。
- [ntt_kernel.cu](../sources/legacy/cuda/ntt_kernel.cu):79–118,202–247 包含蝶形、逐点乘法和实际 kernel launch；[fold_kernel.cu](../sources/legacy/cuda/fold_kernel.cu):189–206 实际计算 left+right*challenge。
- Benchmark 用 Instant 包围真实 initialize/update；折叠内部同样使用 Instant，而非仅按文件大小套用时长模型。

未运行旧二进制，也没有历史日志/环境关联证据，因此无法确认历史数据实际使用哪条 backend、是否对应此 commit、是否达到所述速度。源码存在测试不表示本次执行过测试。

### CRT 的可证明大维度边界缺口

此项是通用多项式 API 的边界，不应归咎于全部小规模运行。令 P 为 config.rs:9–18 中8个素数的乘积：

    P = 457382208004459228185863060543074006848449056900536100998412935792779329537

旧代码使用 canonical 非负输入0…q−1（ntt.rs:145–147），最后选 modulo P 的中心代表元（414–422）。对所有此类输入保证精确负循环整数系数重构的充分条件是：

    |s_i| ≤ n(q−1)² < P/2
    2n(q−1)² < P

P 为249 bit，满足此界的 n 最大整数为8,482,624，因此 power-of-two n≤2²³足够。源码只检查各素数是否支持2n次单位根（125–129），未检查 CRT 动态范围；该根条件仍放行 n=2²⁴。

静态反例：n=2²⁴，两输入全部系数为q−1。第 n−1 个负循环乘积系数的整数提升 s=n(q−1)² 满足 P/2<s<P。正确模 q 值为 n；源码中心化取 s−P，于是：

    P mod q = 4257386383479885331917584153274572
    旧重构值 = 934910475054942296612912192722665
    正确值   = 16777216

这是独立整数常量推导，不是执行旧代码所得实测输出。对 n≤2²³ 且输入遵守 Fp canonical 不变量的调用，此动态范围问题不适用。是否在历史预处理/内存限制下达到该大维度，没有运行证据。

## 2. Verify 计时与测量含义

[protocol_bench.rs](../sources/legacy/benches/protocol_bench.rs) 有两套不同测量：

1. run_single_scenario：255行启动 Verify timer，256–258只调用 update_commitment，259停止；343仅累加该 duration。verifier 初始化在212行，未计入总和。最终 opening 在356–360行检查，位于 timer 外；362行所谓 end-to-end 只是 preprocess+fold+逐轮verify之和。
2. Criterion verify_all_rounds：83–92行创建 verifier 并回放全部 micro-block，没有 final opening 参数或检查。它包含 verifier 初始化，而 CSV Verify 总计不包含；两者不可混用。

VerifyScenario（13–19行）没有 final opening 字段。verify_payload_bytes（265–267、345行）仅统计 serialized micro-block，不包括终值或context/framing。356行还使用 if let Some：若 opening 缺失，就跳过 final check，而不是报错。正常完整 prover 路径通常产生 opening，但这不是严格完整 Verify 的拒绝语义。

[full_flow.rs](../sources/legacy/examples/full_flow.rs) 同样在75–85行累计 update 时间，100–104行于计时外检查 opening。

Prove timer 还包括 invariant 重算：prover.rs:195–207 包含在 vector timer 内，279–292 包含在 poly timer 内。它们是原型真实额外工作，不只是最小 prover 所需的交叉项与fold。

论文611–623行的 Verify 包含 context/deadline、精确记录数、parity、整数bound与final equation。旧计时既漏终值，也不存在这些新增检查，不能作为现稿完整 Verify 计时。

## 3. GPU 开关：已修复部分与残余混杂

### 此 commit 已正确传递的折叠链

[prover.rs](../sources/legacy/src/protocol/prover.rs):160–175、236–251的4个交叉项，以及195–202、279–286的两次invariant重算，均传 self.gpu_enabled：

    fold_round
    → cross_term_vec(..., ntt_enabled, gpu_enabled)          prover.rs:322–329
    → commit_with_generators_ntt(..., ntt_enabled, gpu_enabled) sis.rs:146–164
    → ring_mul_with_ntt(..., ntt_enabled, gpu_enabled)      module.rs:65–78
    → Poly::mul(..., ntt_enabled, gpu_enabled)              poly.rs:134–139
    → negacyclic_multiply(..., gpu_enabled)                ntt.rs:112,157–182

所以不能对该 commit 再写“fold cross-term NTT无条件尝试GPU”。GPU=false 在此链确实进入 CPU NTT；NTT=false 则进入 CPU 朴素负循环乘法。

见证 vector fold 在prover.rs:343–360由GPU flag和阈值共同控制。341行阈值统计左半部分系数数目；默认4096（config.rs:84；benchmark:108）。最小64×64布局的左半部分为2048，故vector GPU fold即使ON也不触发；NTT backend仍可独立尝试。

### 预处理残留混杂：GPU=false 被丢失

initialize_with_config只传 config.ntt_enabled给注册（prover.rs:83–90），没有传GPU flag：

    initialize_with_config(config.gpu_enabled=false)
    → register_with_ntt(..., config.ntt_enabled)   prover.rs:83–90
    → commit_with_ntt(witness, ntt_enabled)        sis.rs:179–187
    → commit_with_generators_ntt(..., ntt_enabled, true) sis.rs:130–131

因此NTT=ON/GPU=OFF的初始承诺仍可尝试GPU，且benchmark preprocess timer（199–202行）包含它。实际是否执行取决于backend可用；backend不存在或全局禁用时不会执行GPU。便利API commit_with_generators和ring_mul也硬编码允许GPU（sis.rs:143；module.rs:62）。

### GPU ON 标签不证明成功执行 CUDA

- [gpu.rs](../sources/legacy/src/utils/gpu.rs):23–24要求编译backend及设备探测；28–32受DAMASCUS_GPU=0影响。
- 95–137、148–206行在不可用或CUDA失败时返回None，上层静默转CPU。
- [build.rs](../sources/legacy/build.rs):17–19在非Windows构建主机直接return；正常构建路径不生成CUDA backend。Linux上的ON标签不能作为GPU执行证据。
- Benchmark:171–178的标签只来自请求布尔值，没有成功kernel计数。
- NTT=OFF/GPU=ON仅可能加速见证vector fold；poly witness fold及generator fold仍在CPU/Rayon（prover.rs:377–394,421–455）。
- full_flow默认阈值仍为2,097,152（examples/full_flow.rs:24–27），与runtime/bench的4096不同。
- CUDA设备探测被OnceLock缓存（gpu.rs:16–20,27–32）；进程内后续改变环境变量不会自动重新探测。

补充未确认风险：fold_kernel.cu:224–240的设备buffers/capacity为无锁静态全局，Rust安全公共调用也没有互斥。并发调用可能共享覆盖或重分配竞争；本次未证明当前单一prover路径实际并发调用它，不作为已发生故障结论。

## 4. Codec、挑战、整数提升与范数

### Codec保留字节信息，但不满足β₀=1

旧BYTES_PER_COEFF=13（config.rs:8），按13字节little-endian直接打包（io.rs:51–54；field.rs:65–70）。最大满chunk系数2¹⁰⁴−1，比q/2小，故中心提升也仍为2¹⁰⁴−1；中心化不能把它变成三元系数。

io.rs:72–75、100–119以ceil(bytes/13)及最小深度6选择方阵容量。长度记录在statement中，因此该packing可以保持原始字节可恢复性；问题是范数与容量语义不同，不是13 bytes必然发生模约减碰撞。

论文403–407、488行要求公开injective ternary codec、padding/length规则及β₀=1。新方案不能沿用ceil(bytes/13)又声称满足β₀=1，也不能直接复用旧文件大小到轮数的映射。

### 挑战不是小标量集合

旧transcript.rs:50–62将32-byte BLAKE3 digest按little-endian整数模q，66–74仅拒绝0，得到全域非零Fp。没有T参数或1…T映射。现稿403–405要求T=2ᵇ≥4及挑战集合1…T；旧实现无法直接继承该整数范数及extraction条件。

### Terminal response没有整数语义或norm check

旧FinalOpening=FieldElement（prover.rs:33）；witness fold每一步用Fp取模（例如367、426行）；final_opening返回最终模域系数（133–137行）。

verifier.rs:122–133只检查replay轮数、生成元族长度1及g[0]*opening==current_commitment。没有整数opening类型、B计算或绝对值检查，也未显式检查terminal ring_len==1。把Fp直接cast成整数不能恢复未模约减的整数折叠语义。

论文611–623、645–646明确最终传输bounded integer，norm用整数本身，equation才modulo q。论文651–659另要求q>2β_ext；旧112-bit固定q和全域挑战没有落实该条件。具体参数可行性由独立参数审查负责，本报告不主张任何安全位数。

## 5. Transcript：已有绑定与缺失绑定

已有部分：transcript.rs:51–60哈希epoch_seed、长度分隔的vec/poly标签、file_id、epoch_index、round、当前承诺及本阶段L/R；82–89也编码commitment维度。因此不能写成“完全没有transcript binding”。

缺失部分：

- Transcript只有epoch_seed、file_id、epoch_index（7–10行）；challenge方法接收不可变self，不积累记录或transcript hash。
- new将epoch_index固定为0（14–19行）；无外部epoch/deadline绑定。
- 没有吸收完整pp、codec、T、完整stmt、g_0_seed、原始字节长度、d、认证上下文或deadline。com_0在第一轮作为current commitment参与，所以不能说com_0也完全没绑定。
- 每次只有本对L/R；poly challenge没有显式吸收同轮vector pair。过去记录仅可能经压缩后的current commitment间接影响hash。
- “hash当前承诺”不是“规范编码完整前缀并hash”，不能直接据此套用现稿full-prefix Fiat–Shamir论证。

论文448定义ctx=(pp,stmt,e,ρ_e,Δ_e)及Π_j；520–530、591–600指定精确stage输入。poly输入包含同轮两对cross-terms。接口差异确定；本次没有为全部差异构造实际伪造或证明可利用性。

## 6. 逐式L/R对照：不能机械补odd检查

在当前round环中写f=a+Xb、g=c+Xe，子环变量Y=X²；对所有条目求和：

    C = E + X O
    E = Σ(a c + Y b e)
    O = Σ(a e + b c)

现稿main.tex:561–571：

    L_paper = Σ a e
    R_paper = Σ b c
    O = L_paper + R_paper                       必须检查
    f' = a + y b
    g' = c + (Y/y)e
    C' = E + (Y/y)L_paper + y R_paper

旧prover.rs:408–418先把odd generator做mul_by_x。该操作在子环中乘变量Y（poly.rs:144–153）。因此236–251实际构造：

    L_old = Σ a (Y e) = Y L_paper
    R_old = Σ b c     = R_paper
    f' = a + y b
    g' = c + y⁻¹(Y e)
    C' = E + y⁻¹ L_old + y R_old

固定相同y时，后3个诚实更新式与现稿代数相等。旧prover两次invariant重算检查这个诚实关系。但须区分：

1. L_old≠L_paper；hash吸收的字段值也不同，不能声称两套实际transcript或挑战逐轮相同。
2. 旧verifier:89–103，尤其98行只保留(c_even,_)并丢弃odd。没有检查O与交叉项关系。诚实prover自检不能替代面对恶意prover的verifier parity检查。
3. 保持旧字段定义时，正确式是O=Y⁻¹L_old+R_old。Y在负循环子环是单项式单位。机械补O=L_old+R_old会错误拒绝一般诚实记录；子环维度1时Y=−1，该区别仍然存在。
4. 按现稿独立实现应采用L_paper/R_paper，在commitment update显式乘Y，并将未乘Y的L写入challenge输入；generator update仍含Y。不能只增加一个equal检查。
5. vector stage的L/R与现稿548–557一致：L_vec=<f_L,g_R>、R_vec=<f_R,g_L>，无需同类解释。

未修改或补丁化旧代码。新实现应从现稿公式独立实现，并验证非零奇部、非平凡Y及最后n=2→1轮，避免全零样例掩盖差异。

## 7. 其他确定的验证边界

**非canonical域编码。** field.rs:121–127对16-byte输入调用from_u128，后者41–42行取modulo q。q≪2¹²⁸，因此0与q的16-byte编码都被接受为Fp零；解析后hash的是同一规范域值。这违反论文586、612行的非canonical拒绝要求。源码测试every_serialized_micro_block_byte_flip_is_rejected（prover.rs:810–877）只覆盖逐字节XOR 1的特定扰动，并不等于拒绝所有加q的编码；本次没有运行它。

**声明与终态形状。** verifier.rs:22–34先验证传入params，再按original_len_bytes、com_0.ring_len、statement.d覆盖维度，未核对三者与N₀=n₀=2ᵈ的一致性。update_commitment仅检查record.round==当前round（57–58），入口不显式拒绝round≥d；final_opening才要求round==d（123–126）。它支持预期调用方式，但不是论文要求的严格完整Verify wrapper。

**认证context/deadline。** 核心verifier没有这些输入；审查范围没有可识别外部wrapper证据。不能因此断言某个未审计服务绝对不存在，只能确认本次核心源码缺失这些检查。

## 8. 快照、许可与交付边界

[SNAPSHOT.json](../sources/legacy/SNAPSHOT.json)列出18个文件的commit-pinned URL和Git blob SHA。按SHA1("blob "+byte_len+NUL+bytes)逐字验证匹配，快照设为只读。不包含旧.git、构建产物、性能日志或图片。完整Git tree元数据在TREE.json，用于文件存在性及license检查。

完整tree未发现LICENSE、COPYING或NOTICE文件；但Cargo.toml:6明确声明license="MIT"。准确表述是“有MIT元数据声明，但此commit缺少独立许可文本”，不是“已确定完全没有license”。快照只作本地审计，不上传、公开分发或移植进新实现；后续上传继续排除sources/legacy/。

本次指定源码及论文对照均已完成，没有剩余阻塞。未执行旧代码是用户边界，不是权限拒绝。性能复现、历史数据真伪、完整安全证明及实现修改不在此次审查范围。

