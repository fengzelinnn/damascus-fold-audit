# 冻结稿与实现对应

依据为 `sources/paper/manifest.json`；原始论文仅保留本地，源代码包不含论文或旧仓库快照。目录中唯一 main.tex/PDF 的当前 Drive revision 已核对，取回前后 size/modifiedTime 一致。PDF 为 13 页，内置创建时间 09:43:15 UTC，Drive 修改时间 09:58:54 UTC；这些字段含义不同，不能据其差异推断论文变更。标题、两阶段公式、奇偶检查、整数范数及 H 四次递推已文本对照；未声称从 TeX 可复现出位级相同 PDF。

| 冻结 TeX 行号 | 约束/公式 | 实现边界 |
|---|---|---|
| 346–347,403,483–488 | T=2^b>=4、beta0=1、N0=n0=2^d | 参数检查与算术类型 |
| 381–396,651–659 | indexed MSIS、终层普通 SIS、当前 extraction bound | 参数工具与显然攻击筛查；无安全配置 |
| 448,519–530,590–600 | 完整ctx、prefix、vec/poly域分离 | 精确列入设计；FS实例与wire未批准，尚未实现协议哈希 |
| 551–557 | Lvec=<fL,gR>、Rvec=<fR,gL> | 参考轮证明与公开更新 |
| 561–571 | Lpoly无Y、odd=C关系、Y/y作用 | 独立参考算术与差分测试 |
| 609–621 | generator replay、整数终端norm与全部k坐标opening | 算术replay完整检查；不含外部epoch认证 |
| 612 | certified context、deadline、ordered d records、replay拒绝 | typed算术轮序列；认证/时限/跨调用重放待D5 |
| 624–629 | 6k(2^d−1)+1系数、Theta(kM) generator replay | 仅系数公式，不能当实际序列化字节 |
| 405及正文codec概述 | bytes到ternary、beta0=1 | 仅接受已给定ternary测试见证；真实file codec待D1 |

`algebra.py`/`fold.py` 的测试挑战由调用者显式给定，避免在未批准时选定哈希算法、wire格式或信任模型。因此它们是完整折叠等式和终端检查的参考实现，不是完整PoSt Prove/Verify API。CLI禁止正式benchmark，日志 `data_kind=correctness_test`。

`encoding.py` 仅提供严格的长度前缀、整数、field residue和frame原语。它不决定注册字段顺序、epoch certificate、proof wire、文件codec；原语字节计数也不用于A1。

旧实现差异见 `legacy-audit.md`。未将旧代码移植到新实现，未将旧CSV/图/模拟值当成新实验输入。
