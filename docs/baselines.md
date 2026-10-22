# A5 baseline provenance and comparison contract

Research checked on 2026-10-22. Scheme selection is already authorized: ADJ21 **public** low-storage PoR and ePoSt. This document records source evidence, not a baseline implementation or benchmark result. The machine-readable companion is `configs/baselines.json`; its local execution profiles remain unset and its local measurement arrays are empty.

## Bibliographic identities

**ADJ21** denotes Gaspard Anthoine, Jean-Guillaume Dumas, Mélanie de Jonghe, Aude Maignan, Clément Pernet, Michael Hanling, and Daniel S. Roche, *Dynamic proofs of retrievability with low server storage*, 30th USENIX Security Symposium, 2021, pp. 537–554. Use the publisher's author order above. The [USENIX record](https://www.usenix.org/conference/usenixsecurity21/presentation/anthoine) supplies no proceedings DOI. The separate [preprint DOI](https://doi.org/10.48550/arXiv.2007.12556) identifies arXiv:2007.12556, not a USENIX DOI. The read version is [v3, 8 June 2021](https://arxiv.org/abs/2007.12556v3); the [publisher PDF](https://www.usenix.org/system/files/sec21-anthoine.pdf) confirms the relevant parameters and theorem.

**ePoSt** is Chengru Zhang, Xinyu Li, and Man Ho Au, *ePoSt: Practical and Client-Friendly Proof of Storage-Time*, IEEE Transactions on Information Forensics and Security **18** (2023), pp. 1052–1063, [DOI 10.1109/TIFS.2022.3233780](https://doi.org/10.1109/TIFS.2022.3233780). This exactly matches the `2023epost` entry read from the supplied private `refs.bib` (source locator excluded from public release). Both [Li's author page](https://lixinyu2016.github.io/xinyuli/) and [Au's author page](https://web.comp.polyu.edu.hk/mhaau/research.html) corroborate the identity.

## Verified semantics and parameters

ADJ21's public variant computes `y=Mx` over the whole matrix, with randomized challenges and public verification. Its retrievability definition uses successful transcripts and rewinding extraction; it supplies no storage-duration guarantee. Public keys and updated roots require authenticated publication, with timestamped root updates. Theorem 9 assumes LIP security, hard discrete logarithms, and `p >= max(16*n + 96*lambda, m*2^(2*kappa))`; Merkle authentication also requires collision resistance. Public experiments use Ristretto255, 252-bit data coefficients, square matrices, and report computational security 117.78–120.2 bits. These are published settings, not an approved local security profile. See [§§2, 5.4, 6.1; Theorem 9; Figure 2](https://www.usenix.org/system/files/sec21-anthoine.pdf). In particular, do not transfer the paper's faster private-mode results to the selected public baseline.

ePoSt's institutional abstract describes a public, stateless PoSt with repeated proof/verification support. It reports a 1 GB outsourcing example with three proof/verify interactions, each covering one year at 25-minute intervals: preparation 66.34 minutes, proof 48.82 KB, verification 36.05 ms. These are **published abstract-level observations** with original unit labels; exact byte conventions, hardware, security parameters, phase boundaries, and amortization details remain unverified. [PolyU publication record and abstract](https://research.polyu.edu.hk/en/publications/epost-practical-and-client-friendly-proof-of-storage-time/).

The [IEEE full-text endpoint](https://ieeexplore.ieee.org/iel7/10206/9970396/10004939.pdf) failed to fetch (HTTP 418), and the [article page](https://ieeexplore.ieee.org/document/10004939) presented robot verification. Therefore the current manuscript's assertions about ePoSt's single-block sampling, approximately 460 rounds, RSA accumulator, and SNARK aggregation are **claims awaiting primary-full-text verification**, not accepted baseline parameters. No curve, RSA modulus, VDF, challenge distribution, trusted-setup requirement, or concrete security level is inferred from later papers' reimplementations.

## Implementation and license status

The ADJ21 paper's availability section links [dsroche/la-por](https://github.com/dsroche/la-por). Its repository listing contains `publicverif/` and `pubver_tests.txt`; its [top-level license](https://raw.githubusercontent.com/dsroche/la-por/master/LICENSE) is the Unlicense. Dependency/subcomponent licenses still need checking before reuse. No commit has been pinned, source downloaded, build executed, or output measured here. The mere existence of a public directory does not establish that a future selected executable implements every theorem assumption.

No author-linked ePoSt implementation was located in the publisher/institutional records, author publication pages, or the web searches performed. This is a search outcome, **not evidence that no implementation exists**. Repository URL, commit, license, build procedure, and execution parameters remain null. No substitute protocol, simulator, or later third-party reimplementation is accepted under the ePoSt label.

## Fair A5 comparison

The following are requirements for this experiment, rather than new claims about either paper:

| Dimension | Required treatment |
|---|---|
| Security statement | Keep point-in-time PoR retrievability, duration-dependent PoSt, and Damascus's claimed epoch statement distinct. Full data processing is not a deterministic zero-error security guarantee. |
| Public verification | Record challenge origin, interaction, statement authentication, updates, replay protection, and any secret needed by the verifier. |
| Concrete security | Record all relevant computational/statistical bounds and assumptions. A curve's nominal security is insufficient; do not label the published ADJ21 profile 128-bit. |
| Data/workload | Record original bytes, encoded bytes, coefficient/block count, padding, update regime, and exact unit conversion. |
| Timing scope | Separate setup, registration, online proof, aggregation, verification, I/O, and network. Record cold/cached state, repetitions, threads, compiler, dependencies, and full hardware. |
| Duration | Record covered interval, challenge cadence, deadline, sequential-work calibration, number of epochs, and amortization horizon where applicable. A PoR audit has no automatically comparable PoSt interval. |
| Bytes and resources | Separate full proof, individual records, challenges, public keys/registration, persistent storage, peak RSS, and sampled VRAM. Include serialization and metadata. |
| Sampling confidence | Use `1-(1-p)^r` only when independent challenges and the per-challenge detection model are justified. Do not equate detection probability with percentage of file bytes accessed or with extractability. |
| Provenance | Keep `published`, `local_measured`, `correctness_test`, `fixture`, and `simulation` records separate. No heterogeneous-hardware ranking by seconds or speedup ratio. |

The existing Damascus comparison table, discarded figures, B-group material, and DamascusSim are excluded as baseline implementation and measurement evidence. No values have been read from plots or imported into local results.

## Remaining decisions and evidence gates

1. **Security target and ADJ21 profile:** decide whether A5 presents the historical published profile or a separately labeled locally selected profile at the common target security. Raising its group size or changing its implementation must be documented; do not silently relabel historical results.
2. **ePoSt source access:** obtain a readable authoritative full paper or author artifact to resolve its sampling, duration theorem, cryptographic parameters, hardware, and exact measurement scopes. This is missing evidence, not a reason to choose invented values.
3. **Baseline execution route:** before local timing, pin official source and inspect its license/build/parameter provenance. If no usable ePoSt artifact is obtained, keep ePoSt as a literature-only baseline unless the user explicitly accepts a separately labeled and reviewed reimplementation.
4. **Matching scope:** agree on file encoding, security target, audit/duration semantics, and phase boundaries before starting comparable runs on the two actual local platforms. The scheme choices themselves do not need reconfirmation.

The current A5 deliverable can show source/semantics/status rows. It cannot show local baseline timings, a same-security performance ranking, or a verified ePoSt parameter set.
