# A Computational Study of Password Strength and Vulnerability to Common Attack Methods

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Type](https://img.shields.io/badge/Type-Simulation--Based%20Research-purple)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

> **Simulation-based computational study.**  
> No live systems, real passwords, or cracking tools were used at any point.

---

## The Core Question

Standard password strength meters score `S3cur1ty!` as **Strong**.  
A rule-based attacker cracks it in **31 attempts**.

This study investigates why — and quantifies the gap.

---

## Overview

This project extends standard password entropy analysis with a new variable: **rule-based attack resistance**. It introduces the *Deceptive* password category — passwords that score well on entropy metrics but follow predictable substitution patterns (leet speak, symbol-for-letter replacements) that rule-based attack tools exploit trivially.

**Primary research question:**
> Do entropy-based strength metrics accurately predict resistance to rule-based dictionary attacks, or do they systematically overestimate the security of structured substitution passwords?

**Key finding:**
> Entropy metrics can overestimate real-world password security by up to **16 orders of magnitude** for passwords based on predictable substitution patterns.

---

## Repository Structure

```
password-strength-study/
│
├── password_analysis.py     # Main analysis script
│
├── data/
│   └── passwords.csv        # Input dataset (13 passwords, 5 categories)
│
├── results/
│   ├── summary.md           # Full results + key findings
│   └── results.csv          # Auto-generated output from script
│
└── docs/
    └── paper.md             # Full research paper
```

---

## Quick Start

**Requirements:** Python 3.8+ (no external libraries needed)

```bash
git clone https://github.com/YOUR_USERNAME/password-strength-study.git
cd password-strength-study
python password_analysis.py
```

**Sample output:**

```
Password       Category      log10     Metric       Real  Gap
---------------------------------------------------------------
123456         Simple          6.0   Critical   Critical  Accurate
S3cur1ty!      Deceptive      16.7     Strong   Critical  Overestimated ⚠⚠
Adm1n@2024     Deceptive      18.6     Strong   Critical  Overestimated ⚠⚠
X7#kP2!zQ      Random         17.8     Strong     Strong  Accurate
```

---

## Methodology

### Password Categories

| Category | Examples | Rationale |
|---|---|---|
| Simple | `123456`, `qwerty`, `password` | Common real-world weak passwords |
| Name + year | `Anna2005`, `Mike1998`, `Alex2001` | Predictable human patterns |
| Complex | `S0lar!X9` | Mixed structure, semi-predictable |
| **Deceptive** | `P@ssw0rd`, `S3cur1ty!`, `Adm1n@2024` | **High entropy, predictable substitution** |
| Random | `X7#kP2!zQ`, `@mR4$vN8!p` | High entropy, no pattern |

### Two Metrics Compared

**Entropy metric** (standard): `charset_size ^ length`  
→ measures theoretical possibility space

**Rule-based attack estimate** (new): applies leet-substitution rules to a base dictionary  
→ models real attacker behavior (subset of hashcat best64 ruleset)

### The Gap

| Password | Entropy metric | Rule-based reality | Δ orders of magnitude |
|---|---|---|---|
| `P@ssw0rd` | ~10¹⁵ attempts | 23 attempts | **~13** |
| `S3cur1ty!` | ~10¹⁷ attempts | 31 attempts | **~15** |
| `Adm1n@2024` | ~10¹⁸ attempts | 48 attempts | **~16** |

### Strength Classification

Strength labels are derived from log₁₀ brute-force space thresholds — used as comparative metrics, not absolute guarantees.

| Label | log₁₀ threshold |
|---|---|
| Critical | < 9 |
| Weak | 9 – 13 |
| Moderate | 13 – 16 |
| Strong | > 16 |

---

## Key Findings

1. Entropy metrics **accurately** predict resistance for Simple, Name/year, and Random passwords
2. Entropy metrics **fail** for Deceptive passwords — overestimating by 2–3 strength levels in all cases
3. The maximum observed gap: **16 orders of magnitude** (`Adm1n@2024`)
4. Truly random passwords show **zero gap** — entropy metrics remain valid when no base word exists
5. This suggests entropy metrics are only reliable for passwords with no recognizable structural origin

---

## Limitations

- Rule-based attempt counts are conservative approximations
- Models a subset of hashcat best64; full rulesets would yield lower attempt counts
- Does not simulate GPU-accelerated parallel cracking
- Dictionary ranks approximated from RockYou structure, not live datasets

---

## References

- RockYou dataset (2009) — structural reference for dictionary frequency modeling
- Hashcat project — best64.rule ruleset documentation
- Florencio, D., & Herley, C. (2007). *A large-scale study of web password habits.* WWW 2007.
- Weir, M. et al. (2009). *Password cracking using probabilistic context-free grammars.* IEEE S&P 2009.
- NIST SP 800-63B (2017). *Digital Identity Guidelines.*
- Shannon, C. E. (1948). *A mathematical theory of communication.* Bell System Technical Journal.

---

## License

MIT — free to use for educational purposes.

---

*This study is intended as an educational and comparative computational model for security analysis.*
