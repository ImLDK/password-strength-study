# A Computational Study of Password Strength and Vulnerability to Common Attack Methods

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Type](https://img.shields.io/badge/Type-Simulation--Based%20Research-purple)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

> **Simulation-based computational study.**  
> This project uses mathematical modeling and publicly known password frequency patterns.  
> No live systems, real passwords, or cracking tools were used at any point.

---

## Overview

This study investigates how structural properties of a password — length, character set size, and predictability — affect resistance to two common attack models: **dictionary attacks** and **brute-force attacks**.

Nine passwords across four categories were analyzed using combinatorial mathematics and password frequency data modeled on the RockYou dataset structure.

**Research question:**
> Which types of passwords are most vulnerable to dictionary and brute-force attacks, and what structural factors explain the difference?

**Hypothesis:**
> Predictability is a stronger predictor of vulnerability than length alone.

---

## Repository Structure

```
password-strength-study/
│
├── password_analysis.py     # Main analysis script
│
├── data/
│   └── passwords.csv        # Input dataset (9 passwords, 4 categories)
│
├── results/
│   ├── summary.md           # Full results table + category summary
│   └── results.csv          # Auto-generated output from script
│
└── docs/
    └── paper.md             # Full research paper (text version)
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
A Computational Study of Password Strength
Simulation-based model — no live systems used

| Password     | Category    | log10 | BF time (10⁹/s)  | Strength |
|--------------|-------------|-------|------------------|----------|
| 123456       | Simple      |   6.0 | < 1 second       | Critical |
| Anna2005     | Name/year   |  12.5 | ~47 minutes      | Weak     |
| S0lar!X9     | Complex     |  14.9 | ~8 days          | Moderate |
| @mR4$vN8!p   | Random      |  19.7 | ~1,700 years     | Strong   |

Category summary (avg log10 brute-force space):
  Simple        log10 ≈   8.6  ████████
  Name/year     log10 ≈  12.4  ████████████
  Complex       log10 ≈  14.9  ██████████████
  Random        log10 ≈  18.7  ██████████████████
```

---

## Methodology

### Password Categories

| Category | Examples | Rationale |
|---|---|---|
| Simple | `123456`, `qwerty`, `password` | Common real-world weak passwords |
| Name + year | `Anna2005`, `Mike1998`, `Alex2001` | Predictable human patterns |
| Complex | `S0lar!X9` | Mixed structure, semi-predictable |
| Random | `X7#kP2!zQ`, `@mR4$vN8!p` | High entropy, no recognizable pattern |

### Core Formula

Brute-force search space:

```
attempts = charset_size ** length
```

Charset sizes used:

| Character class | Size |
|---|---|
| Digits only | 10 |
| Lowercase letters | 26 |
| Alphanumeric | 36 |
| Extended printable ASCII | ~94 |

### Strength Classification

Strength labels are derived from log₁₀ brute-force space thresholds and used as comparative metrics, not absolute security guarantees.

| Label | log₁₀ threshold |
|---|---|
| Critical | < 9 |
| Weak | 9 – 13 |
| Moderate | 13 – 16 |
| Strong | > 16 |

---

## Key Findings

- Simple passwords are cracked in **1–4 dictionary attempts**
- Name+year patterns are vulnerable despite mixed characters (~5,000 attempts)
- Moving from Simple → Random increases search space by **~10¹⁰×**
- **Structure matters more than length**: `password` (8 chars) ≈ Weak; `X7#kP2!zQ` (9 chars) ≈ Strong

---

## Limitations

- Does not simulate GPU-accelerated or parallel cracking
- Does not account for adaptive AI-based attack strategies
- Assumes uniform character probability in brute-force space
- Dictionary modeling based on structural approximations, not live datasets

---

## References

- RockYou dataset (2009) — structural reference for dictionary frequency modeling
- Florencio, D., & Herley, C. (2007). *A large-scale study of web password habits.* WWW 2007.
- NIST SP 800-63B (2017). *Digital Identity Guidelines — Authentication and Lifecycle Management.*
- Shannon, C. E. (1948). *A mathematical theory of communication.* Bell System Technical Journal.

---

## License

MIT — free to use for educational purposes.

---

*This study is intended as an educational and comparative computational model for security analysis.*
