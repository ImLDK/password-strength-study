# A Computational Study of Password Strength and Vulnerability to Common Attack Methods

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Dataset](https://img.shields.io/badge/Dataset-1000%20passwords-orange)
![Type](https://img.shields.io/badge/Type-Simulation--Based%20Research-purple)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

> **Simulation-based computational study.**  
> No live systems, real passwords, or cracking tools were used at any point.

---

## The Core Finding

> **72% of passwords that score Moderate or Strong on standard entropy metrics  
> are deceptive — they contain a recognizable dictionary base word and would be  
> cracked quickly by rule-based attacks.**

We expected entropy metrics to be a reliable security indicator.  
They are not — for nearly three quarters of "high-scoring" passwords.

---

## Overview

This project investigates a fundamental question about password security tooling:

> *Do standard entropy-based strength metrics accurately predict resistance to rule-based dictionary attacks, or do they systematically overestimate the security of structured substitution passwords?*

Using a 1,000-password dataset modeled on documented RockYou distribution patterns, the study compares **entropy-based strength scores** against **rule-based attack resistance** — and finds a systematic gap.

---

## Repository Structure

```
password-strength-study/
│
├── password_analysis.py     # Core model: 13 passwords, 5 categories (original study)
├── generate_dataset.py      # Generates 1000-password research dataset
├── large_analysis.py        # Large-scale analysis engine
│
├── data/
│   ├── passwords.csv        # Original 13-password dataset
│   └── passwords_large.csv  # 1000-password dataset (auto-generated)
│
├── results/
│   ├── summary.md           # Key findings + tables
│   ├── results.csv          # Original study output
│   └── large_results.csv    # Large-scale analysis output
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

# Run original 13-password study
python password_analysis.py

# Generate dataset + run large-scale analysis
python generate_dataset.py
python large_analysis.py

# Use a real password file (e.g. RockYou)
python large_analysis.py --file rockyou.txt --limit 10000
```

---

## Key Results

### Large-scale analysis (1,000 passwords)

| Metric score | Count | Of these: genuinely strong | Of these: deceptive |
|---|---|---|---|
| Critical | 312 (31.2%) | 312 | 0 |
| Weak | 445 (44.5%) | 445 | 0 |
| Moderate | 182 (18.2%) | 51 | **131 (72%)** |
| Strong | 61 (6.1%) | 17 | **44 (72%)** |

**72% of Moderate/Strong passwords are deceptive.**

### The deceptive password problem

| Password | Entropy score | Metric says | Reality | Δ log₁₀ |
|---|---|---|---|---|
| `Christopher1985` | 26.9 | Strong | Critical | ~25 |
| `Sp1d3rm@n!` | 19.7 | Strong | Critical | ~18 |
| `Jessica1985` | 19.7 | Strong | Critical | ~18 |
| `spiderman123` | 18.7 | Strong | Critical | ~17 |

### Length vs real security — unexpected finding

- **31.0%** of passwords with length ≥ 8 are still Critical or Weak in reality
- Their average entropy score: **13.82 log₁₀** (rated *Moderate* by metrics)
- Length alone does not predict resistance to rule-based attacks

---

## Methodology

### Two metrics compared

| Metric | Formula | What it measures |
|---|---|---|
| Entropy score | `log₁₀(charset ^ length)` | Theoretical possibility space |
| Rule-based resistance | Dictionary lookup + leet-rule detection | Real attacker behavior |

### Deceptive password detection

A password is classified as *deceptive* if:
1. Its entropy score is ≥ Moderate (log₁₀ ≥ 13)
2. Its base word (after reversing leet substitutions and stripping digits/symbols) exists in a frequency dictionary

This models an attacker applying standard mutation rules (subset of hashcat best64 ruleset) to a base word list.

### Dataset

1,000 passwords generated according to documented RockYou category distribution patterns (Weir et al. 2009, Veras et al. 2014):

| Category | Count | % |
|---|---|---|
| Simple dictionary | ~560 | 56% |
| Name + year | ~180 | 18% |
| Deceptive / leet | ~120 | 12% |
| Keyboard patterns | ~80 | 8% |
| Numeric / PIN | ~120 | 12% |
| Truly random | ~50 | 5% |

---

## Limitations

- Rule-based detection uses a simplified model; real attack tools (hashcat) would achieve higher detection rates
- Dataset is synthetically generated from documented patterns, not a live leaked corpus
- Does not model GPU-accelerated parallel attacks
- Dictionary covers ~1,000 base words; production tools use millions

---

## References

- RockYou dataset (2009). Leaked password corpus (~14M entries).
- Weir, M. et al. (2009). Password cracking using probabilistic context-free grammars. *IEEE S&P.*
- Veras, R. et al. (2014). On the semantic patterns of passwords. *NDSS 2014.*
- Mazurek, M. et al. (2013). Measuring password guessability for an entire university. *CCS 2013.*
- Hashcat project. best64.rule ruleset. https://github.com/hashcat/hashcat
- NIST SP 800-63B (2017). Digital Identity Guidelines.
- Shannon, C. E. (1948). A mathematical theory of communication. *Bell System Technical Journal.*

---

## License

MIT — free to use for educational purposes.

---

*This study is intended as an educational and comparative computational model for security analysis.*
