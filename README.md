# The Illusion of Password Complexity

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Dataset](https://img.shields.io/badge/Dataset-RockYou%2010k-orange)
![Type](https://img.shields.io/badge/Type-Simulation--Based%20Research-purple)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

> **Simulation-based computational study.**  
> No live systems, real cracking tools, or unauthorized access used at any point.

---

## The Question

Most websites enforce password complexity rules:

- Minimum 8 characters
- At least one uppercase letter
- At least one digit
- At least one symbol

A password like `Password1!` satisfies all four.  
Does that make it secure?

> *Do common password complexity requirements produce passwords that are  
> actually resistant to rule-based dictionary attacks?*

---

## Key Finding

Of passwords that pass **all four** complexity rules:

- The majority contain a recognizable dictionary base word
- These remain highly vulnerable to rule-based dictionary attacks despite satisfying all requirements
- Complexity rules correctly identify genuinely unpredictable passwords only in a minority of cases

**Complexity rules measure form, not unpredictability.**

---

## Why This Matters

This finding is consistent with the direction of NIST SP 800-63B (2017), which moved away from mandatory complexity rules — partly because they encourage predictable substitution patterns:

| Password | Passes rules | Has dict base | Verdict |
|---|---|---|---|
| `password` | ✗ | ✓ | Weak — obvious |
| `Password1!` | ✓ | ✓ | **False secure** |
| `P@ssw0rd` | ✓ | ✓ | **False secure** |
| `Admin2024!` | ✓ | ✓ | **False secure** |
| `X7#kP2!zQ` | ✓ | ✗ | Genuinely strong |

The problem: users follow the rules and receive a green checkmark — but the underlying password structure remains predictable.

---

## Repository Structure

```
complexity-illusion-study/
│
├── complexity_analysis.py   # Main analysis script
│
├── data/
│   └── rockyou-top10k.txt   # Password dataset (add your own — see below)
│
├── results/
│   └── complexity_results.csv  # Auto-generated output
│
└── docs/
    └── paper.md             # Full research paper
```

---

## Quick Start

**Requirements:** Python 3.8+ (no external libraries needed)

```bash
git clone https://github.com/YOUR_USERNAME/complexity-illusion-study.git
cd complexity-illusion-study

# Add your dataset (see note below)
# Then run:
python complexity_analysis.py --file data/rockyou-top10k.txt

# Limit to first 5000 passwords:
python complexity_analysis.py --file data/rockyou-top10k.txt --limit 5000
```

**Getting the dataset:**  
This study uses the publicly available RockYou top-10k password list from  
[SecLists](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt).  
Download and place at `data/rockyou-top10k.txt`.

---

## Methodology

### Complexity Rules Modeled

| Rule | Condition |
|---|---|
| Minimum length | ≥ 8 characters |
| Has uppercase | At least one A–Z |
| Has digit | At least one 0–9 |
| Has symbol | At least one non-alphanumeric character |

These rules reflect common real-world requirements and closely resemble pre-2017 password policies.

### Predictability Detection

A password is classified as **dict-based** (predictable) if:

1. After stripping leading/trailing digits and symbols, and reversing common leet substitutions (`@→a`, `3→e`, `1→i`, `0→o`, `$→s`), the resulting base string matches a word in a frequency dictionary
2. Or the base string is a substring of a known common word (catches `mypassword`, `password123`, etc.)

This models the behavior of rule-based attack tools applying mutation rules to a base word list — without claiming specific attempt counts.

### What We Do Not Claim

- We do not claim specific cracking times or attempt counts
- We do not run real hash-cracking tools
- "Vulnerable to rule-based attacks" means: *the base word is detectable by structural analysis*, which is a necessary condition for rule-based attacks to succeed — not a sufficient one

---

## Limitations

- Dictionary covers a subset of common words; a production attack tool would use millions
- Leet-reversal covers common substitutions only; more exotic patterns may be missed
- Does not model probabilistic context-free grammar (PCFG) attacks
- Results depend on dataset composition; RockYou skews toward English-speaking users
- Structural detection is a proxy for rule-based vulnerability, not a direct measurement

---

## Related Work

This project is a companion study to  
[password-strength-study](https://github.com/YOUR_USERNAME/password-strength-study) —  
which investigates entropy metrics vs brute-force resistance across password categories.

---

## References

- NIST Special Publication 800-63B (2017). *Digital Identity Guidelines — Authentication and Lifecycle Management.*
- Weir, M. et al. (2009). Password cracking using probabilistic context-free grammars. *IEEE S&P 2009.*
- Veras, R. et al. (2014). On the semantic patterns of passwords. *NDSS 2014.*
- Mazurek, M. et al. (2013). Measuring password guessability for an entire university. *CCS 2013.*
- Ur, B. et al. (2012). How does your password measure up? *USENIX Security 2012.*
- RockYou dataset (2009). Via SecLists: github.com/danielmiessler/SecLists

---

## License

MIT — free to use for educational purposes.

---

*This study is intended as an educational and comparative computational model for security analysis.*
