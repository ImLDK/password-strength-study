# A Computational Study of Password Strength and Vulnerability to Common Attack Methods

*A Simulation-Based Computational Study — 2025*

---

## 1. Introduction

Passwords remain the most widespread form of digital authentication, yet they are also one of the most commonly exploited security weaknesses. Research consistently shows that many users choose short, predictable passwords based on common words, names, or number sequences, creating a gap between perceived and actual security.

This study investigates how structural properties of a password — including length, character set, and predictability — affect resistance to two common attack models: dictionary attacks and brute-force attacks.

> **Note:** This is a simulation-based computational study. It uses mathematical modeling and publicly known password frequency patterns rather than real-world penetration testing or interaction with live systems. All results are theoretical estimates derived from combinatorial analysis.

---

## 2. Research Question

*Which types of passwords are most vulnerable to dictionary and brute-force attacks, and what structural factors explain the difference?*

---

## 3. Hypothesis

Simple, dictionary-based passwords are significantly more vulnerable than randomly generated passwords, regardless of length. Predictability — the use of common words, names, or recognizable patterns — is a stronger predictor of vulnerability than length alone.

---

## 4. Methodology

### 4.1 Password Categories

| Category | Examples | Rationale |
|---|---|---|
| Simple | 123456, qwerty, password | Common real-world weak passwords |
| Name + year | Anna2005, Mike1998, Alex2001 | Predictable human patterns |
| Complex | S0lar!X9 | Mixed structure, semi-predictable |
| Random | X7#kP2!zQ, @mR4$vN8!p | High entropy, no recognizable pattern |

### 4.2 Metrics

Two theoretical metrics were used:

- **Dictionary vulnerability:** estimated based on frequency ranking structure of known leaked password datasets (e.g., RockYou dataset distribution patterns).
- **Brute-force complexity:** `Attempts = charset_size ^ length`. This represents the total theoretical search space for exhaustive attacks.

*Note: Strength classification (Critical / Weak / Moderate / Strong) is derived from logarithmic brute-force space thresholds and is used as a comparative metric, not an absolute security guarantee.*

### 4.3 Implementation

All calculations were performed using deterministic combinatorial modeling. Charset sizes were defined as:

| Character class | Charset size |
|---|---|
| Digits only | 10 |
| Lowercase letters | 26 |
| Alphanumeric (lower + digits) | 36 |
| Extended printable ASCII | ~94 |

This study does not perform real-world cracking attempts. Instead, it models theoretical security boundaries using mathematical estimation. Dictionary attack risk was approximated from structural patterns in publicly available leaked password datasets, not live hash-cracking tools.

---

## 5. Results

### 5.1 Dataset Overview

| Password | Category | Length | Charset | Dict risk | BF complexity | Strength |
|---|---|---|---|---|---|---|
| 123456 | Simple | 6 | 10 | Very high | ~10⁶ | Critical |
| qwerty | Simple | 6 | 26 | Very high | ~3×10⁸ | Critical |
| password | Simple | 8 | 26 | Very high | ~2×10¹¹ | Critical |
| Anna2005 | Name/year | 8 | 36 | High | ~2.8×10¹² | Weak |
| Mike1998 | Name/year | 8 | 36 | High | ~2.8×10¹² | Weak |
| Alex2001 | Name/year | 8 | 36 | High | ~2.8×10¹² | Weak |
| S0lar!X9 | Complex | 8 | ~72 | Medium | ~7×10¹⁴ | Moderate |
| X7#kP2!zQ | Random | 9 | 94 | Very low | ~5×10¹⁷ | Strong |
| @mR4$vN8!p | Random | 10 | 94 | Very low | ~5×10¹⁹ | Strong |

### 5.2 Category Summary

| Category | Dictionary risk | Log₁₀ complexity | Estimated resistance |
|---|---|---|---|
| Simple | Yes | ~8 | Very weak |
| Name/year | Yes | ~12 | Weak |
| Complex | No | ~14–15 | Moderate |
| Random | No | ~17–19 | Strong |

---

## 6. Analysis

Two dominant factors determine password security: predictability and entropy.

**Predictability dominates dictionary resistance.** Simple passwords such as "123456" or "qwerty" appear at the top of leaked password datasets and are immediately vulnerable to dictionary attacks. Even structured variants like "Anna2005" remain weak due to predictable human patterns that are easily reproduced by rule-based attack systems.

**Entropy determines brute-force resistance.** It grows exponentially with both character set size and password length. Increasing charset diversity has a stronger effect per character than increasing length alone, as each additional character class multiplies the entire search space.

**Structure outweighs length.** An 8-character predictable password can be significantly weaker than a shorter but fully random one. This directly supports the study's hypothesis that predictability is a stronger predictor of vulnerability than length alone.

---

## 7. Conclusion

The findings of this study demonstrate that password security is primarily determined by structural predictability rather than length alone. Randomly generated passwords provide exponentially higher resistance to both dictionary and brute-force attacks.

The hypothesis is supported: randomness is a stronger predictor of security than memorability.

**Practical implication:** Users should prioritize randomness and entropy over memorability, ideally using password managers and passwords of at least 12 characters with full character set diversity.

This study is intended as an educational and comparative computational model for security analysis.

---

## 8. Limitations

- Does not simulate GPU-accelerated or parallel cracking optimizations
- Does not account for adaptive AI-based attack strategies
- Assumes uniform character probability in brute-force space
- Dictionary attack modeling is based on structural approximations, not live datasets

Despite these limitations, the model accurately represents relative differences in password security and provides a valid basis for comparative analysis.

---

## 9. References

- RockYou dataset (2009). Publicly leaked password corpus (~14 million entries). Used as structural reference for dictionary frequency modeling.
- Florencio, D., & Herley, C. (2007). A large-scale study of web password habits. *Proceedings of WWW 2007.*
- NIST Special Publication 800-63B (2017). *Digital Identity Guidelines — Authentication and Lifecycle Management.*
- Shannon, C. E. (1948). A mathematical theory of communication. *Bell System Technical Journal, 27*(3), 379–423.
