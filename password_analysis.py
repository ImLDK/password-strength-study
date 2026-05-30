
"""
A Computational Study of Password Strength and Vulnerability to Common Attack Methods
Extended: The Deceptive Password Problem — entropy metrics vs rule-based attack resistance

Simulation-based combinatorial analysis — no live systems or real cracking tools used.

Author: ImLDK
Year:   2025
"""

import math
import csv
import os

# ── Dataset ────────────────────────────────────────────────────────────────────

# (password, category, charset_size, dict_risk, dict_attempts, rule_based_attempts)
#
# rule_based_attempts: estimated attempts when attacker uses rule-based mutations
# (leet substitution, case toggle, append digit/year/symbol) on a base dictionary.
# None = password has no recognizable base word; rules don't apply.

PASSWORDS = [
    # Original categories
    ("123456",       "Simple",     10,  "Very high", 1,       1),
    ("qwerty",       "Simple",     26,  "Very high", 2,       2),
    ("password",     "Simple",     26,  "Very high", 4,       4),
    ("Anna2005",     "Name/year",  36,  "High",      5_000,   5_000),
    ("Mike1998",     "Name/year",  36,  "High",      5_000,   5_000),
    ("Alex2001",     "Name/year",  36,  "High",      5_000,   5_000),
    ("S0lar!X9",     "Complex",    72,  "Medium",    None,    None),
    ("X7#kP2!zQ",    "Random",     94,  "Very low",  None,    None),
    ("@mR4$vN8!p",   "Random",     94,  "Very low",  None,    None),

    # NEW: Deceptive category — high entropy score, low real resistance
    ("P@ssw0rd",     "Deceptive",  72,  "Very high", None,    23),
    ("S3cur1ty!",    "Deceptive",  72,  "Very high", None,    31),
    ("Adm1n@2024",   "Deceptive",  72,  "Very high", None,    48),
    ("Tr0ub4dor&3",  "Deceptive",  72,  "Medium",    None,    120),
]

CRACK_SPEED = 1_000_000_000  # 10^9 attempts/second (modern GPU, simplified)

# Common leet substitution rules (subset of hashcat best64 ruleset)
LEET_RULES = {
    'a': '@', 'e': '3', 'i': '1', 'o': '0',
    's': '$', 't': '7', 'l': '1', 'b': '8'
}


# ── Core model ─────────────────────────────────────────────────────────────────

def brute_force_space(charset_size: int, length: int) -> int:
    """Total theoretical search space: charset_size ^ length."""
    return charset_size ** length


def log10_space(space: int) -> float:
    return math.log10(space)


def estimated_time_seconds(space: int, speed: int = CRACK_SPEED) -> float:
    return space / speed


def strength_label(log10: float) -> str:
    """
    Strength classification derived from logarithmic brute-force space thresholds.
    Comparative metric only — not an absolute security guarantee.
    """
    if log10 < 9:   return "Critical"
    if log10 < 13:  return "Weak"
    if log10 < 16:  return "Moderate"
    return "Strong"


def real_strength_label(log10_bf: float, rule_attempts) -> str:
    """
    Real-world strength accounting for rule-based attacks.
    If rule_attempts is known, uses that instead of brute-force space.
    """
    if rule_attempts is not None:
        if rule_attempts < 100:    return "Critical"
        if rule_attempts < 10_000: return "Weak"
        return "Moderate"
    return strength_label(log10_bf)


def metric_gap(log10_bf: float, rule_attempts) -> str:
    """
    Measures the gap between what entropy metrics predict vs rule-based reality.
    Returns 'Overestimated', 'Accurate', or N/A.
    """
    if rule_attempts is None:
        return "Accurate"
    metric_label   = strength_label(log10_bf)
    real_label     = real_strength_label(log10_bf, rule_attempts)
    order = ["Critical", "Weak", "Moderate", "Strong"]
    diff = order.index(metric_label) - order.index(real_label)
    if diff >= 2:   return "Overestimated ⚠ ⚠"
    if diff == 1:   return "Overestimated ⚠"
    return "Accurate"


def format_time(seconds: float) -> str:
    if seconds < 1:           return "< 1 second"
    if seconds < 60:          return f"{seconds:.1f} seconds"
    if seconds < 3600:        return f"{seconds/60:.1f} minutes"
    if seconds < 86400:       return f"{seconds/3600:.1f} hours"
    if seconds < 86400*365:   return f"{seconds/86400:.1f} days"
    if seconds < 86400*365*1000: return f"{seconds/(86400*365):.1f} years"
    return f"{seconds/(86400*365):.2e} years"


# ── Analysis ───────────────────────────────────────────────────────────────────

def analyze():
    results = []
    for pwd, category, charset, dict_risk, dict_attempts, rule_attempts in PASSWORDS:
        length  = len(pwd)
        space   = brute_force_space(charset, length)
        log10   = log10_space(space)
        time_s  = estimated_time_seconds(space)

        results.append({
            "password":           pwd,
            "category":           category,
            "length":             length,
            "charset_size":       charset,
            "dict_risk":          dict_risk,
            "dict_attempts":      dict_attempts if dict_attempts else "N/A",
            "rule_attempts":      rule_attempts if rule_attempts else "N/A",
            "bf_space":           f"~{space:.2e}",
            "log10_space":        round(log10, 2),
            "bf_time_est":        format_time(time_s),
            "metric_strength":    strength_label(log10),
            "real_strength":      real_strength_label(log10, rule_attempts),
            "metric_gap":         metric_gap(log10, rule_attempts),
        })
    return results


# ── Output ─────────────────────────────────────────────────────────────────────

def print_table(results):
    print("\nA Computational Study of Password Strength")
    print("Simulation-based model — no live systems used\n")

    # Main table
    header = f"{'Password':<14} {'Category':<12} {'log10':>6} {'Metric':>10} {'Real':>10} {'Gap':<22} {'BF time (10⁹/s)'}"
    print(header)
    print("-" * len(header))
    for r in results:
        gap = r["metric_gap"]
        print(f"{r['password']:<14} {r['category']:<12} {r['log10_space']:>6} "
              f"{r['metric_strength']:>10} {r['real_strength']:>10} {gap:<22} {r['bf_time_est']}")

    # Deceptive focus
    print("\n── Deceptive passwords: metric score vs rule-based attempts ──")
    print(f"{'Password':<14} {'Metric strength':>16} {'Rule attempts':>14} {'Real strength':>14}")
    print("-" * 62)
    for r in results:
        if r["category"] == "Deceptive":
            print(f"{r['password']:<14} {r['metric_strength']:>16} "
                  f"{str(r['rule_attempts']):>14} {r['real_strength']:>14}")

    # Category summary
    print("\nCategory summary (avg log10 brute-force space):")
    print("-" * 50)
    from collections import defaultdict
    cats = defaultdict(list)
    for r in results:
        cats[r["category"]].append(r["log10_space"])
    for cat, logs in cats.items():
        avg = sum(logs) / len(logs)
        bar = "█" * int(avg)
        print(f"  {cat:<12}  log10 ≈ {avg:5.1f}  {bar}")
    print()


def save_csv(results, path="results/results.csv"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"Results saved to {path}")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    results = analyze()
    print_table(results)
    save_csv(results)
