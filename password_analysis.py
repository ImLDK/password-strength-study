"""
A Computational Study of Password Strength and Vulnerability to Common Attack Methods
Simulation-based combinatorial analysis — no live systems or real cracking tools used.

Author: [Your Name]
Year:   2025
"""

import math
import csv
import os

# ── Dataset ────────────────────────────────────────────────────────────────────

PASSWORDS = [
    # (password, category, charset_size, dict_risk, dict_attempts)
    ("123456",      "Simple",    10,  "Very high", 1),
    ("qwerty",      "Simple",    26,  "Very high", 2),
    ("password",    "Simple",    26,  "Very high", 4),
    ("Anna2005",    "Name/year", 36,  "High",      5000),
    ("Mike1998",    "Name/year", 36,  "High",      5000),
    ("Alex2001",    "Name/year", 36,  "High",      5000),
    ("S0lar!X9",    "Complex",   72,  "Medium",    None),
    ("X7#kP2!zQ",   "Random",    94,  "Very low",  None),
    ("@mR4$vN8!p",  "Random",    94,  "Very low",  None),
]

CRACK_SPEED = 1_000_000_000  # assumed: 10^9 attempts/second (modern GPU, simplified)


# ── Core model ─────────────────────────────────────────────────────────────────

def brute_force_space(charset_size: int, length: int) -> int:
    """Total theoretical search space: charset_size ^ length."""
    return charset_size ** length


def log10_space(space: int) -> float:
    return math.log10(space)


def estimated_time_seconds(space: int, speed: int = CRACK_SPEED) -> float:
    """Worst-case brute-force time in seconds at given crack speed."""
    return space / speed


def strength_label(log10: float) -> str:
    """
    Strength classification derived from logarithmic brute-force space thresholds.
    Used as a comparative metric, not an absolute security guarantee.
    """
    if log10 < 9:
        return "Critical"
    elif log10 < 13:
        return "Weak"
    elif log10 < 16:
        return "Moderate"
    else:
        return "Strong"


def format_time(seconds: float) -> str:
    if seconds < 1:
        return "< 1 second"
    elif seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    elif seconds < 86400 * 365:
        return f"{seconds/86400:.1f} days"
    elif seconds < 86400 * 365 * 1000:
        return f"{seconds/(86400*365):.1f} years"
    else:
        return f"{seconds/(86400*365):.2e} years"


# ── Analysis ───────────────────────────────────────────────────────────────────

def analyze():
    results = []

    for pwd, category, charset, dict_risk, dict_attempts in PASSWORDS:
        length = len(pwd)
        space  = brute_force_space(charset, length)
        log10  = log10_space(space)
        time_s = estimated_time_seconds(space)
        label  = strength_label(log10)

        results.append({
            "password":       pwd,
            "category":       category,
            "length":         length,
            "charset_size":   charset,
            "dict_risk":      dict_risk,
            "dict_attempts":  dict_attempts if dict_attempts else "N/A",
            "bf_space":       f"~{space:.2e}",
            "log10_space":    round(log10, 2),
            "bf_time_est":    format_time(time_s),
            "strength":       label,
        })

    return results


# ── Output ─────────────────────────────────────────────────────────────────────

def print_table(results):
    col_w = [12, 11, 7, 9, 11, 14, 14, 11, 20, 10]
    headers = ["Password", "Category", "Length", "Charset", "Dict risk",
               "Dict attempts", "BF space", "log10", "BF time (10⁹/s)", "Strength"]

    sep = "+" + "+".join("-" * (w + 2) for w in col_w) + "+"
    header_row = "|" + "|".join(f" {h:<{w}} " for h, w in zip(headers, col_w)) + "|"

    print("\nA Computational Study of Password Strength")
    print("Simulation-based model — no live systems used\n")
    print(sep)
    print(header_row)
    print(sep)
    for r in results:
        row = [r["password"], r["category"], str(r["length"]), str(r["charset_size"]),
               r["dict_risk"], str(r["dict_attempts"]), r["bf_space"],
               str(r["log10_space"]), r["bf_time_est"], r["strength"]]
        print("|" + "|".join(f" {v:<{w}} " for v, w in zip(row, col_w)) + "|")
    print(sep)


def save_csv(results, path="results/results.csv"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"\nResults saved to {path}")


def category_summary(results):
    from collections import defaultdict
    cats = defaultdict(list)
    for r in results:
        cats[r["category"]].append(r["log10_space"])

    print("\nCategory summary (avg log10 brute-force space):")
    print("-" * 45)
    for cat, logs in cats.items():
        avg = sum(logs) / len(logs)
        bar = "█" * int(avg)
        print(f"  {cat:<12}  log10 ≈ {avg:5.1f}  {bar}")
    print()


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    results = analyze()
    print_table(results)
    category_summary(results)
    save_csv(results)
