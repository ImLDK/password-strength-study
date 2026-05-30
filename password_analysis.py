"""
The Illusion of Password Complexity
A Simulation-Based Computational Study

Research question:
  Do common password complexity requirements produce passwords that are
  actually resistant to rule-based dictionary attacks?

Usage:
  python complexity_analysis.py --file data/rockyou-top10k.txt
  python complexity_analysis.py --file data/rockyou-top10k.txt --limit 5000

Simulation-based study — no live systems or cracking tools used.
Author: ImLDK
Year:   2025
"""

import math, csv, os, re, argparse, collections

# ── Complexity rules (modeled on common real-world requirements) ───────────────
#
# These rules are used by the majority of websites and closely resemble
# pre-2017 NIST guidelines. Note: NIST SP 800-63B (2017) has since moved
# away from mandatory complexity rules — one reason being that they produce
# predictable patterns. This study investigates that exact phenomenon.

COMPLEXITY_RULES = {
    "min_length_8":    lambda p: len(p) >= 8,
    "has_uppercase":   lambda p: any(c.isupper() for c in p),
    "has_digit":       lambda p: any(c.isdigit() for c in p),
    "has_symbol":      lambda p: any(not c.isalnum() for c in p),
}

# ── Dictionary of common base words (subset; real study uses full RockYou) ────

DICT_WORDS = {
    "password","love","dragon","monkey","shadow","master","hello","welcome",
    "sunshine","princess","football","baseball","soccer","hockey","tennis",
    "batman","superman","spiderman","michael","jessica","ashley","letmein",
    "iloveyou","trustno1","starwars","pokemon","jordan","harley","ranger",
    "hunter","killer","thomas","robert","andrew","daniel","george","samuel",
    "joshua","kevin","brandon","austin","angel","flower","butter","cheese",
    "purple","orange","yellow","silver","guitar","matrix","coffee","winter",
    "summer","spring","tiger","eagle","wolf","cobra","thunder","storm",
    "admin","user","test","guest","login","secure","access","system",
    "baby","honey","sweet","sugar","candy","ninja","wizard","champion",
    "music","dance","sport","game","happy","lucky","magic","super","mega",
    "apple","google","amazon","netflix","twitter","facebook","minecraft",
    "anna","kate","emma","lisa","sara","mary","alex","ryan","john","mike",
    "jake","luke","mark","paul","adam","eric","sean","kyle","chris","james",
    "david","peter","brian","scott","kevin","jason","tyler","ashley",
    "jessica","amanda","melissa","sarah","jennifer","matthew","andrew",
    "welcome","monkey","abc","pass","word","qwerty","letme","enter",
    "ninja","pirate","dragon","wizard","knight","warrior","legend","hero",
    "blue","red","green","black","white","dark","light","ghost","fire",
}

LEET_MAP = {
    '@': 'a', '3': 'e', '1': 'i', '0': 'o',
    '$': 's', '7': 't', '!': 'i', '8': 'b', '4': 'a', '5': 's',
}

# ── Core functions ─────────────────────────────────────────────────────────────

def meets_rules(pwd):
    """Check which complexity rules a password satisfies."""
    return {name: fn(pwd) for name, fn in COMPLEXITY_RULES.items()}

def meets_all_rules(pwd):
    return all(fn(pwd) for fn in COMPLEXITY_RULES.values())

def meets_n_rules(pwd, n):
    return sum(fn(pwd) for fn in COMPLEXITY_RULES.values()) >= n

def reverse_leet(pwd):
    return ''.join(LEET_MAP.get(c, c) for c in pwd.lower())

def extract_base(pwd):
    """Strip digits/symbols from ends, reverse leet substitutions."""
    s = pwd.strip("0123456789!@#$%^&*_-+=.,?/\\|")
    return reverse_leet(s).lower()

def has_dict_base(pwd):
    """True if password contains a recognizable dictionary word as its base."""
    base = extract_base(pwd)
    if base in DICT_WORDS:
        return True
    # Substring check — catches 'password123!', 'mypassword', etc.
    for word in DICT_WORDS:
        if len(word) >= 4 and (word in base or base in word):
            return True
    return False

def charset_size(pwd):
    size = 0
    if any(c.islower() for c in pwd): size += 26
    if any(c.isupper() for c in pwd): size += 26
    if any(c.isdigit() for c in pwd): size += 10
    if any(not c.isalnum() for c in pwd): size += 32
    return max(size, 10)

def entropy_log10(pwd):
    return math.log10(charset_size(pwd) ** len(pwd))

def strength_label(log10):
    if log10 < 9:  return "Critical"
    if log10 < 13: return "Weak"
    if log10 < 16: return "Moderate"
    return "Strong"

def predictability_label(pwd):
    """
    Classifies real-world predictability based on structural analysis.
    Does NOT claim specific attempt counts — models relative vulnerability.
    """
    base = extract_base(pwd)
    # Pure keyboard pattern
    kb = ["qwerty","asdf","zxcv","1234","0987","qazwsx","1qaz","abcd"]
    if any(k in pwd.lower() for k in kb):
        return "keyboard_pattern"
    # Dictionary base with common mutations
    if has_dict_base(pwd):
        return "dict_based"
    # Looks random
    return "appears_random"

def analyze_password(pwd):
    pwd = pwd.strip()
    rules     = meets_rules(pwd)
    passes_all = meets_all_rules(pwd)
    log10     = entropy_log10(pwd)
    metric    = strength_label(log10)
    pred      = predictability_label(pwd)
    dict_base = has_dict_base(pwd)

    # The key variable: passes complexity rules BUT is still predictable
    false_secure = passes_all and dict_base

    return {
        "password":         pwd[:24],
        "length":           len(pwd),
        "charset":          charset_size(pwd),
        "log10":            round(log10, 2),
        "metric_strength":  metric,
        "passes_all_rules": passes_all,
        "rules_passed":     sum(rules.values()),
        "predictability":   pred,
        "dict_based":       dict_base,
        "false_secure":     false_secure,
        # individual rules
        "rule_length":      rules["min_length_8"],
        "rule_upper":       rules["has_uppercase"],
        "rule_digit":       rules["has_digit"],
        "rule_symbol":      rules["has_symbol"],
    }

# ── Load ───────────────────────────────────────────────────────────────────────

def load(filepath, limit):
    passwords = []
    with open(filepath, encoding="utf-8", errors="ignore") as f:
        if filepath.endswith(".csv"):
            reader = csv.DictReader(f)
            for row in reader:
                pwd = row.get("password", "").strip()
                if pwd: passwords.append(pwd)
        else:
            for line in f:
                pwd = line.strip()
                if pwd: passwords.append(pwd)
        if limit:
            passwords = passwords[:limit]
    return passwords

# ── Report ─────────────────────────────────────────────────────────────────────

def report(results):
    n = len(results)
    passes   = [r for r in results if r["passes_all_rules"]]
    fails    = [r for r in results if not r["passes_all_rules"]]
    false_s  = [r for r in results if r["false_secure"]]
    genuine  = [r for r in passes  if not r["dict_based"]]

    print(f"\n{'='*65}")
    print(f"  THE ILLUSION OF PASSWORD COMPLEXITY — {n:,} passwords")
    print(f"{'='*65}\n")

    # Rule compliance
    print("── Complexity rule compliance ──────────────────────────────")
    print(f"  Passwords passing ALL 4 rules : {len(passes):>5} ({len(passes)/n*100:.1f}%)")
    print(f"  Passwords failing rules       : {len(fails):>5} ({len(fails)/n*100:.1f}%)\n")

    rule_names = ["rule_length","rule_upper","rule_digit","rule_symbol"]
    labels     = ["Length ≥ 8","Has uppercase","Has digit","Has symbol"]
    for key, label in zip(rule_names, labels):
        count = sum(r[key] for r in results)
        print(f"  {label:<18} {count:>5} ({count/n*100:.1f}%)")

    # The main finding
    print(f"\n── Main finding ────────────────────────────────────────────")
    if passes:
        pct_false = len(false_s) / len(passes) * 100
        pct_genuine = len(genuine) / len(passes) * 100
        print(f"  Of {len(passes)} passwords passing ALL complexity rules:")
        print(f"  → {len(false_s):>5} ({pct_false:.1f}%) are predictable  — dict base word detected")
        print(f"  → {len(genuine):>5} ({pct_genuine:.1f}%) appear genuinely unpredictable\n")
        print(f"  Complexity rules correctly identify strong passwords")
        print(f"  only {pct_genuine:.1f}% of the time in this dataset.")

    # Entropy distribution among rule-passing passwords
    print(f"\n── Entropy scores of rule-compliant passwords ──────────────")
    if passes:
        for label in ["Critical","Weak","Moderate","Strong"]:
            count = sum(r["metric_strength"] == label for r in passes)
            pct   = count / len(passes) * 100
            bar   = "█" * int(pct / 3)
            print(f"  {label:<10} {count:>5} ({pct:5.1f}%)  {bar}")

    # Predictability breakdown
    print(f"\n── Predictability of rule-compliant passwords ──────────────")
    pred_counts = collections.Counter(r["predictability"] for r in passes)
    for label, count in sorted(pred_counts.items(), key=lambda x: -x[1]):
        pct = count / len(passes) * 100 if passes else 0
        print(f"  {label:<20} {count:>5} ({pct:.1f}%)")

    # Examples
    if false_s:
        print(f"\n── Examples: passes all rules, remains predictable ─────────")
        print(f"  {'Password':<22} {'Rules':>5}  {'Metric':<10} {'Predictability'}")
        print(f"  {'─'*60}")
        shown = sorted(false_s, key=lambda r: -r["log10"])[:10]
        for r in shown:
            print(f"  {r['password']:<22} {r['rules_passed']:>5}  "
                  f"{r['metric_strength']:<10} {r['predictability']}")

    # The unexpected finding
    print(f"\n── Length vs predictability (unexpected finding) ───────────")
    long_pred = [r for r in results if r["length"] >= 10 and r["dict_based"]]
    long_rand = [r for r in results if r["length"] >= 10 and not r["dict_based"]]
    print(f"  Passwords with length ≥ 10:")
    print(f"  → {len(long_pred)} still have a dictionary base word ({len(long_pred)/(len(long_pred)+len(long_rand)+1)*100:.1f}%)")
    print(f"  → {len(long_rand)} appear genuinely unpredictable")
    print(f"\n  Conclusion: length ≥ 10 does not reliably indicate")
    print(f"  resistance to rule-based attacks in this dataset.")

    print(f"\n{'='*65}\n")

def save(results, path="results/complexity_results.csv"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=results[0].keys())
        w.writeheader()
        w.writerows(results)
    print(f"Results saved → {path}")

# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--file",  default="data/rockyou-top10k.txt",
                        help="Password file (.txt or .csv)")
    parser.add_argument("--limit", type=int, default=None,
                        help="Max passwords to analyze (default: all)")
    args = parser.parse_args()

    print(f"Loading: {args.file}")
    passwords = load(args.file, args.limit)
    print(f"Loaded {len(passwords):,} passwords\n")

    results = [analyze_password(p) for p in passwords if p.strip()]
    report(results)
    save(results)
