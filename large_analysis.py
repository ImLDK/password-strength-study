"""
Large-scale password analysis — works on generated or real datasets.

Usage:
  python large_analysis.py                        # uses data/passwords_large.csv
  python large_analysis.py --file rockyou.txt     # use real RockYou file
  python large_analysis.py --limit 5000           # limit rows
"""

import math, csv, os, sys, argparse, collections

# ── Config ─────────────────────────────────────────────────────────────────────

CRACK_SPEED = 1_000_000_000  # 10^9 attempts/second

LEET_MAP = {'@':'a','3':'e','1':'i','0':'o','$':'s','7':'t','!':'i','8':'b'}

# Top-1000 base words (simulates checking against a frequency dictionary)
# In a real study, replace with actual RockYou top-1000 list
DICT_WORDS = {
    "password","love","dragon","monkey","shadow","master","hello","welcome",
    "sunshine","princess","football","baseball","soccer","hockey","tennis",
    "batman","superman","spiderman","michael","jessica","ashley","letmein",
    "iloveyou","trustno1","starwars","pokemon","jordan","harley","ranger",
    "hunter","killer","buster","thomas","robert","andrew","daniel","george",
    "samuel","joshua","kevin","brandon","zachary","austin","angel","flower",
    "butter","cheese","purple","orange","yellow","silver","guitar","matrix",
    "coffee","winter","summer","spring","tiger","eagle","wolf","panther",
    "cobra","falcon","thunder","storm","blaze","flame","frost","admin",
    "user","test","guest","login","secure","access","apple","google","qwerty",
    "abc","xyz","pass","word","name","time","year","life","love","home",
    # names
    "anna","kate","emma","lisa","sara","mary","jane","rose","alex","ryan",
    "john","mike","jake","luke","mark","paul","adam","eric","sean","kyle",
    "chris","james","david","peter","brian","scott","kevin","jason","tyler",
}

# ── Core functions ─────────────────────────────────────────────────────────────

def charset_size(pwd):
    has_lower  = any(c.islower() for c in pwd)
    has_upper  = any(c.isupper() for c in pwd)
    has_digit  = any(c.isdigit() for c in pwd)
    has_symbol = any(not c.isalnum() for c in pwd)
    size = 0
    if has_lower:  size += 26
    if has_upper:  size += 26
    if has_digit:  size += 10
    if has_symbol: size += 32
    return max(size, 10)

def entropy_score(pwd):
    cs = charset_size(pwd)
    return math.log10(cs ** len(pwd))

def strength_label(log10):
    if log10 < 9:  return "Critical"
    if log10 < 13: return "Weak"
    if log10 < 16: return "Moderate"
    return "Strong"

def deleet(pwd):
    """Reverse leet: P@ssw0rd → password"""
    return ''.join(LEET_MAP.get(c, c) for c in pwd.lower())

def base_word(pwd):
    """Extract base word by stripping digits/symbols from ends and reversing leet."""
    stripped = pwd.strip(r"0123456789!@#$%^&*_-+=")
    deLeeted = deleet(stripped)
    return deLeeted.lower()

def is_deceptive(pwd):
    """
    True if password scores >= Moderate on entropy but has a dictionary base word.
    These are the passwords that fool entropy meters.
    """
    log10 = entropy_score(pwd)
    if log10 < 13:  # weak anyway, not deceptive
        return False
    base = base_word(pwd)
    if base in DICT_WORDS:
        return True
    # Also check if the base (3+ chars) is a substring of a dict word
    if len(base) >= 4:
        for word in DICT_WORDS:
            if base in word or word in base:
                return True
    return False

def analyze_password(pwd):
    log10  = entropy_score(pwd)
    metric = strength_label(log10)
    dec    = is_deceptive(pwd)
    real   = "Critical" if dec else metric  # deceptive = always Critical in reality
    gap    = (metric != real)
    return {
        "password":    pwd[:20],
        "length":      len(pwd),
        "charset":     charset_size(pwd),
        "log10":       round(log10, 2),
        "metric":      metric,
        "deceptive":   dec,
        "real":        real,
        "gap":         gap,
    }

# ── Load data ──────────────────────────────────────────────────────────────────

def load_passwords(filepath, limit=1000):
    passwords = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            if filepath.endswith(".csv"):
                reader = csv.DictReader(f)
                for row in reader:
                    passwords.append(row["password"])
                    if len(passwords) >= limit:
                        break
            else:
                # plain text, one password per line
                for line in f:
                    pwd = line.strip()
                    if pwd:
                        passwords.append(pwd)
                    if len(passwords) >= limit:
                        break
    except FileNotFoundError:
        print(f"File not found: {filepath}")
        sys.exit(1)
    return passwords

# ── Analysis & reporting ───────────────────────────────────────────────────────

def run_analysis(passwords):
    results = [analyze_password(p) for p in passwords]
    return results

def print_report(results):
    n = len(results)
    print(f"\n{'='*60}")
    print(f"  LARGE-SCALE PASSWORD ANALYSIS — {n} passwords")
    print(f"{'='*60}\n")

    # Distribution by metric strength
    metric_counts = collections.Counter(r["metric"] for r in results)
    print("Metric strength distribution:")
    for label in ["Critical","Weak","Moderate","Strong"]:
        count = metric_counts.get(label, 0)
        pct   = count / n * 100
        bar   = "█" * int(pct / 2)
        print(f"  {label:<10} {count:>5} ({pct:5.1f}%)  {bar}")

    # Deceptive passwords
    deceptive = [r for r in results if r["deceptive"]]
    print(f"\nDeceptive passwords (score >= Moderate but have dict base word):")
    print(f"  Found: {len(deceptive)} / {n} ({len(deceptive)/n*100:.1f}%)")

    # Among those scoring Moderate or Strong — how many are deceptive?
    high_score = [r for r in results if r["metric"] in ("Moderate","Strong")]
    if high_score:
        dec_among_high = [r for r in high_score if r["deceptive"]]
        pct_false      = len(dec_among_high) / len(high_score) * 100
        print(f"\n  Of passwords scoring Moderate/Strong ({len(high_score)} total):")
        print(f"  → {len(dec_among_high)} ({pct_false:.1f}%) are deceptive")
        print(f"  → {len(high_score)-len(dec_among_high)} ({100-pct_false:.1f}%) are genuinely strong")

    # Length vs strength — the unexpected finding
    print(f"\nLength vs real strength (the unexpected finding):")
    long_weak = [r for r in results if r["length"] >= 8 and r["real"] in ("Critical","Weak")]
    short_ok  = [r for r in results if r["length"] <= 6 and r["metric"] == "Critical"]
    print(f"  Passwords with length >= 8 that are still Critical/Weak: {len(long_weak)} ({len(long_weak)/n*100:.1f}%)")
    print(f"  Passwords with length <= 6 that are Critical: {len(short_ok)} ({len(short_ok)/n*100:.1f}%)")
    if long_weak:
        avg_log10_long_weak = sum(r["log10"] for r in long_weak) / len(long_weak)
        print(f"  Avg entropy score of long-but-weak passwords: {avg_log10_long_weak:.2f} log10")
        print(f"  → These score '{strength_label(avg_log10_long_weak)}' on entropy meters but are predictable")

    # Deceptive examples
    if deceptive:
        print(f"\nTop deceptive password examples (entropy says strong, reality says critical):")
        shown = sorted(deceptive, key=lambda r: -r["log10"])[:8]
        print(f"  {'Password':<20} {'log10':>6}  {'Metric':<10} {'Real':<10}")
        print(f"  {'-'*50}")
        for r in shown:
            print(f"  {r['password']:<20} {r['log10']:>6}  {r['metric']:<10} {r['real']:<10}")

    # Summary verdict
    print(f"\n{'─'*60}")
    print(f"KEY FINDING:")
    if high_score and dec_among_high:
        pct = len(dec_among_high) / len(high_score) * 100
        print(f"  {pct:.1f}% of passwords scoring Moderate/Strong on entropy metrics")
        print(f"  are deceptive — they have a recognizable dictionary base word")
        print(f"  and would be cracked quickly by rule-based attacks.")
        print(f"\n  Entropy metrics overestimate security for these passwords.")
        print(f"  Length alone does not guarantee resistance to rule-based attacks.")
    print(f"{'='*60}\n")

def save_results(results, path="results/large_results.csv"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"Full results saved to {path}")

# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Large-scale password analysis")
    parser.add_argument("--file",  default="data/passwords_large.csv", help="Password file (.csv or plain text)")
    parser.add_argument("--limit", type=int, default=1000,             help="Max passwords to analyze")
    args = parser.parse_args()

    print(f"Loading passwords from: {args.file} (limit: {args.limit})")
    passwords = load_passwords(args.file, args.limit)
    print(f"Loaded {len(passwords)} passwords")

    results = run_analysis(passwords)
    print_report(results)
    save_results(results)
