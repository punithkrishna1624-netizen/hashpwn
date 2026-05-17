#!/usr/bin/env python3
"""
╦ ╦╔═╗╔═╗╦ ╦╔═╗╦ ╦╔╗╔
╠═╣╠═╣╚═╗╠═╣╠═╝║║║║║║
╩ ╩╩ ╩╚═╝╩ ╩╩  ╚╩╝╝╚╝
HashPwn - Password & Hash Toolkit for Kali Linux
Author: Built for CTF & Security Research
Usage: python3 hashpwn.py <command> [options]
"""

import argparse
import hashlib
import hmac
import itertools
import os
import random
import re
import string
import sys
import time
from pathlib import Path

# ─── ANSI Colors ────────────────────────────────────────────────────────────
R  = "\033[91m"   # Red
G  = "\033[92m"   # Green
Y  = "\033[93m"   # Yellow
B  = "\033[94m"   # Blue
M  = "\033[95m"   # Magenta
C  = "\033[96m"   # Cyan
W  = "\033[97m"   # White
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

BANNER = f"""
{C}{BOLD}
 ██╗  ██╗ █████╗ ███████╗██╗  ██╗██████╗ ██╗    ██╗███╗   ██╗
 ██║  ██║██╔══██╗██╔════╝██║  ██║██╔══██╗██║    ██║████╗  ██║
 ███████║███████║███████╗███████║██████╔╝██║ █╗ ██║██╔██╗ ██║
 ██╔══██║██╔══██║╚════██║██╔══██║██╔═══╝ ██║███╗██║██║╚██╗██║
 ██║  ██║██║  ██║███████║██║  ██║██║     ╚███╔███╔╝██║ ╚████║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝
{RESET}{DIM}    Password & Hash Toolkit  |  For authorized use only{RESET} KEVIN - 
"""

# ─── SUPPORTED ALGORITHMS ───────────────────────────────────────────────────
ALGORITHMS = {
    "md5":       hashlib.md5,
    "sha1":      hashlib.sha1,
    "sha224":    hashlib.sha224,
    "sha256":    hashlib.sha256,
    "sha384":    hashlib.sha384,
    "sha512":    hashlib.sha512,
    "sha3_256":  hashlib.sha3_256,
    "sha3_512":  hashlib.sha3_512,
    "blake2b":   hashlib.blake2b,
    "blake2s":   hashlib.blake2s,
}

# ─── HELPERS ────────────────────────────────────────────────────────────────
def compute_hash(text: str, algo: str) -> str:
    algo = algo.lower()
    if algo not in ALGORITHMS:
        print(f"{R}[!] Unsupported algorithm: {algo}{RESET}")
        sys.exit(1)
    return ALGORITHMS[algo](text.encode()).hexdigest()

def info(msg):  print(f"{C}[*]{RESET} {msg}")
def ok(msg):    print(f"{G}[+]{RESET} {msg}")
def warn(msg):  print(f"{Y}[!]{RESET} {msg}")
def err(msg):   print(f"{R}[-]{RESET} {msg}")
def label(k, v): print(f"  {DIM}{k:<22}{RESET}{W}{v}{RESET}")

# ═══════════════════════════════════════════════════════════════════════════
# COMMAND 1 — HASH GENERATOR
# ═══════════════════════════════════════════════════════════════════════════
def cmd_hash(args):
    print(f"\n{M}{BOLD}[ HASH GENERATOR ]{RESET}\n")

    text = args.text or input(f"{C}  Enter text to hash:{RESET} ")
    algos = [a.strip().lower() for a in args.algo.split(",")]

    if "all" in algos:
        algos = list(ALGORITHMS.keys())

    print()
    for algo in algos:
        if algo not in ALGORITHMS:
            warn(f"Unknown algorithm skipped: {algo}")
            continue
        digest = compute_hash(text, algo)
        print(f"  {Y}{algo.upper():<12}{RESET}  {W}{digest}{RESET}")

    if args.output:
        with open(args.output, "w") as f:
            for algo in algos:
                if algo in ALGORITHMS:
                    f.write(f"{algo.upper()}: {compute_hash(text, algo)}\n")
        ok(f"Hashes saved to {args.output}")
    print()

# ═══════════════════════════════════════════════════════════════════════════
# COMMAND 2 — HASH CRACKER
# ═══════════════════════════════════════════════════════════════════════════
def cmd_crack(args):
    print(f"\n{M}{BOLD}[ HASH CRACKER ]{RESET}\n")

    target = args.hash.strip().lower()
    algo   = args.algo.lower()

    if algo not in ALGORITHMS:
        err(f"Unsupported algorithm: {algo}")
        sys.exit(1)

    # ── Wordlist mode ──────────────────────────────────────────────────────
    if args.wordlist:
        wl_path = Path(args.wordlist)
        if not wl_path.exists():
            err(f"Wordlist not found: {args.wordlist}")
            sys.exit(1)

        info(f"Target hash : {C}{target}{RESET}")
        info(f"Algorithm   : {C}{algo.upper()}{RESET}")
        info(f"Wordlist    : {C}{args.wordlist}{RESET}")
        print()

        tried = 0
        start = time.time()
        try:
            with open(wl_path, "r", errors="ignore") as f:
                for line in f:
                    word = line.strip()
                    if not word:
                        continue
                    tried += 1
                    digest = compute_hash(word, algo)

                    if args.verbose and tried % 5000 == 0:
                        elapsed = time.time() - start
                        rate = tried / elapsed if elapsed > 0 else 0
                        print(f"\r  {DIM}Tried: {tried:,}  |  Rate: {rate:,.0f}/s  |  Last: {word:<20}{RESET}", end="", flush=True)

                    if digest == target:
                        elapsed = time.time() - start
                        print(f"\r{' ' * 70}\r")
                        ok(f"{BOLD}CRACKED!{RESET}")
                        label("Password", word)
                        label("Hash", digest)
                        label("Algorithm", algo.upper())
                        label("Attempts", f"{tried:,}")
                        label("Time", f"{elapsed:.2f}s")
                        return

        except KeyboardInterrupt:
            print()
            warn("Cracking interrupted by user.")

        elapsed = time.time() - start
        print(f"\r{' ' * 70}\r")
        err(f"Hash not found in wordlist after {tried:,} attempts ({elapsed:.2f}s)")

    # ── Brute-force mode ───────────────────────────────────────────────────
    elif args.bruteforce:
        charset = ""
        if args.charset == "lower":   charset = string.ascii_lowercase
        elif args.charset == "upper": charset = string.ascii_uppercase
        elif args.charset == "alpha": charset = string.ascii_letters
        elif args.charset == "alnum": charset = string.ascii_letters + string.digits
        elif args.charset == "all":   charset = string.printable.strip()
        else:                         charset = args.charset  # custom

        max_len = args.max_len or 4
        info(f"Target hash : {C}{target}{RESET}")
        info(f"Algorithm   : {C}{algo.upper()}{RESET}")
        info(f"Charset     : {C}{args.charset}{RESET} ({len(charset)} chars)")
        info(f"Max length  : {C}{max_len}{RESET}")
        print()

        tried = 0
        start = time.time()
        try:
            for length in range(args.min_len or 1, max_len + 1):
                for combo in itertools.product(charset, repeat=length):
                    word = "".join(combo)
                    tried += 1
                    digest = compute_hash(word, algo)

                    if tried % 10000 == 0:
                        elapsed = time.time() - start
                        rate = tried / elapsed if elapsed > 0 else 0
                        print(f"\r  {DIM}Tried: {tried:,}  |  Len: {length}  |  Rate: {rate:,.0f}/s  |  Last: {word}{RESET}", end="", flush=True)

                    if digest == target:
                        elapsed = time.time() - start
                        print(f"\r{' ' * 80}\r")
                        ok(f"{BOLD}CRACKED!{RESET}")
                        label("Password", word)
                        label("Hash", digest)
                        label("Algorithm", algo.upper())
                        label("Attempts", f"{tried:,}")
                        label("Time", f"{elapsed:.2f}s")
                        return
        except KeyboardInterrupt:
            print()
            warn("Brute-force interrupted by user.")

        elapsed = time.time() - start
        print(f"\r{' ' * 80}\r")
        err(f"Hash not cracked after {tried:,} attempts ({elapsed:.2f}s)")

    else:
        err("Specify --wordlist <file> or --bruteforce")
        sys.exit(1)

    print()

# ═══════════════════════════════════════════════════════════════════════════
# COMMAND 3 — PASSWORD STRENGTH CHECKER
# ═══════════════════════════════════════════════════════════════════════════
def cmd_strength(args):
    print(f"\n{M}{BOLD}[ PASSWORD STRENGTH CHECKER ]{RESET}\n")

    password = args.password or input(f"{C}  Enter password to check:{RESET} ")

    checks = {
        "Length ≥ 8":          len(password) >= 8,
        "Length ≥ 12":         len(password) >= 12,
        "Length ≥ 16":         len(password) >= 16,
        "Lowercase letters":   bool(re.search(r"[a-z]", password)),
        "Uppercase letters":   bool(re.search(r"[A-Z]", password)),
        "Digits":              bool(re.search(r"\d", password)),
        "Special characters":  bool(re.search(r"[!@#$%^&*(),.?\":{}|<>_\-\[\]\\\/]", password)),
        "No common patterns":  not bool(re.search(r"(password|123456|qwerty|abc|111|000)", password.lower())),
        "No sequential chars": not bool(re.search(r"(abcd|1234|4321|dcba)", password.lower())),
    }

    score = sum(checks.values())
    total = len(checks)

    print(f"  {DIM}Password:{RESET} {Y}{'*' * len(password)}{RESET}  ({len(password)} chars)\n")

    for check, passed in checks.items():
        icon = f"{G}✔{RESET}" if passed else f"{R}✘{RESET}"
        print(f"  {icon}  {check}")

    print()

    pct = score / total
    bar_len = 30
    filled = int(bar_len * pct)
    if pct < 0.4:
        color = R; grade = "WEAK"
    elif pct < 0.65:
        color = Y; grade = "MODERATE"
    elif pct < 0.85:
        color = C; grade = "STRONG"
    else:
        color = G; grade = "VERY STRONG"

    bar = color + "█" * filled + DIM + "░" * (bar_len - filled) + RESET
    print(f"  Strength  [{bar}]  {color}{BOLD}{grade}{RESET}  ({score}/{total})")

    # Entropy estimate
    charset_size = 0
    if re.search(r"[a-z]", password): charset_size += 26
    if re.search(r"[A-Z]", password): charset_size += 26
    if re.search(r"\d", password):    charset_size += 10
    if re.search(r"[^a-zA-Z0-9]", password): charset_size += 32
    if charset_size > 0:
        import math
        entropy = len(password) * math.log2(charset_size)
        print(f"  Entropy   {DIM}~{RESET}{W}{entropy:.1f} bits{RESET}")

    print()

# ═══════════════════════════════════════════════════════════════════════════
# COMMAND 4 — PASSWORD GENERATOR
# ═══════════════════════════════════════════════════════════════════════════
def cmd_generate(args):
    print(f"\n{M}{BOLD}[ PASSWORD GENERATOR ]{RESET}\n")

    charset = ""
    if args.lower:  charset += string.ascii_lowercase
    if args.upper:  charset += string.ascii_uppercase
    if args.digits: charset += string.digits
    if args.special: charset += "!@#$%^&*()-_=+[]{}|;:,.<>?"

    # Default: all types
    if not charset:
        charset = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"

    if args.exclude:
        for ch in args.exclude:
            charset = charset.replace(ch, "")

    if not charset:
        err("Charset is empty after exclusions.")
        sys.exit(1)

    count  = args.count or 1
    length = args.length or 16

    info(f"Length    : {C}{length}{RESET}")
    info(f"Count     : {C}{count}{RESET}")
    info(f"Charset   : {C}{len(charset)} characters{RESET}")
    print()

    passwords = []
    for i in range(count):
        # Ensure at least one from each requested type
        pwd_chars = []
        if args.lower:   pwd_chars.append(random.choice(string.ascii_lowercase))
        if args.upper:   pwd_chars.append(random.choice(string.ascii_uppercase))
        if args.digits:  pwd_chars.append(random.choice(string.digits))
        if args.special: pwd_chars.append(random.choice("!@#$%^&*()-_=+[]{}|;:,.<>?"))

        remaining = length - len(pwd_chars)
        pwd_chars += random.choices(charset, k=max(remaining, 0))
        random.shuffle(pwd_chars)
        pwd = "".join(pwd_chars[:length])
        passwords.append(pwd)
        print(f"  {G}{i+1:>3}.{RESET}  {W}{BOLD}{pwd}{RESET}")

    if args.output:
        with open(args.output, "w") as f:
            for p in passwords:
                f.write(p + "\n")
        print()
        ok(f"Saved {count} password(s) to {args.output}")

    print()

# ═══════════════════════════════════════════════════════════════════════════
# ARGUMENT PARSER
# ═══════════════════════════════════════════════════════════════════════════
def build_parser():
    parser = argparse.ArgumentParser(
        prog="hashpwn",
        description=f"{BOLD}HashPwn{RESET} — Password & Hash Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Y}Commands:{RESET}
  hash      Generate hash(es) from text
  crack     Crack a hash via wordlist or brute-force
  strength  Analyse password strength
  generate  Generate secure random passwords

{Y}Examples:{RESET}
  {DIM}# Hash a string{RESET}
  python3 hashpwn.py hash -t "hello" -a sha256,md5

  {DIM}# Hash with all algorithms{RESET}
  python3 hashpwn.py hash -t "secret" -a all

  {DIM}# Crack with rockyou.txt{RESET}
  python3 hashpwn.py crack -H 5d41402abc4b2a76b9719d911017c592 -a md5 --wordlist /usr/share/wordlists/rockyou.txt

  {DIM}# Brute-force crack{RESET}
  python3 hashpwn.py crack -H 900150983cd24fb0d6963f7d28e17f72 -a md5 --bruteforce --charset alnum --max-len 4

  {DIM}# Check password strength{RESET}
  python3 hashpwn.py strength -p "MyP@ssw0rd!"

  {DIM}# Generate 5 strong passwords{RESET}
  python3 hashpwn.py generate -l 20 -c 5 --upper --lower --digits --special
        """
    )

    sub = parser.add_subparsers(dest="command")

    # ── hash ──
    p_hash = sub.add_parser("hash", help="Generate hash from text")
    p_hash.add_argument("-t", "--text",   help="Text to hash")
    p_hash.add_argument("-a", "--algo",   default="sha256",
                        help="Algorithm(s), comma-separated or 'all' (default: sha256)")
    p_hash.add_argument("-o", "--output", help="Save output to file")

    # ── crack ──
    p_crack = sub.add_parser("crack", help="Crack a hash")
    p_crack.add_argument("-H", "--hash",      required=True, help="Target hash")
    p_crack.add_argument("-a", "--algo",      default="md5", help="Hash algorithm (default: md5)")
    p_crack.add_argument("-w", "--wordlist",  help="Path to wordlist file")
    p_crack.add_argument("-b", "--bruteforce",action="store_true", help="Enable brute-force mode")
    p_crack.add_argument("--charset",         default="alnum",
                         help="Charset: lower|upper|alpha|alnum|all|<custom> (default: alnum)")
    p_crack.add_argument("--min-len",         type=int, default=1, help="Min brute-force length")
    p_crack.add_argument("--max-len",         type=int, default=4, help="Max brute-force length")
    p_crack.add_argument("-v", "--verbose",   action="store_true", help="Show progress")

    # ── strength ──
    p_str = sub.add_parser("strength", help="Check password strength")
    p_str.add_argument("-p", "--password", help="Password to analyse")

    # ── generate ──
    p_gen = sub.add_parser("generate", help="Generate random passwords")
    p_gen.add_argument("-l", "--length",  type=int, default=16, help="Password length (default: 16)")
    p_gen.add_argument("-c", "--count",   type=int, default=1,  help="Number of passwords (default: 1)")
    p_gen.add_argument("--lower",   action="store_true", help="Include lowercase")
    p_gen.add_argument("--upper",   action="store_true", help="Include uppercase")
    p_gen.add_argument("--digits",  action="store_true", help="Include digits")
    p_gen.add_argument("--special", action="store_true", help="Include special chars")
    p_gen.add_argument("--exclude", default="",          help="Characters to exclude")
    p_gen.add_argument("-o", "--output", help="Save passwords to file")

    return parser

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════
def main():
    print(BANNER)
    parser = build_parser()
    args   = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "hash":     cmd_hash,
        "crack":    cmd_crack,
        "strength": cmd_strength,
        "generate": cmd_generate,
    }
    dispatch[args.command](args)

if __name__ == "__main__":
    main()
