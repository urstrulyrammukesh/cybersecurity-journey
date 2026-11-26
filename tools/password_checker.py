"""Password strength checker.

Scores a password from 0 to 100 and explains how to make it stronger.
It runs fully offline: the password is never stored, logged or sent anywhere.

Usage:
    python3 tools/password_checker.py          # asks for a password (input is hidden)
    python3 tools/password_checker.py --test   # runs the built-in tests
"""
import getpass
import math
import string
import sys

# A small sample of the most common leaked passwords. Real checkers use lists with millions of entries.
COMMON_PASSWORDS = {
    "123456", "123456789", "12345678", "password", "qwerty", "abc123", "111111", "123123",
    "password1", "iloveyou", "admin", "welcome", "monkey", "dragon", "letmein", "football",
    "qwerty123", "1q2w3e4r", "sunshine", "princess", "000000", "passw0rd", "india123",
}

SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm"]


def charset_size(pw: str) -> int:
    size = 0
    if any(c in string.ascii_lowercase for c in pw):
        size += 26
    if any(c in string.ascii_uppercase for c in pw):
        size += 26
    if any(c in string.digits for c in pw):
        size += 10
    if any(c in string.punctuation or c == " " for c in pw):
        size += 33
    if any(ord(c) > 127 for c in pw):
        size += 100
    return size


def entropy_bits(pw: str) -> float:
    """Upper bound on guessing effort if every character were picked at random."""
    size = charset_size(pw)
    return len(pw) * math.log2(size) if size else 0.0


def has_sequence(pw: str, length: int = 4) -> bool:
    low = pw.lower()
    for seq in SEQUENCES:
        for s in (seq, seq[::-1]):
            for i in range(len(s) - length + 1):
                if s[i:i + length] in low:
                    return True
    return False


def has_repeats(pw: str, length: int = 3) -> bool:
    return any(pw[i] * length == pw[i:i + length] for i in range(len(pw) - length + 1))


def check(pw: str) -> tuple[int, str, list[str]]:
    """Return (score 0-100, label, tips)."""
    tips = []
    if pw.lower() in COMMON_PASSWORDS:
        return 0, "Very weak", ["This is one of the most common passwords. It would be guessed instantly."]

    score = min(entropy_bits(pw), 100)

    if len(pw) < 8:
        tips.append("Use at least 12 characters; length matters more than anything else.")
        score = min(score, 25)
    elif len(pw) < 12:
        tips.append("Make it 12 characters or longer.")
    if not any(c.isupper() for c in pw):
        tips.append("Add an uppercase letter.")
    if not any(c.isdigit() for c in pw):
        tips.append("Add a number.")
    if not any(c in string.punctuation for c in pw):
        tips.append("Add a symbol such as ! @ # ?")
    if has_sequence(pw):
        tips.append("Avoid sequences like 'abcd', '1234' or 'qwerty'.")
        score -= 20
    if has_repeats(pw):
        tips.append("Avoid repeating the same character, like 'aaa'.")
        score -= 15

    score = max(0, min(100, round(score)))
    if score < 30:
        label = "Very weak"
    elif score < 50:
        label = "Weak"
    elif score < 70:
        label = "Okay"
    elif score < 85:
        label = "Strong"
    else:
        label = "Very strong"
    if not tips:
        tips.append("Great password. Use a different one for every site, and turn on 2FA.")
    return score, label, tips


def _tests():
    assert check("password")[0] == 0
    assert check("123456")[1] == "Very weak"
    assert check("abc")[0] <= 25
    assert check("abcd1234")[0] < check("k7#Rq9!vLm2@")[0]
    assert check("aaaaaaaaaaaa")[0] < check("hT5$wQ9zL!3m")[0]
    score, label, _ = check("Correct-Horse-Battery-Staple-42")
    assert label == "Very strong" and score >= 85
    assert has_sequence("xx4321yy") and has_sequence("myQWERTYpass")
    assert not has_sequence("k7#Rq9!vLm2@")
    assert has_repeats("passsword") and not has_repeats("password")
    print("password_checker tests ok")


def main():
    if "--test" in sys.argv:
        _tests()
        return
    pw = getpass.getpass("Password to check (hidden): ")
    score, label, tips = check(pw)
    bar = "#" * (score // 5) + "-" * (20 - score // 5)
    print(f"\nStrength: [{bar}] {score}/100 · {label}")
    print(f"Estimated entropy: {entropy_bits(pw):.0f} bits")
    for tip in tips:
        print(f"  • {tip}")


if __name__ == "__main__":
    main()
