# 03 · OWASP Top 10 (2021)

The OWASP Top 10 is the standard list of the most critical web application security risks. These notes follow the 2021 edition; check [owasp.org](https://owasp.org/www-project-top-ten/) for newer editions.

| # | Risk | In one line | How to defend |
|---|------|-------------|---------------|
| A01 | **Broken Access Control** | A user can see or change things they shouldn't, e.g. changing `?user_id=5` to `?user_id=6` in a URL | Check permissions on the server for every request; deny by default |
| A02 | **Cryptographic Failures** | Sensitive data is stored or sent without strong encryption | Use HTTPS everywhere; hash passwords with bcrypt or Argon2, never MD5 |
| A03 | **Injection** | User input is run as code, like SQL injection: `' OR '1'='1` | Use parameterised queries; never glue user input into SQL or shell commands |
| A04 | **Insecure Design** | The design itself has a flaw, like unlimited password-reset attempts | Threat-model features before building them |
| A05 | **Security Misconfiguration** | Default passwords, debug mode left on, detailed error pages | Harden settings; turn off what you don't use |
| A06 | **Vulnerable and Outdated Components** | Using a library with a known security hole | Keep dependencies updated; scan them |
| A07 | **Identification and Authentication Failures** | Weak passwords allowed, no brute-force protection, sessions never expire | Multi-factor authentication, rate limiting, secure session handling |
| A08 | **Software and Data Integrity Failures** | Trusting updates or data without checking they weren't tampered with | Verify signatures; secure the build pipeline |
| A09 | **Security Logging and Monitoring Failures** | An attack happens and nobody notices | Log logins and errors; alert on suspicious activity |
| A10 | **Server-Side Request Forgery (SSRF)** | The attacker makes the server fetch an internal URL for them | Allow-list the URLs the server may fetch |

## SQL injection, up close

Vulnerable code:
```python
query = "SELECT * FROM users WHERE name = '" + username + "'"
```
If `username` is `' OR '1'='1`, the query becomes `... WHERE name = '' OR '1'='1'`, which is always true, so every user is returned.

Safe code (parameterised query):
```python
cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
```
The database treats the input purely as data, never as SQL.

## Cross-site scripting (XSS), up close

If a site shows a comment without escaping it, a comment like `<script>alert(1)</script>` runs in every visitor's browser.
**Defence:** escape output, use a Content Security Policy, and use frameworks that escape by default.

## Practice

PortSwigger Web Security Academy has free labs for each of these. Start with **SQL injection** and **XSS**, and log each lab in [`../labs/README.md`](../labs/README.md).

## ✅ Self-check
- [ ] I can explain why parameterised queries stop SQL injection
- [ ] I can give a real example of broken access control
- [ ] I know why MD5 is a bad way to store passwords
