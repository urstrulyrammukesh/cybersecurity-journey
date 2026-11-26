# 02 · Linux Basics

Most servers, and most security tools, run on Linux. Being fast on the command line is a core skill.

## Moving around

| Command | What it does |
|---------|--------------|
| `pwd` | Show the current folder |
| `ls -la` | List all files, including hidden ones, with details |
| `cd /path` | Change folder (`cd ..` goes up, `cd ~` goes home) |
| `find / -name "*.conf" 2>/dev/null` | Search for files, hiding permission errors |

## Reading files

| Command | What it does |
|---------|--------------|
| `cat file` | Print a whole file |
| `less file` | Scroll through a long file (`q` to quit) |
| `head -n 20 file` / `tail -n 20 file` | First / last 20 lines |
| `grep "password" file` | Find lines containing a word |
| `tail -f /var/log/auth.log` | Watch a log file live |

## File permissions

```
-rwxr-xr--  1 ram  staff  1024  script.sh
 │└┬┘└┬┘└┬┘
 │ │  │  └── others: r-- (read only)
 │ │  └───── group:  r-x (read, execute)
 │ └──────── owner:  rwx (read, write, execute)
 └────────── type: - file, d directory, l link
```

Numbers: **r = 4, w = 2, x = 1**. So `chmod 755` = owner `rwx` (7), group `r-x` (5), others `r-x` (5).

- `chmod 600 secret.txt`: only the owner can read and write. Use this for private keys.
- **Danger:** `chmod 777` lets everyone change the file. Attackers look for files like this.

## Users and privileges

| Command | What it does |
|---------|--------------|
| `whoami` | Which user am I? |
| `id` | My user ID and groups |
| `sudo command` | Run one command as root (admin) |
| `cat /etc/passwd` | List of users (passwords are not stored here) |
| `/etc/shadow` | Where password hashes live; only root can read it |

## Processes and network

| Command | What it does |
|---------|--------------|
| `ps aux` | All running processes |
| `top` | Live view of processes and CPU |
| `kill PID` | Stop a process |
| `ss -tulpn` | Which ports are listening, and by which program |

## Pipes and redirection

```bash
cat access.log | grep "404" | wc -l     # count 404 errors in a log
ls -la > files.txt                       # save output to a file
echo "note" >> notes.txt                 # append to a file
```

## Practice

Play **OverTheWire: Bandit**. Each level teaches one of these commands. Log progress in [`../labs/README.md`](../labs/README.md).

## ✅ Self-check
- [ ] I can read `-rw-r-----` and say who can do what
- [ ] I know the difference between `/etc/passwd` and `/etc/shadow`
- [ ] I can count matching lines in a log with one pipe
