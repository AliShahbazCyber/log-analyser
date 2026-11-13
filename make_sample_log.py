"""Generate a sample SSH auth.log with a few attack scenarios baked in.

The IP addresses are from the documentation ranges (RFC 5737) and the
usernames are made up, so nothing here refers to a real system.
"""
import random

random.seed(7)  # same file every run, so results in the README can be reproduced


def line(day, time, status, user, ip, invalid=False):
    inv = "invalid user " if invalid else ""
    pid = random.randint(1000, 9999)
    port = random.randint(1024, 65000)
    return (f"Mar {day} {time} server sshd[{pid}]: {status} password "
            f"for {inv}{user} from {ip} port {port} ssh2")


lines = []
legit_ips = ["10.0.0.5", "10.0.0.8", "192.168.0.12"]
legit_users = ["alice", "admin", "deploy"]

# 1. Normal daytime successful logins (baseline)
for t in ["09:14:02", "10:31:44", "13:05:19", "15:47:08"]:
    lines.append(line(10, t, "Accepted", random.choice(legit_users),
                      random.choice(legit_ips)))

# 2. Brute force from one IP: many failures, many usernames, no success
attacker = "203.0.113.7"
usernames = ["root", "admin", "test", "oracle", "postgres", "ubuntu", "git",
             "user", "guest", "ftp", "mysql", "www", "backup", "pi", "support"]
h, m = 11, 0
for u in usernames:
    for _ in range(random.randint(2, 4)):
        lines.append(line(10, f"{h:02d}:{m:02d}:{random.randint(0, 59):02d}",
                          "Failed", u, attacker, invalid=True))
        m += 1
        if m >= 60:
            m, h = 0, h + 1

# 3. Successful brute force: 41 failures on root, then an Accepted
breach = "198.51.100.23"
for i in range(41):
    lines.append(line(10, f"14:{i % 60:02d}:{random.randint(0, 59):02d}",
                      "Failed", "root", breach))
lines.append(line(10, "14:59:31", "Accepted", "root", breach))

# 4. Off-hours login at 03:14
lines.append(line(11, "03:14:52", "Accepted", "admin", "192.0.2.44"))

with open("auth.log", "w") as f:
    f.write("\n".join(lines) + "\n")
print(f"auth.log created with {len(lines)} lines")
