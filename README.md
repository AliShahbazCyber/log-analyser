# SSH Log Analyser

A small Python tool that reads an SSH `auth.log` and reports the login patterns a SOC analyst would want to look at first. It uses only the standard library, so there is nothing to install.

## What it flags

| Finding | Rule |
|---|---|
| Possible successful brute force | 10 or more failed logins from one IP, followed by an accepted login from the same IP |
| Brute-force attempt | 10 or more failed logins from one IP and no success |
| Credential stuffing | One IP trying 5 or more different usernames |
| Out-of-hours login | An accepted login between 00:00 and 05:59 |

The thresholds are constants at the top of `log_analyser.py`.

## Run it

```
python make_sample_log.py
python log_analyser.py auth.log
```

`make_sample_log.py` writes a 93-line test log with four scenarios in it: normal daytime logins, a noisy brute force, a brute force that ends in a successful login, and one login at 03:14. On a Linux machine you can point the tool at the real log instead:

```
python log_analyser.py /var/log/auth.log
```

## Sample output

```
[SUMMARY]
  Failed logins:      87
  Successful logins:  6
  Unique source IPs:  5

[!! CRITICAL] Possible SUCCESSFUL brute-force
  198.51.100.23  ->  41 failed, then SUCCESS  (tried 1 users)

[!]  WARNING - Brute-force attempts (10 or more failures)
  203.0.113.7  ->  46 failed attempts, 15 usernames (credential stuffing)

[!]  WARNING - Out-of-hours logins (00:00-05:59)
  03:14:52  Accepted login for 'admin' from 192.0.2.44
```

## How it works

1. One regular expression with named groups pulls the time, status, username and source IP out of each `sshd` line.
2. Every attempt is grouped by source IP in a dictionary: failures, successes, usernames tried, and how many failures came before the first success.
3. The report compares those counts against the thresholds.

Counting failures before the first success matters. Without it, someone who logs in normally and later mistypes a password ten times would be reported as a break-in.

## Limits

I have only tested this on generated data, which is much cleaner than a real server log.

- It counts failures across the whole file, with no time window. A slow attacker spread over days looks the same as a fast one, and on a month of logs most busy IPs would cross the threshold.
- It only reads password logins. Public key logins and other `sshd` messages are ignored.
- IPv4 only.
- The out-of-hours window is fixed and takes the log's timestamps as they are, with no timezone handling.

## Next

- A sliding time window for the brute-force rule
- Windows Security event logs (4624 and 4625)
- Output as CSV or JSON so the findings can go into another tool

The sample data uses documentation IP ranges (RFC 5737) and made-up usernames.
