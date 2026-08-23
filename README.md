# RnE Tool — Reconnaissance and Exposure Triage

RnE is a small **read-only** helper for authorized service inventory and CVE triage.

The 2026 maintenance refresh intentionally removes the historical exploit-execution workflow. The tool no longer copies exploit code, launches DirBuster, or offers automated exploitation.

## Safety boundary

- active scanning requires the explicit `--authorized` flag;
- public IP addresses additionally require `--allow-public`;
- targets must be literal IPv4/IPv6 addresses;
- Nmap arguments are fixed to a conservative service-inventory profile;
- no shell commands are constructed from user input;
- no exploit execution or exploit materialization exists;
- output is structured JSON.

Use only on systems you own or are explicitly authorized to assess.

## Requirements

- Python 3.10+
- Nmap available on `PATH`
- network access to NVD only when CVE triage is desired

No third-party Python packages are required.

## Usage

Private/lab target:

```bash
python rne.py 192.168.1.10 --authorized
```

Authorized public target:

```bash
python rne.py 203.0.113.10 --authorized --allow-public
```

Custom report path:

```bash
python rne.py 127.0.0.1 --authorized --output evidence/scan_results.json
```

## Scan profile

The active inventory uses a fixed Nmap profile equivalent to:

```text
-sV --version-light -T3 --top-ports 100
```

This is intentionally narrower than the historical `-A -T4 -p- --script vuln` behavior.

## NVD

CVE triage uses the NVD CVE API 2.0 endpoint and keyword search. Results are leads for review, not proof that a detected service is vulnerable.

## Tests

```bash
python -m unittest discover -s tests -v
```

The unit tests do not perform network scans or NVD requests.
