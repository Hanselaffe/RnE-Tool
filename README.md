# RnE — Mini-Legion Red-Team Orchestrator

RnE is a small operator-driven orchestration tool for **authorized** reconnaissance and exposure triage. Its purpose is to connect established tools instead of reimplementing them: discover services with Nmap, correlate them with Exploit-DB/SearchSploit and NVD, optionally enumerate discovered web services, and write one normalized JSON report.

The R2 refresh restores the original project idea after the earlier maintenance branch reduced RnE too far. RnE is intentionally closer to a compact, scriptable "mini Legion" than to a single-purpose scanner.

## Current adapters

- **Nmap** — host/service discovery and version detection.
- **SearchSploit / Exploit-DB** — exploit candidate correlation in JSON form.
- **NVD CVE API 2.0** — CVE candidate correlation.
- **Gobuster** — optional bounded directory enumeration for discovered web services.
- **SearchSploit mirror** — explicitly copy one selected public Exploit-DB entry into a local workspace for operator review. Mirroring does not execute the exploit.

External tools are optional except Nmap for the scan pipeline. `python rne.py status` shows which adapters are currently available.

## Scan profiles

RnE provides three fixed profiles:

| Profile | Nmap arguments | Purpose |
| --- | --- | --- |
| `quick` | `-sV --version-light -T3 --top-ports 100` | fast service inventory |
| `standard` | `-sV -T3 --top-ports 1000` | normal assessment workflow |
| `deep` | `-sV -T3 -p-` | full TCP port inventory |

`--nse-vuln` explicitly adds Nmap's `vuln` NSE category to the chosen profile. It is never enabled implicitly.

## Safety and operator controls

RnE is a red-team helper, so active capability is controlled rather than removed:

- every scan requires `--authorized`;
- public IPs require the second explicit `--allow-public` gate;
- targets must be literal IPv4/IPv6 addresses;
- subprocesses use argument arrays with `shell=False`;
- command timeouts and result-count bounds are enforced;
- external tool output is bounded before being accepted into the report;
- web enumeration is opt-in and requires an explicit wordlist;
- Gobuster concurrency is capped by the adapter;
- exploit correlation is passive local SearchSploit lookup;
- copying an Exploit-DB entry requires a separate `mirror` command and `--confirm-mirror`;
- RnE does not automatically execute a mirrored exploit.

These controls do not replace network segmentation, rules of engagement, or operator judgment.

## Requirements

- Python 3.10+
- Nmap for active scan runs
- SearchSploit/Exploit-DB for exploit correlation and mirroring
- Gobuster only when `--web-enum` is requested
- network access to NVD only when CVE correlation is enabled

There are no mandatory third-party Python packages.

## Usage

Check adapter availability:

```bash
python rne.py status
```

Standard private/lab assessment:

```bash
python rne.py scan 192.168.56.10 --authorized
```

Fast inventory:

```bash
python rne.py scan 192.168.56.10 --authorized --profile quick
```

Deep authorized inventory with explicitly requested Nmap vulnerability scripts:

```bash
python rne.py scan 192.168.56.10 --authorized --profile deep --nse-vuln
```

Authorized public target:

```bash
python rne.py scan 203.0.113.10 --authorized --allow-public
```

Add web enumeration to web services discovered by Nmap:

```bash
python rne.py scan 192.168.56.10 --authorized --web-enum --wordlist ./wordlists/content.txt
```

Disable one correlation source:

```bash
python rne.py scan 192.168.56.10 --authorized --no-nvd
python rne.py scan 192.168.56.10 --authorized --no-exploit-db
```

Mirror one reviewed Exploit-DB entry into a local workspace:

```bash
python rne.py mirror --edb-id 12345 --workspace ./exploit_workspace --confirm-mirror
```

The mirror command only invokes `searchsploit -m <EDB-ID>` and verifies that exactly one new file appears in the workspace.

## Result model

A scan writes `rne_report.json` by default. The report contains:

- normalized open services;
- Exploit-DB candidates grouped by discovered service;
- NVD CVE candidates grouped by discovered service;
- optional web-enumeration findings;
- external tool availability;
- warnings for unavailable/failed optional adapters;
- the exact external command argument lists executed during the run.

This gives future adapters a stable interface and avoids parsing a single mixed text file as the historical prototype did.

## Architecture

```text
Target + explicit scope gates
          |
          v
        Nmap
          |
          v
  normalized services
     /      |       \
    /       |        \
NVD   SearchSploit   web service?
 |         |             |
 |         |          Gobuster
  \        |             /
   \       |            /
     unified RnE report
            |
      operator actions
            |
   optional EDB mirror
```

The architecture is deliberately adapter-oriented so future integrations can be added without turning the orchestration core back into one large script.

## Tests

All regression tests are offline and mock external tools/network calls:

```bash
python -m unittest discover -s tests -v
python -m compileall -q .
```

A real end-to-end scan should only be performed against an explicitly authorized lab/target after the offline suite passes.
