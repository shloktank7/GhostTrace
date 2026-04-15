# GhostTrace

GhostTrace is a local digital identity exposure and exploitation simulator. It maps a simulated identity footprint, generates attacker-style compromise paths, scores the risk, estimates business impact, and produces an executive-ready brief.

The project uses mock OSINT, breach, and dark-web data only. It is designed for defensive education, portfolio demos, and consulting-style risk storytelling.

## Features

- Simulated digital footprint scanner for email or name inputs
- Breach, credential reuse, social, public record, and mock dark-web signals
- Attack path generator for credential stuffing, targeted phishing, SIM swap, helpdesk reset, and invoice fraud
- 0-100 compromise risk score with category scoring
- Business impact estimator with loss range and drivers
- Executive report generator: how you get hacked and how to fix it
- Attack chain graph visualization
- Before/after hardening controls showing risk reduction
- Fix recommendations ranked by impact

## Run locally

```bash
python3 -m pip install -r requirements.txt
python3 app.py
```

Then open:

```text
http://127.0.0.1:5001
```

## API

```bash
curl -X POST http://127.0.0.1:5001/api/scan \
  -H "Content-Type: application/json" \
  -d '{"query":"maya.patel@example.com","hardening":{"mfaEnabled":true}}'
```

## Safety note

GhostTrace does not perform live OSINT lookups, credential testing, dark-web access, account probing, or exploitation. All outputs are simulated from local mock data.
