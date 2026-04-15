from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd


ROOT = Path(__file__).resolve().parent.parent
DATA_FILE = ROOT / "data" / "simulated_exposures.json"


@dataclass(frozen=True)
class HardeningProfile:
    password_manager: bool = False
    mfa_enabled: bool = False
    privacy_lockdown: bool = False
    breach_monitoring: bool = False
    sim_swap_lock: bool = False


def load_dataset() -> dict[str, Any]:
    with DATA_FILE.open("r", encoding="utf-8") as dataset:
        return json.load(dataset)


def stable_int(value: str) -> int:
    return int(hashlib.sha256(value.lower().encode("utf-8")).hexdigest()[:12], 16)


def normalize_query(query: str) -> str:
    return " ".join(query.strip().split())


def infer_identity(query: str) -> dict[str, str]:
    cleaned = normalize_query(query)
    if not cleaned:
        cleaned = "alex.morgan@example.com"

    if "@" in cleaned:
        local, domain = cleaned.split("@", 1)
        name_bits = [bit for bit in local.replace(".", " ").replace("_", " ").split() if bit]
        first = name_bits[0].capitalize() if name_bits else "Alex"
        last = name_bits[-1].capitalize() if len(name_bits) > 1 else "Morgan"
        company = domain.split(".")[0].replace("-", " ").title()
        email = cleaned.lower()
    else:
        parts = cleaned.split()
        first = parts[0].capitalize()
        last = parts[-1].capitalize() if len(parts) > 1 else "Morgan"
        company = "Northstar"
        email = f"{first.lower()}.{last.lower()}@northstar.example"

    return {
        "name": f"{first} {last}",
        "email": email,
        "company": company,
        "role": choose(["Finance Lead", "Operations Manager", "Founder", "HR Partner", "Product Lead"], cleaned),
    }


def choose(values: list[Any], key: str, offset: int = 0) -> Any:
    return values[(stable_int(f"{key}:{offset}") % len(values))]


def pick_many(values: list[Any], key: str, minimum: int, maximum: int, offset: int = 0) -> list[Any]:
    if not values:
        return []
    span = maximum - minimum + 1
    count = minimum + (stable_int(f"{key}:count:{offset}") % span)
    ranked = sorted(values, key=lambda item: stable_int(f"{key}:{item.get('id', item)}:{offset}"))
    return ranked[: min(count, len(ranked))]


def clamp(value: float, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, int(round(value))))


def build_exposures(dataset: dict[str, Any], identity: dict[str, str]) -> dict[str, list[dict[str, Any]]]:
    key = identity["email"]
    breaches = pick_many(dataset["breaches"], key, 2, 5)
    socials = pick_many(dataset["social_accounts"], key, 2, 4, 1)
    dark_web = pick_many(dataset["dark_web_listings"], key, 1, 3, 2)
    public_records = pick_many(dataset["public_records"], key, 2, 4, 3)

    credential_reuse = 35 + (stable_int(f"{key}:reuse") % 61)
    password_age_months = 8 + (stable_int(f"{key}:age") % 44)
    recovery_surface = choose(dataset["recovery_surfaces"], key)
    phone_exposed = stable_int(f"{key}:phone") % 100 > 28

    credentials = [
        {
            "id": "password_reuse",
            "label": "Password reuse likelihood",
            "value": f"{credential_reuse}%",
            "severity": "critical" if credential_reuse >= 72 else "high" if credential_reuse >= 55 else "medium",
            "confidence": 0.82,
            "description": "Simulated reuse estimate based on repeated breach categories and account age.",
            "weight": credential_reuse / 100,
        },
        {
            "id": "password_age",
            "label": "Oldest exposed password age",
            "value": f"{password_age_months} months",
            "severity": "high" if password_age_months >= 30 else "medium",
            "confidence": 0.75,
            "description": "Older leaked credentials remain useful when people recycle password patterns.",
            "weight": min(password_age_months / 48, 1),
        },
        {
            "id": "recovery_surface",
            "label": "Account recovery surface",
            "value": recovery_surface["label"],
            "severity": recovery_surface["severity"],
            "confidence": recovery_surface["confidence"],
            "description": recovery_surface["description"],
            "weight": recovery_surface["weight"],
        },
    ]

    if phone_exposed:
        credentials.append(
            {
                "id": "phone_exposed",
                "label": "Phone number exposure",
                "value": "Likely exposed",
                "severity": "high",
                "confidence": 0.7,
                "description": "A phone number connected to recovery flows increases SIM-swap and helpdesk risk.",
                "weight": 0.74,
            }
        )

    return {
        "breaches": breaches,
        "socials": socials,
        "darkWeb": dark_web,
        "publicRecords": public_records,
        "credentials": credentials,
    }


def severity_points(severity: str) -> int:
    return {
        "low": 20,
        "medium": 45,
        "high": 70,
        "critical": 92,
    }.get(severity, 35)


def category_score(items: list[dict[str, Any]]) -> float:
    if not items:
        return 0
    frame = pd.DataFrame(items)
    if "severity" not in frame:
        return 0
    frame["points"] = frame["severity"].map(severity_points)
    frame["confidence"] = frame.get("confidence", 0.7)
    if "weight" in frame:
        frame["points"] = frame["points"] * frame["weight"].clip(0.35, 1.15)
    return min(100, frame["points"].mul(frame["confidence"]).sum() / max(1.2, math.sqrt(len(frame)) * 1.35))


def hardening_reduction(profile: HardeningProfile) -> int:
    reduction = 0
    reduction += 16 if profile.password_manager else 0
    reduction += 18 if profile.mfa_enabled else 0
    reduction += 10 if profile.privacy_lockdown else 0
    reduction += 9 if profile.breach_monitoring else 0
    reduction += 12 if profile.sim_swap_lock else 0
    return reduction


def score_identity(exposures: dict[str, list[dict[str, Any]]], profile: HardeningProfile) -> dict[str, Any]:
    category_weights = {
        "breaches": 0.28,
        "credentials": 0.32,
        "socials": 0.16,
        "darkWeb": 0.15,
        "publicRecords": 0.09,
    }
    category_scores = {
        category: round(category_score(exposures.get(category, [])), 1)
        for category in category_weights
    }
    raw_score = sum(category_scores[category] * weight for category, weight in category_weights.items())
    final_score = clamp(raw_score - hardening_reduction(profile))

    if final_score >= 78:
        band = "Severe"
    elif final_score >= 58:
        band = "High"
    elif final_score >= 35:
        band = "Moderate"
    else:
        band = "Managed"

    return {
        "score": final_score,
        "band": band,
        "rawScore": round(raw_score, 1),
        "categoryScores": category_scores,
        "hardeningReduction": hardening_reduction(profile),
    }


def build_attack_paths(
    dataset: dict[str, Any],
    identity: dict[str, str],
    exposures: dict[str, list[dict[str, Any]]],
    score: dict[str, Any],
) -> list[dict[str, Any]]:
    key = identity["email"]
    paths = [
        {
            "id": "credential-takeover",
            "title": "Credential stuffing into cloud apps",
            "likelihood": min(96, 42 + score["categoryScores"]["credentials"] * 0.58),
            "impact": "Account takeover, mailbox access, invoice fraud",
            "steps": [
                f"Find {identity['email']} in breach bundles",
                "Test password patterns against email, payroll, and SaaS portals",
                "Search mailbox for invoices, reset links, and vendor contacts",
                "Trigger payment change or data export from a trusted account",
            ],
            "evidence": [
                exposures["breaches"][0]["name"] if exposures["breaches"] else "Historical credential leak",
                exposures["credentials"][0]["value"],
            ],
            "fix": "Enforce unique passwords, phishing-resistant MFA, and login velocity alerts.",
        },
        {
            "id": "phishing-pretext",
            "title": "Targeted phishing using public context",
            "likelihood": min(94, 35 + score["categoryScores"]["socials"] * 0.45 + score["categoryScores"]["publicRecords"] * 0.28),
            "impact": "Credential capture or malware delivery through a believable pretext",
            "steps": [
                "Collect role, employer, posting cadence, and personal interests",
                "Craft a message that references a recent project or public profile",
                "Send a fake document share or SSO prompt",
                "Use captured session token before security teams can react",
            ],
            "evidence": [
                exposures["socials"][0]["platform"] if exposures["socials"] else "Public profile cluster",
                exposures["publicRecords"][0]["label"] if exposures["publicRecords"] else "Open web reference",
            ],
            "fix": "Reduce public recovery clues and run executive-style phishing simulations.",
        },
        {
            "id": "sim-swap",
            "title": "SIM swap assisted account recovery",
            "likelihood": min(88, 28 + score["categoryScores"]["credentials"] * 0.32 + score["categoryScores"]["darkWeb"] * 0.42),
            "impact": "SMS code interception and recovery flow abuse",
            "steps": [
                "Correlate phone, address, and date hints from exposed records",
                "Impersonate the target through a carrier or helpdesk channel",
                "Intercept SMS-based recovery codes",
                "Reset passwords on email or financial platforms",
            ],
            "evidence": [
                "Phone exposure signal" if any(item["id"] == "phone_exposed" for item in exposures["credentials"]) else "Recovery metadata",
                exposures["darkWeb"][0]["market"] if exposures["darkWeb"] else "Mock dark-web listing",
            ],
            "fix": "Add carrier port freeze, remove SMS recovery, and require hardware-backed MFA.",
        },
    ]

    bonus_path = choose(dataset["bonus_attack_paths"], key)
    paths.append(bonus_path)
    return sorted(paths, key=lambda path: path["likelihood"], reverse=True)


def estimate_business_impact(identity: dict[str, str], score: dict[str, Any], paths: list[dict[str, Any]]) -> dict[str, Any]:
    role_multiplier = {
        "Finance Lead": 1.55,
        "Operations Manager": 1.25,
        "Founder": 1.75,
        "HR Partner": 1.4,
        "Product Lead": 1.1,
    }.get(identity["role"], 1.0)
    path_pressure = sum(path["likelihood"] for path in paths[:3]) / 300
    base = 14000 + score["score"] * 620
    estimate = int(round(base * role_multiplier * (0.86 + path_pressure), -2))

    return {
        "estimatedFinancialRisk": estimate,
        "rangeLow": int(round(estimate * 0.58, -2)),
        "rangeHigh": int(round(estimate * 1.68, -2)),
        "primaryLossDrivers": [
            "Account takeover response and recovery",
            "Vendor payment diversion exposure",
            "Legal, notification, and productivity costs",
        ],
        "assumption": "Mock consulting estimate for portfolio/demo use; not a financial guarantee.",
    }


def recommendations(profile: HardeningProfile) -> list[dict[str, Any]]:
    items = [
        {
            "id": "mfa",
            "title": "Move critical accounts to phishing-resistant MFA",
            "impact": 18,
            "effort": "Medium",
            "status": "done" if profile.mfa_enabled else "recommended",
        },
        {
            "id": "passwords",
            "title": "Rotate exposed credentials and enforce a password manager",
            "impact": 16,
            "effort": "Low",
            "status": "done" if profile.password_manager else "recommended",
        },
        {
            "id": "carrier-lock",
            "title": "Enable carrier port freeze and remove SMS recovery",
            "impact": 12,
            "effort": "Low",
            "status": "done" if profile.sim_swap_lock else "recommended",
        },
        {
            "id": "privacy",
            "title": "Reduce public recovery clues on social and people-search sites",
            "impact": 10,
            "effort": "Medium",
            "status": "done" if profile.privacy_lockdown else "recommended",
        },
        {
            "id": "monitoring",
            "title": "Add breach monitoring and account change alerts",
            "impact": 9,
            "effort": "Low",
            "status": "done" if profile.breach_monitoring else "recommended",
        },
    ]
    return sorted(items, key=lambda item: (item["status"] == "done", -item["impact"]))


def build_graph(identity: dict[str, str], exposures: dict[str, list[dict[str, Any]]], paths: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    nodes = [
        {"id": "identity", "label": identity["name"], "type": "identity", "risk": 80},
        {"id": "email", "label": identity["email"], "type": "asset", "risk": 70},
    ]
    edges = [{"source": "identity", "target": "email", "label": "owns"}]

    for breach in exposures["breaches"]:
        node_id = f"breach-{breach['id']}"
        nodes.append({"id": node_id, "label": breach["name"], "type": "breach", "risk": severity_points(breach["severity"])})
        edges.append({"source": "email", "target": node_id, "label": "found in"})

    for social in exposures["socials"]:
        node_id = f"social-{social['id']}"
        nodes.append({"id": node_id, "label": social["platform"], "type": "social", "risk": severity_points(social["severity"])})
        edges.append({"source": "identity", "target": node_id, "label": "public profile"})

    for listing in exposures["darkWeb"]:
        node_id = f"dark-{listing['id']}"
        nodes.append({"id": node_id, "label": listing["market"], "type": "dark", "risk": severity_points(listing["severity"])})
        edges.append({"source": "email", "target": node_id, "label": "listed"})

    for path in paths[:3]:
        node_id = f"path-{path['id']}"
        nodes.append({"id": node_id, "label": path["title"], "type": "path", "risk": int(path["likelihood"])})
        edges.append({"source": "email", "target": node_id, "label": "enables"})

    return {"nodes": nodes, "edges": edges}


def build_report(
    identity: dict[str, str],
    score: dict[str, Any],
    impact: dict[str, Any],
    paths: list[dict[str, Any]],
    recs: list[dict[str, Any]],
) -> dict[str, Any]:
    top_path = paths[0]
    open_recs = [rec for rec in recs if rec["status"] != "done"]
    return {
        "title": f"GhostTrace Executive Exposure Brief: {identity['name']}",
        "summary": (
            f"{identity['name']} shows a {score['band'].lower()} identity compromise risk score of "
            f"{score['score']}/100. The strongest simulated attack path is '{top_path['title']}', "
            f"which could lead to {top_path['impact'].lower()}."
        ),
        "howYouGetHacked": top_path["steps"],
        "businessImpact": (
            f"Estimated financial exposure is ${impact['estimatedFinancialRisk']:,} "
            f"(${impact['rangeLow']:,}-${impact['rangeHigh']:,}) based on role sensitivity, "
            "exposure severity, and likely response cost."
        ),
        "fixPlan": [rec["title"] for rec in open_recs[:4]],
        "disclaimer": "All findings use simulated OSINT and mock dark-web data for defensive education and portfolio demonstration.",
    }


def parse_hardening(payload: dict[str, Any] | None) -> HardeningProfile:
    payload = payload or {}
    return HardeningProfile(
        password_manager=bool(payload.get("passwordManager")),
        mfa_enabled=bool(payload.get("mfaEnabled")),
        privacy_lockdown=bool(payload.get("privacyLockdown")),
        breach_monitoring=bool(payload.get("breachMonitoring")),
        sim_swap_lock=bool(payload.get("simSwapLock")),
    )


def scan_identity(query: str, hardening: dict[str, Any] | None = None) -> dict[str, Any]:
    dataset = load_dataset()
    identity = infer_identity(query)
    profile = parse_hardening(hardening)
    exposures = build_exposures(dataset, identity)
    score = score_identity(exposures, profile)
    default_score = score_identity(exposures, HardeningProfile())
    fully_hardened = score_identity(
        exposures,
        HardeningProfile(
            password_manager=True,
            mfa_enabled=True,
            privacy_lockdown=True,
            breach_monitoring=True,
            sim_swap_lock=True,
        ),
    )
    paths = build_attack_paths(dataset, identity, exposures, score)
    impact = estimate_business_impact(identity, score, paths)
    recs = recommendations(profile)

    return {
        "identity": identity,
        "scanMode": "simulated-osint",
        "generatedAt": pd.Timestamp.utcnow().isoformat(),
        "score": score,
        "exposures": exposures,
        "attackPaths": paths,
        "businessImpact": impact,
        "recommendations": recs,
        "beforeAfter": {
            "current": score["score"],
            "unhardened": default_score["score"],
            "fullyHardened": fully_hardened["score"],
            "riskDrop": max(0, default_score["score"] - fully_hardened["score"]),
        },
        "graph": build_graph(identity, exposures, paths),
        "report": build_report(identity, score, impact, paths, recs),
    }

