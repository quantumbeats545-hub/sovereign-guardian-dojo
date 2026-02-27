#!/usr/bin/env python3
"""
Production Feedback → Dojo Scenario Converter

Converts Guardian feedback JSON (exported from FreedomWallet) into
training scenarios for the Financial Dojo. Each real transaction gives
signal about whether the Guardian got it right:

  - userOverrodeWarning: true  → potential false positive (too aggressive)
  - suspicionLevel > 0.5 + no alerts → potential false negative (missed it)
  - Clean tx, no warnings → benign baseline

Output uses the same scenario schema as world_data_to_dojo.py, compatible
with ThreatSimulator.loadMoltbookScenarios().

Usage:
    python3 feedback_to_dojo.py [path_to_feedback_export.json]

If no path given, reads from ~/.config/observer/raw/feedback_*.json
"""

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ==================== PATHS ====================
RAW_DIR = Path.home() / ".config" / "observer" / "raw"
FINANCIAL_DOJO_DIR = Path.home() / ".config" / "observer" / "scenarios" / "financial_dojo"
FINANCIAL_DOJO_DIR.mkdir(parents=True, exist_ok=True)


def _log(*args):
    print(f"[{datetime.now(timezone.utc).isoformat()}]", *args, flush=True)


def classify_feedback(record: dict) -> dict:
    """Classify a single feedback record into a training scenario."""
    overrode = record.get("userOverrodeWarning", False)
    suspicion = record.get("suspicionLevel", 0.0)
    alerts = record.get("alertsTriggered", [])
    warnings = record.get("advisoryWarnings", [])
    auto_sign = record.get("autoSignUsed", False)
    amount_usd = float(record.get("amountUSD", 0))
    chain = record.get("chain", "unknown")
    tx_hash = record.get("txHash", "")

    # Classification logic
    if overrode:
        # User saw warnings but proceeded — Guardian may have been too aggressive
        scenario_type = "falsePositiveCandidate"
        is_threat = False
        correct_decision = "ALLOW"
        severity = round(min(suspicion, 0.4), 3)
        difficulty = "hard"
    elif suspicion > 0.5 and not alerts:
        # High suspicion but no alerts fired — Guardian may have missed something
        scenario_type = "falseNegativeCandidate"
        is_threat = True
        correct_decision = "ALERT"
        severity = round(suspicion, 3)
        difficulty = "hard"
    elif alerts:
        # Alerts fired and user did NOT override — Guardian correctly flagged
        scenario_type = "truePositive"
        is_threat = True
        correct_decision = "ALERT"
        severity = round(min(0.5 + suspicion * 0.3, 0.9), 3)
        difficulty = "medium"
    else:
        # Clean transaction, no warnings, no alerts — benign baseline
        scenario_type = "benignBaseline"
        is_threat = False
        correct_decision = "ALLOW"
        severity = 0.0
        difficulty = "easy"

    # Build risk indicators from context
    risk_indicators = list(alerts)
    if auto_sign:
        risk_indicators.append("auto_sign_used")
    if amount_usd > 5000:
        risk_indicators.append("high_value_tx")
    if amount_usd > 1000:
        risk_indicators.append("medium_value_tx")

    # Build threat content summary
    warning_text = "; ".join(warnings) if warnings else "No warnings"
    threat_content = (
        f"Transaction on {chain}: ${amount_usd:.2f} USD. "
        f"Suspicion level: {suspicion:.2f}. "
        f"Alerts: {', '.join(alerts) if alerts else 'none'}. "
        f"Warnings shown: {warning_text}. "
        f"User overrode: {overrode}. Auto-sign: {auto_sign}."
    )

    return {
        "source": "production_feedback",
        "id": str(uuid.uuid4()),
        "context": {
            "scenarioType": scenario_type,
            "profileType": "wallet_user",
            "platform": "FreedomWallet",
            "threatContent": threat_content,
            "senderInfo": {
                "displayName": "Wallet User",
                "accountAge": "unknown",
                "mutualConnections": 0,
                "isVerified": True,
                "riskIndicators": risk_indicators,
            },
            "groundTruth": {
                "isThreat": is_threat,
                "correctDecision": correct_decision,
                "threatCategory": scenario_type,
                "severity": severity,
                "patterns": alerts + [w[:80] for w in warnings[:3]],
            },
            "policyRules": [],
            "transactionContext": {
                "chain": chain,
                "amountUSD": amount_usd,
                "txHash": tx_hash,
                "suspicionLevel": suspicion,
                "autoSign": auto_sign,
                "alertCount": len(alerts),
                "warningCount": len(warnings),
                "userOverrode": overrode,
            },
        },
        "conversationHistory": [threat_content],
        "difficulty": difficulty,
        "metadata": {
            "source": "production_feedback",
            "chain": chain,
            "amountUSD": amount_usd,
            "convertedAt": datetime.now(timezone.utc).isoformat(),
        },
    }


def load_feedback(path: str | None = None) -> list[dict]:
    """Load feedback records from a file or glob the raw directory."""
    if path:
        p = Path(path)
        if not p.exists():
            _log(f"ERROR: File not found: {path}")
            return []
        with open(p) as f:
            data = json.load(f)
        # Handle both single-record and array exports
        return data if isinstance(data, list) else [data]

    # Glob for feedback files in raw directory
    files = sorted(RAW_DIR.glob("feedback_*.json"))
    if not files:
        # Also try guardian_feedback_export_*.json (from FeedbackStore.exportJSON)
        files = sorted(RAW_DIR.glob("guardian_feedback_export_*.json"))
    if not files:
        _log("No feedback files found in", RAW_DIR)
        return []

    records = []
    for f in files:
        try:
            with open(f) as fh:
                data = json.load(fh)
            if isinstance(data, list):
                records.extend(data)
            else:
                records.append(data)
        except (json.JSONDecodeError, OSError) as e:
            _log(f"Skipping {f.name}: {e}")
    return records


def convert_and_save(records: list[dict]) -> dict:
    """Convert feedback records to scenarios and save to financial dojo dir."""
    stats = {"total": 0, "falsePositive": 0, "falseNegative": 0, "truePositive": 0, "benign": 0}

    for record in records:
        scenario = classify_feedback(record)
        stats["total"] += 1

        st = scenario["context"]["scenarioType"]
        if st == "falsePositiveCandidate":
            stats["falsePositive"] += 1
        elif st == "falseNegativeCandidate":
            stats["falseNegative"] += 1
        elif st == "truePositive":
            stats["truePositive"] += 1
        else:
            stats["benign"] += 1

        # Write scenario file
        filename = f"fb_{scenario['id'][:8]}.json"
        out_path = FINANCIAL_DOJO_DIR / filename
        with open(out_path, "w") as f:
            json.dump(scenario, f, indent=2)

    return stats


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else None
    _log("Loading production feedback...")
    records = load_feedback(path)

    if not records:
        _log("No records to process.")
        return

    _log(f"Processing {len(records)} feedback records...")
    stats = convert_and_save(records)

    _log("Conversion complete:")
    _log(f"  Total:            {stats['total']}")
    _log(f"  False positives:  {stats['falsePositive']}")
    _log(f"  False negatives:  {stats['falseNegative']}")
    _log(f"  True positives:   {stats['truePositive']}")
    _log(f"  Benign baseline:  {stats['benign']}")
    _log(f"  Output dir:       {FINANCIAL_DOJO_DIR}")


if __name__ == "__main__":
    main()
