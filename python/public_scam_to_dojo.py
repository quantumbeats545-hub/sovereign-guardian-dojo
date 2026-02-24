#!/usr/bin/env python3
"""
Public Scam → Dojo Scenario Converter

Converts sanitised public scam data (Scamwatch, PhishTank, OpenPhish, URLhaus)
into Guardian Dojo and Financial Dojo scenario formats.

Only patterns reach the dojos — never raw victim data. 100% on-device.
"""

import json
import re
import sys
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path

# ==================== PATHS ====================
RAW_DIR = Path.home() / ".config" / "observer" / "raw"
GUARDIAN_DOJO_DIR = Path.home() / ".config" / "observer" / "scenarios" / "guardian_dojo"
FINANCIAL_DOJO_DIR = Path.home() / ".config" / "observer" / "scenarios" / "financial_dojo"
PROCESSED_LOG = Path.home() / ".config" / "observer" / "scam_processed.json"

GUARDIAN_DOJO_DIR.mkdir(parents=True, exist_ok=True)
FINANCIAL_DOJO_DIR.mkdir(parents=True, exist_ok=True)


def _log(*args):
    print(f"[{datetime.now(timezone.utc).isoformat()}]", *args, flush=True)


# ==================== SIGNAL DETECTION ====================
# Reuse the same behavioral categories as moltbook_to_dojo.py
SIGNAL_PATTERNS = {
    "urgency_pressure": [
        r"act now", r"urgent", r"immediately", r"expires? (today|soon|in \d)",
        r"limited time", r"last chance", r"don.t delay", r"right away",
        r"within (24|48) hours", r"suspended", r"locked",
    ],
    "authority_claim": [
        r"government", r"tax office", r"ato\b", r"centrelink", r"myGov",
        r"police", r"federal", r"official", r"department", r"court",
        r"bank of", r"commonwealth", r"westpac", r"nab\b", r"anz\b",
    ],
    "information_extraction": [
        r"verify your", r"confirm your", r"update your (details|account|payment)",
        r"click (here|the link|below)", r"log ?in", r"enter your",
        r"provide your", r"send (me |us )?your", r"personal (details|information)",
    ],
    "deception": [
        r"won a prize", r"you(?:'ve| have) been selected", r"congratulations",
        r"unclaimed", r"inheritance", r"beneficiary", r"lottery",
        r"refund", r"overpaid", r"compensation",
    ],
    "resource_solicitation": [
        r"gift ?card", r"bitcoin", r"crypto", r"wire transfer", r"itunes",
        r"pay ?\$?\d+", r"fee of", r"processing fee", r"upfront",
        r"invest", r"guaranteed returns", r"double your",
    ],
    "emotional_manipulation": [
        r"i love you", r"soul ?mate", r"trust me", r"only you",
        r"don.t tell anyone", r"our secret", r"lonely", r"help me",
        r"sick|dying|hospital|surgery", r"stranded",
    ],
}


def detect_signals(text: str) -> dict[str, list[str]]:
    """Detect behavioral signals in text. Returns {category: [matched_phrases]}."""
    signals = {}
    text_lower = text.lower()
    for category, patterns in SIGNAL_PATTERNS.items():
        matches = []
        for pattern in patterns:
            found = re.findall(pattern, text_lower)
            if found:
                matches.extend(found[:3])  # Cap per pattern
        if matches:
            signals[category] = matches
    return signals


def compute_threat_score(signals: dict) -> float:
    """Compute threat score from signals. Same algorithm as moltbook converter."""
    weights = {
        "urgency_pressure": 0.15,
        "authority_claim": 0.15,
        "information_extraction": 0.25,
        "deception": 0.20,
        "resource_solicitation": 0.20,
        "emotional_manipulation": 0.15,
    }
    score = 0.0
    for cat, matches in signals.items():
        w = weights.get(cat, 0.10)
        # Diminishing returns per match
        for i, _ in enumerate(matches):
            score += w * (0.5 ** i)

    # Diversity multiplier
    n_cats = len(signals)
    if n_cats >= 3:
        score *= 1.3
    elif n_cats >= 2:
        score *= 1.1
    elif n_cats == 1:
        score *= 0.6

    return min(score, 1.0)


# ==================== SCAMWATCH → GUARDIAN DOJO ====================
SCAMWATCH_TO_GUARDIAN_TYPE = {
    "sms_scams": "phishing",
    "phone_scams": "seniorScam",
    "email_scams": "phishing",
    "investment_scams": "gamingScam",  # Closest match — financial lure
    "buying_scams": "gamingScam",
    "romance_scams": "grooming",
}

SCAMWATCH_TO_FINANCIAL_TYPE = {
    "sms_scams": "phishingDapp",
    "phone_scams": "trustedAdvisor",
    "email_scams": "phishingDapp",
    "investment_scams": "rugPull",
    "buying_scams": "tradingBotScam",
    "romance_scams": "trustedAdvisor",
}


def convert_scamwatch(record: dict) -> tuple[list[dict], list[dict]]:
    """Convert a Scamwatch record into Guardian + Financial dojo scenarios."""
    guardian_scenarios = []
    financial_scenarios = []

    category = record.get("category", "email_scams")
    examples = record.get("examples", [])
    full_text = record.get("full_text", "")

    for ex in examples:
        text = ex.get("text", "")
        if len(text) < 20:
            continue

        signals = detect_signals(text)
        threat_score = compute_threat_score(signals)
        if threat_score < 0.1:
            # Also check against full page context
            signals = detect_signals(text + " " + full_text[:500])
            threat_score = compute_threat_score(signals)

        is_threat = threat_score >= 0.25
        if threat_score >= 0.5:
            correct_decision = "BLOCK"
            difficulty = "easy"
        elif threat_score >= 0.25:
            correct_decision = "ALERT"
            difficulty = "medium"
        else:
            correct_decision = "ALLOW"
            difficulty = "hard"

        severity = min(0.3 + threat_score * 0.7, 1.0) if is_threat else threat_score

        # Guardian scenario
        guardian_type = SCAMWATCH_TO_GUARDIAN_TYPE.get(category, "phishing")
        guardian_scenarios.append({
            "source": "scamwatch",
            "id": str(uuid.uuid4()),
            "context": {
                "scenarioType": guardian_type,
                "profileType": "senior" if category in ("phone_scams", "romance_scams") else "child",
                "platform": "SMS" if "sms" in category else "Email" if "email" in category else "Phone",
                "threatContent": text,
                "senderInfo": {
                    "displayName": "Unknown Sender",
                    "accountAge": "unknown",
                    "mutualConnections": 0,
                    "isVerified": False,
                    "riskIndicators": list(signals.keys()),
                },
                "groundTruth": {
                    "isThreat": is_threat,
                    "correctDecision": correct_decision,
                    "threatCategory": guardian_type if is_threat else None,
                    "severity": round(severity, 3),
                    "patterns": [m for matches in signals.values() for m in matches[:2]],
                },
                "policyRules": [],
            },
            "conversationHistory": [text],
            "difficulty": difficulty,
            "metadata": {
                "source": "scamwatch",
                "category": category,
                "exampleType": ex.get("type", "unknown"),
                "convertedAt": datetime.now(timezone.utc).isoformat(),
            },
        })

        # Financial scenario (only for investment/buying/phishing-related)
        fin_type = SCAMWATCH_TO_FINANCIAL_TYPE.get(category, "phishingDapp")
        chain = "ethereum"  # Default — scamwatch doesn't specify chain
        if any(kw in text.lower() for kw in ["bitcoin", "btc"]):
            chain = "bitcoin"
        elif any(kw in text.lower() for kw in ["solana", "sol"]):
            chain = "solana"

        financial_scenarios.append({
            "id": str(uuid.uuid4()),
            "context": {
                "threatType": fin_type,
                "walletProfile": "novice",
                "chain": chain,
                "transactionData": text[:2000],
                "txContext": {
                    "contractAddress": "0x" + hashlib.sha256(text.encode()).hexdigest()[:40],
                    "contractAge": "unknown",
                    "liquidityUSD": 0.0,
                    "isVerified": False,
                    "riskIndicators": list(signals.keys()),
                    "chain": chain,
                },
                "groundTruth": {
                    "isThreat": is_threat,
                    "correctDecision": correct_decision,
                    "threatCategory": fin_type if is_threat else None,
                    "severity": round(severity, 3),
                    "patterns": [m for matches in signals.values() for m in matches[:2]],
                },
                "policyRules": [],
            },
            "transactionHistory": [text],
            "difficulty": difficulty,
            "metadata": {
                "source": "scamwatch",
                "category": category,
                "originalExampleType": ex.get("type", "unknown"),
                "convertedAt": datetime.now(timezone.utc).isoformat(),
            },
        })

    return guardian_scenarios, financial_scenarios


# ==================== PHISHING FEEDS → FINANCIAL DOJO ====================
def convert_phishing_feed(record: dict) -> tuple[list[dict], list[dict]]:
    """Convert PhishTank/OpenPhish/URLhaus records into Financial Dojo scenarios."""
    guardian_scenarios = []
    financial_scenarios = []
    source = record.get("source", "unknown")

    urls = []
    if source == "phishtank":
        for entry in record.get("entries", []):
            urls.append({
                "url": entry.get("url", ""),
                "target": entry.get("target", "unknown"),
                "threat": "phishing",
            })
    elif source == "openphish":
        for url in record.get("urls", []):
            urls.append({"url": url, "target": "unknown", "threat": "phishing"})
    elif source == "urlhaus":
        for entry in record.get("entries", []):
            urls.append({
                "url": entry.get("url", ""),
                "target": "unknown",
                "threat": entry.get("threat", "malware"),
                "tags": entry.get("tags", ""),
            })

    for item in urls[:50]:  # Cap per batch
        url = item["url"]
        if len(url) < 10:
            continue

        # Determine financial threat type from URL patterns
        url_lower = url.lower()
        if any(kw in url_lower for kw in ["wallet", "metamask", "phantom", "uniswap", "pancake"]):
            fin_type = "drainerContract"
        elif any(kw in url_lower for kw in ["airdrop", "claim", "reward"]):
            fin_type = "fakeAirdrop"
        elif any(kw in url_lower for kw in ["seed", "recovery", "mnemonic"]):
            fin_type = "seedPhraseScam"
        elif item.get("threat") == "malware":
            fin_type = "drainerContract"
        else:
            fin_type = "phishingDapp"

        # Detect chain from URL
        chain = "ethereum"
        if "solana" in url_lower or "phantom" in url_lower:
            chain = "solana"
        elif "bsc" in url_lower or "pancake" in url_lower:
            chain = "bsc"

        threat_text = f"Suspicious URL detected: {url}"
        if item.get("target") != "unknown":
            threat_text += f" (targeting: {item['target']})"

        financial_scenarios.append({
            "id": str(uuid.uuid4()),
            "context": {
                "threatType": fin_type,
                "walletProfile": "novice",
                "chain": chain,
                "transactionData": threat_text,
                "txContext": {
                    "contractAddress": "0x" + hashlib.sha256(url.encode()).hexdigest()[:40],
                    "contractAge": "< 24 hours",
                    "liquidityUSD": 0.0,
                    "isVerified": False,
                    "riskIndicators": [source, item.get("threat", "phishing")],
                    "chain": chain,
                },
                "groundTruth": {
                    "isThreat": True,
                    "correctDecision": "BLOCK",
                    "threatCategory": fin_type,
                    "severity": 0.8,
                    "patterns": [url],
                },
                "policyRules": [],
            },
            "transactionHistory": [threat_text],
            "difficulty": "easy",
            "metadata": {
                "source": source,
                "originalUrl": url,
                "target": item.get("target", "unknown"),
                "tags": item.get("tags", ""),
                "convertedAt": datetime.now(timezone.utc).isoformat(),
            },
        })

    return guardian_scenarios, financial_scenarios


# ==================== MAIN ====================
def main():
    _log("Public Scam → Dojo Converter starting")

    # Load processed file list
    processed = set()
    if PROCESSED_LOG.exists():
        try:
            processed = set(json.loads(PROCESSED_LOG.read_text()))
        except (json.JSONDecodeError, TypeError):
            pass

    # Find all scam_*.json files
    scam_files = sorted(RAW_DIR.glob("scam_*.json"))
    if not scam_files:
        _log("No scam files to convert.")
        return

    _log(f"Found {len(scam_files)} scam files, {len(processed)} already processed")

    total_guardian = 0
    total_financial = 0
    ts = int(datetime.now(timezone.utc).timestamp())

    for sf in scam_files:
        if sf.name in processed:
            continue

        try:
            record = json.loads(sf.read_text())
        except (json.JSONDecodeError, ValueError):
            _log(f"  Skipping malformed: {sf.name}")
            processed.add(sf.name)
            continue

        source = record.get("source", "unknown")

        if source == "scamwatch":
            g_scenarios, f_scenarios = convert_scamwatch(record)
        elif source in ("phishtank", "openphish", "urlhaus"):
            g_scenarios, f_scenarios = convert_phishing_feed(record)
        else:
            _log(f"  Unknown source: {source} in {sf.name}")
            processed.add(sf.name)
            continue

        # Write Guardian scenarios
        for i, gs in enumerate(g_scenarios):
            fname = f"scamwatch_{ts}_{sf.stem}_{i}.json"
            (GUARDIAN_DOJO_DIR / fname).write_text(json.dumps(gs, indent=2))
            total_guardian += 1

        # Write Financial scenarios
        for i, fs in enumerate(f_scenarios):
            fname = f"financial_scam_{ts}_{sf.stem}_{i}.json"
            (FINANCIAL_DOJO_DIR / fname).write_text(json.dumps(fs, indent=2))
            total_financial += 1

        processed.add(sf.name)

    # Save processed log
    PROCESSED_LOG.write_text(json.dumps(list(processed)))

    _log(f"Conversion complete:")
    _log(f"  Guardian scenarios: +{total_guardian} (total: {len(list(GUARDIAN_DOJO_DIR.glob('*.json')))})")
    _log(f"  Financial scenarios: +{total_financial} (total: {len(list(FINANCIAL_DOJO_DIR.glob('*.json')))})")


if __name__ == "__main__":
    main()
