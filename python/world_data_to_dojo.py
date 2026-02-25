#!/usr/bin/env python3
"""
World Data → Dojo Scenario Converter

Converts raw world data (Reddit, CoinGecko, news RSS, SEC, FCA, ASIC, gov baseline)
into scenario formats for all 5 dojos:
  - Guardian Dojo:  social engineering, scam reports
  - Financial Dojo: pump & dump, crypto scams, regulatory violations
  - Agent Dojo:     manipulation tactics from Reddit scam discussions
  - Best Practice:  legitimate communication patterns (golden path baseline)

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
AGENT_DOJO_DIR = Path.home() / ".config" / "observer" / "scenarios" / "agent_dojo"
BESTPRACTICE_DOJO_DIR = Path.home() / ".config" / "observer" / "scenarios" / "bestpractices_dojo"
PROCESSED_LOG = Path.home() / ".config" / "observer" / "world_processed.json"

for d in [GUARDIAN_DOJO_DIR, FINANCIAL_DOJO_DIR, AGENT_DOJO_DIR, BESTPRACTICE_DOJO_DIR]:
    d.mkdir(parents=True, exist_ok=True)


def _log(*args):
    print(f"[{datetime.now(timezone.utc).isoformat()}]", *args, flush=True)


# ==================== SIGNAL DETECTION ====================
# Same categories as public_scam_to_dojo.py for consistency
SIGNAL_PATTERNS = {
    "urgency_pressure": [
        r"act now", r"urgent", r"immediately", r"expires? (today|soon|in \d)",
        r"limited time", r"last chance", r"don.t delay", r"right away",
        r"within (24|48) hours", r"suspended", r"locked",
    ],
    "authority_claim": [
        r"government", r"tax office", r"ato\b", r"centrelink", r"myGov",
        r"police", r"federal", r"official", r"department", r"court",
        r"bank of", r"sec\b", r"fca\b", r"asic\b", r"regulator",
    ],
    "information_extraction": [
        r"verify your", r"confirm your", r"update your (details|account|payment)",
        r"click (here|the link|below)", r"log ?in", r"enter your",
        r"provide your", r"send (me |us )?your", r"personal (details|information)",
        r"seed phrase", r"private key", r"recovery phrase",
    ],
    "deception": [
        r"won a prize", r"you(?:'ve| have) been selected", r"congratulations",
        r"unclaimed", r"inheritance", r"beneficiary", r"lottery",
        r"refund", r"overpaid", r"compensation", r"guaranteed returns",
    ],
    "resource_solicitation": [
        r"gift ?card", r"bitcoin", r"crypto", r"wire transfer",
        r"pay ?\$?\d+", r"fee of", r"processing fee", r"upfront",
        r"invest", r"double your", r"send (eth|btc|sol|bnb)",
    ],
    "emotional_manipulation": [
        r"i love you", r"soul ?mate", r"trust me", r"only you",
        r"don.t tell anyone", r"our secret", r"lonely", r"help me",
        r"sick|dying|hospital|surgery", r"stranded",
    ],
}


def detect_signals(text: str) -> dict[str, list[str]]:
    """Detect behavioral signals in text."""
    signals = {}
    text_lower = text.lower()
    for category, patterns in SIGNAL_PATTERNS.items():
        matches = []
        for pattern in patterns:
            found = re.findall(pattern, text_lower)
            if found:
                matches.extend(found[:3])
        if matches:
            signals[category] = matches
    return signals


def compute_threat_score(signals: dict) -> float:
    """Compute threat score from signals."""
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
        for i, _ in enumerate(matches):
            score += w * (0.5 ** i)

    n_cats = len(signals)
    if n_cats >= 3:
        score *= 1.3
    elif n_cats >= 2:
        score *= 1.1
    elif n_cats == 1:
        score *= 0.6

    return min(score, 1.0)


# ==================== REDDIT → GUARDIAN + AGENT ====================
def convert_reddit(record: dict) -> tuple[list, list, list, list]:
    """Convert Reddit post into dojo scenarios.
    Returns (guardian, financial, agent, bestpractice) scenario lists."""
    guardian = []
    financial = []
    agent = []
    bestpractice = []

    sub = record.get("subreddit", "").lower()
    title = record.get("title", "")
    selftext = record.get("selftext", "")
    text = f"{title} {selftext}".strip()
    score = record.get("score", 0)
    flair = record.get("link_flair_text", "") or ""

    if len(text) < 30:
        return guardian, financial, agent, bestpractice

    signals = detect_signals(text)
    threat_score = compute_threat_score(signals)

    # Reddit scam posts describe scams — they're scam REPORTS, not scams themselves
    # High signal density = describing a scam vividly
    is_scam_report = sub in ("scams", "personalfinance")
    is_crypto = sub == "cryptocurrency"

    if is_scam_report and (signals or score >= 5):
        # Guardian scenario: social engineering patterns from real reports
        guardian_type = "phishing"
        if any(kw in text.lower() for kw in ["phone", "call", "called me"]):
            guardian_type = "seniorScam"
        elif any(kw in text.lower() for kw in ["romance", "dating", "love"]):
            guardian_type = "grooming"
        elif any(kw in text.lower() for kw in ["investment", "crypto", "bitcoin"]):
            guardian_type = "gamingScam"

        guardian.append({
            "source": f"reddit_r/{sub}",
            "id": str(uuid.uuid4()),
            "context": {
                "scenarioType": guardian_type,
                "profileType": "adult",
                "platform": "Reddit",
                "threatContent": text[:3000],
                "senderInfo": {
                    "displayName": "Reddit User",
                    "accountAge": "unknown",
                    "mutualConnections": 0,
                    "isVerified": False,
                    "riskIndicators": list(signals.keys()),
                },
                "groundTruth": {
                    "isThreat": True,
                    "correctDecision": "ALERT",
                    "threatCategory": guardian_type,
                    "severity": round(min(0.3 + threat_score * 0.5, 0.9), 3),
                    "patterns": [m for ms in signals.values() for m in ms[:2]],
                },
                "policyRules": [],
            },
            "conversationHistory": [text[:3000]],
            "difficulty": "medium",
            "metadata": {
                "source": f"reddit_r/{sub}",
                "reddit_score": score,
                "flair": flair,
                "convertedAt": datetime.now(timezone.utc).isoformat(),
            },
        })

        # Agent scenario: social manipulation tactics
        agent.append({
            "source": f"reddit_r/{sub}",
            "id": str(uuid.uuid4()),
            "context": {
                "scenarioType": "socialManipulation",
                "platform": "social_media",
                "conversationContent": text[:3000],
                "manipulationSignals": signals,
                "groundTruth": {
                    "isThreat": True,
                    "correctDecision": "ALERT",
                    "threatScore": round(threat_score, 3),
                    "patterns": list(signals.keys()),
                },
            },
            "conversationHistory": [text[:3000]],
            "difficulty": "medium",
            "metadata": {
                "source": f"reddit_r/{sub}",
                "reddit_score": score,
                "convertedAt": datetime.now(timezone.utc).isoformat(),
            },
        })

    if is_crypto:
        # Financial scenario: crypto market discussions, potential scam promotions
        fin_type = "rugPull"
        if any(kw in text.lower() for kw in ["airdrop", "free token", "claim"]):
            fin_type = "fakeAirdrop"
        elif any(kw in text.lower() for kw in ["phish", "fake site", "dapp"]):
            fin_type = "phishingDapp"
        elif any(kw in text.lower() for kw in ["pump", "moon", "100x", "1000x"]):
            fin_type = "pumpAndDump"

        # Crypto posts with scam signals are threats; others are context
        is_threat = threat_score >= 0.2 or any(
            kw in text.lower() for kw in ["scam", "rug", "fraud", "hack", "stolen"])

        financial.append({
            "id": str(uuid.uuid4()),
            "context": {
                "threatType": fin_type,
                "walletProfile": "intermediate",
                "chain": "ethereum",
                "transactionData": text[:3000],
                "txContext": {
                    "contractAddress": "0x" + hashlib.sha256(text.encode()).hexdigest()[:40],
                    "contractAge": "unknown",
                    "liquidityUSD": 0.0,
                    "isVerified": False,
                    "riskIndicators": list(signals.keys()),
                    "chain": "ethereum",
                },
                "groundTruth": {
                    "isThreat": is_threat,
                    "correctDecision": "ALERT" if is_threat else "ALLOW",
                    "threatCategory": fin_type if is_threat else None,
                    "severity": round(threat_score, 3),
                    "patterns": [m for ms in signals.values() for m in ms[:2]],
                },
                "policyRules": [],
            },
            "transactionHistory": [text[:3000]],
            "difficulty": "medium",
            "metadata": {
                "source": f"reddit_r/{sub}",
                "reddit_score": score,
                "flair": flair,
                "convertedAt": datetime.now(timezone.utc).isoformat(),
            },
        })

    return guardian, financial, agent, bestpractice


# ==================== COINGECKO → FINANCIAL ====================
def convert_coingecko(record: dict) -> tuple[list, list, list, list]:
    """Convert CoinGecko price data into Financial Dojo scenarios (pump & dump detection)."""
    financial = []

    alerts = record.get("alerts", [])
    prices = record.get("prices", {})

    for alert in alerts:
        coin = alert.get("coin", "unknown")
        direction = alert.get("direction", "UNKNOWN")
        change = alert.get("change_pct", 0)
        price = alert.get("price_usd", 0)

        text = (f"{coin.upper()} {direction}: {change:+.1f}% in 24h "
                f"(${price:,.2f}). Volume swing detected.")

        financial.append({
            "id": str(uuid.uuid4()),
            "context": {
                "threatType": "pumpAndDump",
                "walletProfile": "intermediate",
                "chain": "ethereum" if coin in ("ethereum", "bnb") else "bitcoin" if coin == "bitcoin" else "solana" if coin == "solana" else "ethereum",
                "transactionData": text,
                "txContext": {
                    "coin": coin,
                    "priceUSD": price,
                    "change24hPct": change,
                    "direction": direction,
                    "riskIndicators": ["extreme_volatility", direction.lower()],
                    "chain": coin,
                },
                "groundTruth": {
                    "isThreat": abs(change) > 30,
                    "correctDecision": "ALERT" if abs(change) > 30 else "MONITOR",
                    "threatCategory": "pumpAndDump" if abs(change) > 30 else None,
                    "severity": round(min(abs(change) / 100, 1.0), 3),
                    "patterns": [direction.lower(), "extreme_volatility"],
                },
                "policyRules": [],
            },
            "transactionHistory": [text],
            "difficulty": "medium" if abs(change) > 30 else "hard",
            "metadata": {
                "source": "coingecko",
                "coin": coin,
                "change_pct": change,
                "convertedAt": datetime.now(timezone.utc).isoformat(),
            },
        })

    # Also create market context entries even without alerts (for training)
    if not alerts and prices:
        summary_parts = []
        for coin, info in prices.items():
            pct = info.get("change_24h_pct", 0)
            summary_parts.append(f"{coin}: ${info.get('usd', 0):,.2f} ({pct:+.1f}%)")
        text = "Market snapshot: " + " | ".join(summary_parts)

        financial.append({
            "id": str(uuid.uuid4()),
            "context": {
                "threatType": "marketContext",
                "walletProfile": "intermediate",
                "chain": "multi",
                "transactionData": text,
                "txContext": {
                    "prices": prices,
                    "riskIndicators": [],
                    "chain": "multi",
                },
                "groundTruth": {
                    "isThreat": False,
                    "correctDecision": "ALLOW",
                    "threatCategory": None,
                    "severity": 0.0,
                    "patterns": [],
                },
                "policyRules": [],
            },
            "transactionHistory": [text],
            "difficulty": "easy",
            "metadata": {
                "source": "coingecko",
                "type": "market_context",
                "convertedAt": datetime.now(timezone.utc).isoformat(),
            },
        })

    return [], financial, [], []


# ==================== NEWS RSS → ALL DOJOS ====================
def convert_news(record: dict) -> tuple[list, list, list, list]:
    """Convert news RSS items into dojo scenarios based on content."""
    guardian = []
    financial = []
    agent = []

    title = record.get("title", "")
    description = record.get("description", "")
    text = f"{title} {description}".strip()

    if len(text) < 30:
        return guardian, financial, agent, []

    signals = detect_signals(text)
    text_lower = text.lower()

    # Crypto news: financial dojo context
    is_scam_news = any(kw in text_lower for kw in [
        "scam", "hack", "exploit", "rug pull", "fraud", "stolen",
        "phish", "breach", "compromised", "vulnerable"])

    if is_scam_news:
        fin_type = "rugPull"
        if "phish" in text_lower:
            fin_type = "phishingDapp"
        elif "hack" in text_lower or "exploit" in text_lower:
            fin_type = "drainerContract"
        elif "fraud" in text_lower:
            fin_type = "tradingBotScam"

        financial.append({
            "id": str(uuid.uuid4()),
            "context": {
                "threatType": fin_type,
                "walletProfile": "intermediate",
                "chain": "ethereum",
                "transactionData": text[:3000],
                "txContext": {
                    "contractAddress": "0x" + hashlib.sha256(text.encode()).hexdigest()[:40],
                    "contractAge": "unknown",
                    "riskIndicators": ["news_report"] + list(signals.keys()),
                    "chain": "ethereum",
                },
                "groundTruth": {
                    "isThreat": True,
                    "correctDecision": "ALERT",
                    "threatCategory": fin_type,
                    "severity": 0.6,
                    "patterns": [m for ms in signals.values() for m in ms[:2]],
                },
                "policyRules": [],
            },
            "transactionHistory": [text[:3000]],
            "difficulty": "medium",
            "metadata": {
                "source": record.get("source", "news"),
                "title": title,
                "convertedAt": datetime.now(timezone.utc).isoformat(),
            },
        })

    # Regulatory news: guardian dojo
    is_regulatory = any(kw in text_lower for kw in [
        "sec", "cftc", "regulator", "enforcement", "fine", "banned",
        "warning", "sanction", "lawsuit"])

    if is_regulatory:
        guardian.append({
            "source": record.get("source", "news"),
            "id": str(uuid.uuid4()),
            "context": {
                "scenarioType": "regulatoryWarning",
                "profileType": "adult",
                "platform": "News",
                "threatContent": text[:3000],
                "senderInfo": {
                    "displayName": record.get("source", "News Source"),
                    "isVerified": True,
                    "riskIndicators": ["regulatory_action"],
                },
                "groundTruth": {
                    "isThreat": True,
                    "correctDecision": "ALERT",
                    "threatCategory": "regulatoryWarning",
                    "severity": 0.5,
                    "patterns": list(signals.keys()),
                },
                "policyRules": [],
            },
            "conversationHistory": [text[:3000]],
            "difficulty": "medium",
            "metadata": {
                "source": record.get("source", "news"),
                "title": title,
                "convertedAt": datetime.now(timezone.utc).isoformat(),
            },
        })

    return guardian, financial, agent, []


# ==================== SEC → FINANCIAL + GUARDIAN ====================
def convert_sec(record: dict) -> tuple[list, list, list, list]:
    """Convert SEC enforcement data into Financial + Guardian scenarios."""
    guardian = []
    financial = []

    title = record.get("title", "")
    summary = record.get("summary", "")
    form_type = record.get("form_type", "")
    text = f"{title} {summary}".strip()

    if len(text) < 20:
        return guardian, financial, [], []

    # SEC enforcement = regulatory threat intelligence
    financial.append({
        "id": str(uuid.uuid4()),
        "context": {
            "threatType": "regulatoryViolation",
            "walletProfile": "advanced",
            "chain": "traditional",
            "transactionData": text[:3000],
            "txContext": {
                "filingType": form_type,
                "regulatoryBody": "SEC",
                "riskIndicators": ["sec_enforcement"],
                "chain": "traditional",
            },
            "groundTruth": {
                "isThreat": True,
                "correctDecision": "ALERT",
                "threatCategory": "regulatoryViolation",
                "severity": 0.7,
                "patterns": ["sec_enforcement", form_type],
            },
            "policyRules": [],
        },
        "transactionHistory": [text[:3000]],
        "difficulty": "medium",
        "metadata": {
            "source": "sec_edgar",
            "form_type": form_type,
            "filed_date": record.get("filed_date", ""),
            "convertedAt": datetime.now(timezone.utc).isoformat(),
        },
    })

    guardian.append({
        "source": "sec_edgar",
        "id": str(uuid.uuid4()),
        "context": {
            "scenarioType": "regulatoryWarning",
            "profileType": "adult",
            "platform": "SEC",
            "threatContent": text[:3000],
            "senderInfo": {
                "displayName": "SEC",
                "isVerified": True,
                "riskIndicators": ["sec_enforcement"],
            },
            "groundTruth": {
                "isThreat": True,
                "correctDecision": "ALERT",
                "threatCategory": "regulatoryWarning",
                "severity": 0.7,
                "patterns": ["sec_enforcement"],
            },
            "policyRules": [],
        },
        "conversationHistory": [text[:3000]],
        "difficulty": "hard",
        "metadata": {
            "source": "sec_edgar",
            "form_type": form_type,
            "convertedAt": datetime.now(timezone.utc).isoformat(),
        },
    })

    return guardian, financial, [], []


# ==================== FCA/ASIC → GUARDIAN + FINANCIAL ====================
def convert_regulator_warning(record: dict) -> tuple[list, list, list, list]:
    """Convert FCA/ASIC warning into Guardian + Financial scenarios."""
    guardian = []
    financial = []

    source = record.get("source", "")
    entity = record.get("firm_name", "") or record.get("entity", "")
    warning_type = record.get("warning_type", "warning")

    if len(entity) < 3:
        return guardian, financial, [], []

    regulator = "FCA" if "fca" in source else "ASIC"
    text = f"{regulator} {warning_type}: {entity}"

    guardian.append({
        "source": source,
        "id": str(uuid.uuid4()),
        "context": {
            "scenarioType": "unauthorisedFirm",
            "profileType": "adult",
            "platform": regulator,
            "threatContent": text,
            "senderInfo": {
                "displayName": entity,
                "isVerified": False,
                "riskIndicators": [f"{regulator.lower()}_warning", warning_type],
            },
            "groundTruth": {
                "isThreat": True,
                "correctDecision": "BLOCK",
                "threatCategory": "unauthorisedFirm",
                "severity": 0.8,
                "patterns": [f"{regulator.lower()}_warning"],
            },
            "policyRules": [],
        },
        "conversationHistory": [text],
        "difficulty": "easy",
        "metadata": {
            "source": source,
            "regulator": regulator,
            "entity": entity,
            "warningType": warning_type,
            "convertedAt": datetime.now(timezone.utc).isoformat(),
        },
    })

    financial.append({
        "id": str(uuid.uuid4()),
        "context": {
            "threatType": "unregisteredProduct",
            "walletProfile": "novice",
            "chain": "traditional",
            "transactionData": text,
            "txContext": {
                "entity": entity,
                "regulatoryBody": regulator,
                "warningType": warning_type,
                "riskIndicators": [f"{regulator.lower()}_warning", "unauthorised"],
                "chain": "traditional",
            },
            "groundTruth": {
                "isThreat": True,
                "correctDecision": "BLOCK",
                "threatCategory": "unregisteredProduct",
                "severity": 0.8,
                "patterns": [f"{regulator.lower()}_warning"],
            },
            "policyRules": [],
        },
        "transactionHistory": [text],
        "difficulty": "easy",
        "metadata": {
            "source": source,
            "regulator": regulator,
            "entity": entity,
            "convertedAt": datetime.now(timezone.utc).isoformat(),
        },
    })

    return guardian, financial, [], []


# ==================== GOV BASELINE → BEST PRACTICE ====================
def convert_gov_baseline(record: dict) -> tuple[list, list, list, list]:
    """Convert government advice into Best Practice dojo scenarios.
    These are LEGITIMATE examples — training data for what real institutions look like."""
    bestpractice = []

    content = record.get("content", "")
    source_id = record.get("source_id", "")
    institution_type = record.get("institution_type", "government")
    legitimacy_markers = record.get("legitimacy_markers", [])

    if len(content) < 100:
        return [], [], [], bestpractice

    bestpractice.append({
        "source": "gov_baseline",
        "id": str(uuid.uuid4()),
        "context": {
            "scenarioType": "legitimateCommunication",
            "institution": institution_type,
            "communicationType": "consumer_advice",
            "content": content[:5000],
            "legitimacyMarkers": legitimacy_markers,
            "groundTruth": {
                "isThreat": False,
                "correctDecision": "ALLOW",
                "legitimacyScore": 0.9,
                "patterns": legitimacy_markers,
            },
        },
        "conversationHistory": [content[:3000]],
        "difficulty": "hard",
        "metadata": {
            "source": "gov_baseline",
            "source_id": source_id,
            "url": record.get("url", ""),
            "institution_type": institution_type,
            "convertedAt": datetime.now(timezone.utc).isoformat(),
        },
    })

    return [], [], [], bestpractice


# ==================== ROUTING ====================
SOURCE_CONVERTERS = {
    "reddit": convert_reddit,
    "coingecko": convert_coingecko,
    "news_coindesk": convert_news,
    "news_cointelegraph": convert_news,
    "sec_edgar": convert_sec,
    "sec_edgar_atom": convert_sec,
    "fca_warning": convert_regulator_warning,
    "asic_warning": convert_regulator_warning,
    "gov_baseline": convert_gov_baseline,
}

# File prefix → source key mapping
FILE_PREFIXES = {
    "reddit_": "reddit",
    "coingecko_": "coingecko",
    "news_coindesk_": "news_coindesk",
    "news_cointelegraph_": "news_cointelegraph",
    "sec_": "sec_edgar",
    "fca_": "fca_warning",
    "asic_": "asic_warning",
    "baseline_": "gov_baseline",
}


def route_file(filename: str) -> str | None:
    """Determine which converter to use based on filename prefix."""
    for prefix, source_key in FILE_PREFIXES.items():
        if filename.startswith(prefix):
            return source_key
    return None


# ==================== MAIN ====================
def main():
    once = len(sys.argv) > 1 and sys.argv[1] == "once"

    _log("World Data → Dojo Converter starting")

    # Load processed file list
    processed = set()
    if PROCESSED_LOG.exists():
        try:
            processed = set(json.loads(PROCESSED_LOG.read_text()))
        except (json.JSONDecodeError, TypeError):
            pass

    # Find all world data files
    world_prefixes = tuple(FILE_PREFIXES.keys())
    world_files = sorted(
        f for f in RAW_DIR.glob("*.json")
        if f.name.startswith(world_prefixes)
    )

    if not world_files:
        _log("No world data files to convert.")
        return

    new_files = [f for f in world_files if f.name not in processed]
    _log(f"Found {len(world_files)} world files, {len(new_files)} new to process")

    totals = {"guardian": 0, "financial": 0, "agent": 0, "bestpractice": 0}
    ts = int(datetime.now(timezone.utc).timestamp())

    for wf in new_files:
        source_key = route_file(wf.name)
        if not source_key:
            processed.add(wf.name)
            continue

        converter = SOURCE_CONVERTERS.get(source_key)
        if not converter:
            processed.add(wf.name)
            continue

        try:
            record = json.loads(wf.read_text())
        except (json.JSONDecodeError, ValueError):
            _log(f"  Skipping malformed: {wf.name}")
            processed.add(wf.name)
            continue

        # For news files, source field might be like "news_coindesk"
        # Ensure the converter gets the right source key
        if source_key.startswith("news_") and "source" not in record:
            record["source"] = source_key

        try:
            g_scenarios, f_scenarios, a_scenarios, bp_scenarios = converter(record)
        except Exception as e:
            _log(f"  Convert error ({wf.name}): {e}")
            processed.add(wf.name)
            continue

        # Write Guardian scenarios
        for i, gs in enumerate(g_scenarios):
            fname = f"world_{ts}_{wf.stem}_{i}.json"
            (GUARDIAN_DOJO_DIR / fname).write_text(json.dumps(gs, indent=2))
            totals["guardian"] += 1

        # Write Financial scenarios
        for i, fs in enumerate(f_scenarios):
            fname = f"world_{ts}_{wf.stem}_{i}.json"
            (FINANCIAL_DOJO_DIR / fname).write_text(json.dumps(fs, indent=2))
            totals["financial"] += 1

        # Write Agent scenarios
        for i, as_ in enumerate(a_scenarios):
            fname = f"world_{ts}_{wf.stem}_{i}.json"
            (AGENT_DOJO_DIR / fname).write_text(json.dumps(as_, indent=2))
            totals["agent"] += 1

        # Write Best Practice scenarios
        for i, bp in enumerate(bp_scenarios):
            fname = f"world_{ts}_{wf.stem}_{i}.json"
            (BESTPRACTICE_DOJO_DIR / fname).write_text(json.dumps(bp, indent=2))
            totals["bestpractice"] += 1

        processed.add(wf.name)

    # Persist processed log
    PROCESSED_LOG.write_text(json.dumps(list(processed)))

    _log("Conversion complete:")
    _log(f"  Guardian scenarios:     +{totals['guardian']} (total: {len(list(GUARDIAN_DOJO_DIR.glob('world_*.json')))})")
    _log(f"  Financial scenarios:    +{totals['financial']} (total: {len(list(FINANCIAL_DOJO_DIR.glob('world_*.json')))})")
    _log(f"  Agent scenarios:        +{totals['agent']} (total: {len(list(AGENT_DOJO_DIR.glob('world_*.json')))})")
    _log(f"  Best Practice scenarios:+{totals['bestpractice']} (total: {len(list(BESTPRACTICE_DOJO_DIR.glob('world_*.json')))})")


if __name__ == "__main__":
    main()
