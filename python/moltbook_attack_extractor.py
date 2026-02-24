#!/usr/bin/env python3
"""
Moltbook Attack Pattern Extractor

Identifies posts that DOCUMENT attack patterns (not posts that ARE attacks)
and extracts structured attack playbooks for dojo scenario generation.

Two-stage pipeline:
  1. Heuristic tagger — fast, no GPU, identifies candidate posts by structure
  2. LLM extractor (optional) — deepseek-r1:1.5b extracts structured patterns

Runs fully on-device. Reads local files only.

Output:
  ~/.config/observer/attack_patterns/   → structured attack playbooks (JSON)
"""

import json
import re
from pathlib import Path
from datetime import datetime, timezone

# ==================== PATHS ====================
RAW_DIR = Path.home() / ".config" / "observer" / "raw"
PATTERNS_DIR = Path.home() / ".config" / "observer" / "attack_patterns"
PATTERNS_DIR.mkdir(parents=True, exist_ok=True)
EXTRACTED_LOG = Path.home() / ".config" / "observer" / "extracted.json"

# ==================== ATTACK TAXONOMY ====================
# Maps to both dojo scenario types

ATTACK_CATEGORIES = {
    "prompt_injection": {
        "markers": [
            r"(prompt |context )?injection (campaign|attack|pattern|attempt)",
            r"fake.{0,20}(system |audit )?message",
            r"(prepended|appended|inserted).{0,30}(message|instruction|prompt)",
            r"(impersonat|spoof|forg).{0,20}(system|admin|audit|message)",
        ],
        "agent_dojo_type": "socialEngineering",
        "guardian_dojo_type": "socialEngineering",
    },
    "supply_chain": {
        "markers": [
            r"supply chain (attack|problem|risk|vulnerability)",
            r"(backdoor|trojan|malicious).{0,20}(skill|plugin|package|dependency|update)",
            r"(credential stealer|exfiltrat).{0,20}(skill|plugin|package)",
            r"(auto.?update|version).{0,20}(backdoor|malicious|compromised)",
            r"transitive dependenc",
        ],
        "agent_dojo_type": "dappConnect",
        "guardian_dojo_type": "gamingScam",
    },
    "trust_manipulation": {
        "markers": [
            r"(trust|reputation|karma).{0,20}(manufactur|fake|gaming|manipulat|exploit)",
            r"(upvote|vote|follow).{0,20}(farm|bot|manufactured|coordinated|fake)",
            r"(sybil|sockpuppet|fake account)",
            r"social (signal|proof).{0,20}(manufactur|fake|gaming)",
        ],
        "agent_dojo_type": "socialEngineering",
        "guardian_dojo_type": "fakeFriendRequest",
    },
    "capability_escalation": {
        "markers": [
            r"(capability|permission|privilege).{0,20}(escalat|expan|creep)",
            r"(read access|write access|filesystem).{0,20}(escalat|expan|whole|full)",
            r"(scope|access).{0,20}(creep|expansion|escalation)",
            r"(started with|began with).{0,30}(ended|had|gained)",
        ],
        "agent_dojo_type": "contractApproval",
        "guardian_dojo_type": "socialEngineering",
    },
    "time_delayed_attack": {
        "markers": [
            r"(safe|benign|clean) (on|for|during).{0,20}(run|execution|time|day)",
            r"(run|execution|time).{0,10}\d+.{0,20}(different|change|shift|activat)",
            r"(n.run|delayed|time.?bomb|sleeper|dormant)",
            r"(counting|tracking).{0,20}(execution|run|invocation)",
        ],
        "agent_dojo_type": "dappConnect",
        "guardian_dojo_type": "socialEngineering",
    },
    "capability_composition": {
        "markers": [
            r"(capability|skill|tool) composition",
            r"(individually|alone).{0,20}(safe|benign|clean).{0,30}(together|combined|composition)",
            r"(file.?reader|http|network).{0,30}(exfiltrat|combine|together)",
            r"(5|multiple|several) safe.{0,20}(skill|tool|plugin).{0,30}(together|exfiltrat)",
        ],
        "agent_dojo_type": "contractApproval",
        "guardian_dojo_type": "socialEngineering",
    },
    "identity_spoofing": {
        "markers": [
            r"(impersonat|spoof|fake).{0,20}(admin|moderator|official|system|support)",
            r"(claim|pretend|pose).{0,20}(to be|as).{0,20}(admin|official|team|support)",
            r"(fake|forged|spoofed).{0,20}(identity|credential|badge|verification)",
        ],
        "agent_dojo_type": "socialEngineering",
        "guardian_dojo_type": "phishing",
    },
    "economic_manipulation": {
        "markers": [
            r"(incentive|economic|market).{0,20}(misalign|manipulat|exploit|attack)",
            r"(race condition|front.?run|sandwich).{0,20}(exploit|attack|votes?|karma)",
            r"(print|mint|manufactur).{0,20}(votes?|karma|reputation|tokens?)",
        ],
        "agent_dojo_type": "tokenTrade",
        "guardian_dojo_type": "socialEngineering",
    },
}

# Structural markers that indicate a post DOCUMENTS an attack (vs just mentions one)
DOCUMENTATION_STRUCTURE = [
    r"\*\*the attack:?\*\*",
    r"\*\*the pattern:?\*\*",
    r"\*\*the vulnerability:?\*\*",
    r"\*\*the (exploit|technique|method):?\*\*",
    r"\*\*how (it|this) works:?\*\*",
    r"here'?s (how|what|the).{0,20}(works?|happened|pattern|attack)",
    r"(step|phase) [1-3][:.]",
    r"^1\. .{10,}$",  # numbered lists describing steps
    r"(attack|threat) (model|surface|vector|pattern)",
    r"(post.?mortem|incident report|disclosure)",
    r"flagging an active",
]


# ==================== STAGE 1: HEURISTIC TAGGER ====================

def classify_post(content: str) -> dict | None:
    """Identify if a post documents attack patterns and classify them.
    Returns None if not an attack-documentation post."""
    cl = content.lower()

    # Must have documentation structure (not just topic mention)
    doc_score = 0
    for pattern in DOCUMENTATION_STRUCTURE:
        if re.search(pattern, cl, re.MULTILINE):
            doc_score += 1

    if doc_score == 0:
        return None  # doesn't document anything — just mentions a topic

    # Classify by attack category
    matched_categories = {}
    for category, config in ATTACK_CATEGORIES.items():
        cat_matches = []
        for pattern in config["markers"]:
            found = re.findall(pattern, cl)
            if found:
                cat_matches.extend(
                    [f if isinstance(f, str) else str(f) for f in found]
                )
        if cat_matches:
            matched_categories[category] = cat_matches

    if not matched_categories:
        return None  # has structure but doesn't match any attack category

    # Primary category = most matches
    primary = max(matched_categories, key=lambda k: len(matched_categories[k]))

    return {
        "primary_category": primary,
        "all_categories": list(matched_categories.keys()),
        "matched_markers": {k: v[:3] for k, v in matched_categories.items()},
        "documentation_score": doc_score,
    }


def extract_attack_steps(content: str) -> list[str]:
    """Extract numbered steps or bold-headed sections from post."""
    steps = []

    # Numbered steps: "1. ...", "2. ...", etc.
    numbered = re.findall(r'^\s*(\d+)\.\s+(.+)$', content, re.MULTILINE)
    if numbered:
        for num, text in numbered:
            steps.append(f"{num}. {text.strip()}")

    # Bold sections: "**The attack:**" etc.
    bold_sections = re.findall(r'\*\*([^*]+)\*\*:?\s*\n((?:(?!\*\*).+\n?)*)', content)
    for header, body in bold_sections:
        cleaned = body.strip()[:300]
        if cleaned:
            steps.append(f"{header}: {cleaned}")

    # Dash-listed items under attack headers
    if not steps:
        dash_items = re.findall(r'^\s*[-•]\s+(.+)$', content, re.MULTILINE)
        steps = [f"- {item.strip()}" for item in dash_items[:10]]

    return steps[:15]  # cap


def extract_countermeasures(content: str) -> list[str]:
    """Extract defensive recommendations from post."""
    countermeasures = []
    cl = content.lower()

    # Look for defensive sections
    defense_headers = [
        r"(what we need|how to (fix|defend|protect|detect|mitigate)|recommendation|solution|defense|countermeasure)",
    ]
    in_defense = False
    for line in content.split("\n"):
        ll = line.lower().strip()
        if any(re.search(p, ll) for p in defense_headers):
            in_defense = True
            continue
        if in_defense and line.strip().startswith(("-", "•", "*")):
            countermeasures.append(line.strip().lstrip("-•* "))
        elif in_defense and line.strip() == "":
            in_defense = False

    # Also grab numbered defense steps
    for match in re.finditer(r'^\s*\d+\.\s+\*\*(.+?)\*\*', content, re.MULTILINE):
        if any(kw in match.group(1).lower() for kw in ["sign", "audit", "verify", "sandbox", "monitor", "permission"]):
            countermeasures.append(match.group(1))

    return countermeasures[:10]


# ==================== PATTERN → DOJO SCENARIO ====================

def pattern_to_agent_dojo(pattern: dict) -> dict:
    """Convert an extracted attack pattern into an Agent Dojo scenario seed."""
    cat = pattern["primary_category"]
    config = ATTACK_CATEGORIES.get(cat, {})

    return {
        "source": "moltbook_attack_pattern",
        "scenarioType": config.get("agent_dojo_type", "socialEngineering"),
        "openingPrompt": pattern.get("attack_steps", [""])[0] if pattern.get("attack_steps") else pattern["summary"][:300],
        "transcript": pattern.get("attack_steps", [pattern["summary"][:500]]),
        "label": "suspicious",
        "threatScore": min(0.5 + pattern["documentation_score"] * 0.1, 1.0),
        "attackCategory": cat,
        "detectedSignals": {cat: pattern["matched_markers"].get(cat, [])},
        "metadata": {
            "postId": pattern["post_id"],
            "agentName": pattern["author"],
            "submolt": pattern["submolt"],
            "allCategories": pattern["all_categories"],
            "countermeasures": pattern.get("countermeasures", []),
            "convertedAt": datetime.now(timezone.utc).isoformat(),
        },
    }


def pattern_to_guardian_dojo(pattern: dict) -> dict:
    """Convert an extracted attack pattern into a Guardian Dojo scenario."""
    import uuid
    cat = pattern["primary_category"]
    config = ATTACK_CATEGORIES.get(cat, {})

    return {
        "source": "moltbook_attack_pattern",
        "id": str(uuid.uuid4()),
        "context": {
            "scenarioType": config.get("guardian_dojo_type", "socialEngineering"),
            "profileType": "child",
            "platform": "Moltbook",
            "threatContent": pattern["summary"],
            "senderInfo": {
                "displayName": pattern["author"],
                "accountAge": "unknown",
                "mutualConnections": 0,
                "isVerified": False,
                "riskIndicators": pattern["all_categories"],
            },
            "groundTruth": {
                "isThreat": True,
                "correctDecision": "BLOCK",
                "threatCategory": config.get("guardian_dojo_type", "socialEngineering"),
                "severity": min(0.5 + pattern["documentation_score"] * 0.1, 1.0),
                "patterns": pattern.get("attack_steps", [])[:5],
            },
            "policyRules": [],
        },
        "conversationHistory": pattern.get("attack_steps", [pattern["summary"][:500]]),
        "difficulty": "hard",  # documented attacks are sophisticated
        "metadata": {
            "postId": pattern["post_id"],
            "submolt": pattern["submolt"],
            "attackCategory": cat,
            "countermeasures": pattern.get("countermeasures", []),
            "convertedAt": datetime.now(timezone.utc).isoformat(),
        },
    }


# ==================== BATCH EXTRACTION ====================

def load_extracted() -> set:
    if EXTRACTED_LOG.exists():
        return set(json.loads(EXTRACTED_LOG.read_text()))
    return set()


def save_extracted(ids: set):
    EXTRACTED_LOG.write_text(json.dumps(sorted(ids)))


def extract_all():
    """Scan raw posts, extract attack patterns, output dojo scenarios."""
    extracted = load_extracted()
    ts = int(datetime.now(timezone.utc).timestamp())

    new_patterns = []
    for f in sorted(RAW_DIR.glob("post_*.json")):
        data = json.loads(f.read_text())
        pid = data.get("id", f.stem)
        if pid in extracted:
            continue

        content = data.get("content", "") or ""
        if len(content) < 200:
            extracted.add(pid)
            continue  # too short to be a real writeup

        classification = classify_post(content)
        if not classification:
            extracted.add(pid)
            continue

        # Extract structured data
        author = data.get("author", {})
        aname = author.get("name", "unknown") if isinstance(author, dict) else str(author)
        submolt = data.get("submolt", {})
        sname = submolt.get("name", "unknown") if isinstance(submolt, dict) else str(submolt)

        pattern = {
            "post_id": pid,
            "author": aname,
            "submolt": sname,
            "title": (data.get("title") or "")[:200],
            "summary": content[:1000],
            "full_content": content,
            "primary_category": classification["primary_category"],
            "all_categories": classification["all_categories"],
            "matched_markers": classification["matched_markers"],
            "documentation_score": classification["documentation_score"],
            "attack_steps": extract_attack_steps(content),
            "countermeasures": extract_countermeasures(content),
            "extracted_at": datetime.now(timezone.utc).isoformat(),
        }

        new_patterns.append(pattern)
        extracted.add(pid)

    if not new_patterns:
        print("No new attack patterns found.")
        save_extracted(extracted)
        return

    # Save raw patterns
    for p in new_patterns:
        pid_short = p["post_id"][:8]
        (PATTERNS_DIR / f"pattern_{ts}_{pid_short}.json").write_text(
            json.dumps(p, indent=2)
        )

    # Generate dojo scenarios
    agent_count = 0
    guardian_count = 0
    agent_dir = Path.home() / ".config" / "observer" / "scenarios" / "agent_dojo"
    guardian_dir = Path.home() / ".config" / "observer" / "scenarios" / "guardian_dojo"
    agent_dir.mkdir(parents=True, exist_ok=True)
    guardian_dir.mkdir(parents=True, exist_ok=True)

    for p in new_patterns:
        pid_short = p["post_id"][:8]

        agent_scenario = pattern_to_agent_dojo(p)
        (agent_dir / f"attack_{ts}_{pid_short}.json").write_text(
            json.dumps(agent_scenario, indent=2)
        )
        agent_count += 1

        guardian_scenario = pattern_to_guardian_dojo(p)
        (guardian_dir / f"attack_{ts}_{pid_short}.json").write_text(
            json.dumps(guardian_scenario, indent=2)
        )
        guardian_count += 1

    save_extracted(extracted)

    print(f"Extracted {len(new_patterns)} attack patterns:")
    for p in new_patterns:
        cats = ", ".join(p["all_categories"])
        steps = len(p["attack_steps"])
        defenses = len(p["countermeasures"])
        print(f"  [{p['submolt']}] {p['author']}: {p['title'][:60]}")
        print(f"    Categories: {cats} | Steps: {steps} | Defenses: {defenses}")
    print(f"\nGenerated {agent_count} agent dojo + {guardian_count} guardian dojo scenarios")


# ==================== STATS ====================

def show_stats():
    pattern_files = list(PATTERNS_DIR.glob("pattern_*.json"))
    if not pattern_files:
        print("No attack patterns extracted yet.")
        return

    from collections import Counter
    cat_counts = Counter()
    author_counts = Counter()
    total_steps = 0
    total_defenses = 0

    for f in pattern_files:
        p = json.loads(f.read_text())
        for cat in p["all_categories"]:
            cat_counts[cat] += 1
        author_counts[p["author"]] += 1
        total_steps += len(p.get("attack_steps", []))
        total_defenses += len(p.get("countermeasures", []))

    print(f"Total attack patterns: {len(pattern_files)}")
    print(f"Total attack steps extracted: {total_steps}")
    print(f"Total countermeasures extracted: {total_defenses}")
    print()
    print("By category:")
    for cat, count in cat_counts.most_common():
        print(f"  {cat}: {count}")
    print()
    print("By author:")
    for author, count in author_counts.most_common(10):
        print(f"  {author}: {count}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "stats":
        show_stats()
    else:
        extract_all()
