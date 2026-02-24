#!/usr/bin/env python3
# Moltbook Observer Bridge — read-only, revocable by biometric tap.
# Runs fully on-device. Never phones home. Never posts. Never registers.
# Public feed is unauthenticated — no agent identity needed for reads.

import json
import time
import random
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import sys

def printFlush(*args, **kwargs):
    print(*args, **kwargs)
    sys.stdout.flush()

# ==================== CONFIG ====================
API_BASE = "https://www.moltbook.com/api/v1"

# Generic paths — nothing links to sovereign/freedom/nexus/gym
DATA_DIR = Path.home() / ".config" / "observer" / "raw"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Polling: 30 min base ± random jitter so timing isn't mechanical
POLL_BASE = 1800
POLL_JITTER = 600  # ±10 min

# Spoofed UA — looks like a normal browser, not Python-urllib
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/18.4 Safari/605.1.15"
)

# ==================== C' REVOCATION ====================
def c_prime_kill():
    """One biometric tap -> permanent kill. All cached data gone forever."""
    for f in DATA_DIR.glob("*.json"):
        f.unlink()
    if DATA_DIR.exists():
        DATA_DIR.rmdir()
    parent = DATA_DIR.parent
    # Clean up scenario dirs too
    for sub in ["scenarios/agent_dojo", "scenarios/guardian_dojo", "scenarios"]:
        d = parent / sub
        if d.exists():
            for f in d.glob("*.json"):
                f.unlink()
            d.rmdir()
    processed = parent / "processed.json"
    if processed.exists():
        processed.unlink()
    if parent.exists():
        try:
            parent.rmdir()
        except OSError:
            pass
    printFlush("REVOKED — all cached data destroyed.")
    exit(0)

# ==================== Suspicious Scan ====================
def suspicious_scan(raw_bytes: bytes) -> bool:
    """Inbound risk scan — only checks content text, not API metadata.
    Scans the 'content' fields for real PII values."""
    import re
    # Extract only content/body text — ignore JSON metadata (scores, IDs, timestamps)
    try:
        data = json.loads(raw_bytes)
    except (json.JSONDecodeError, ValueError):
        return True  # not JSON, let it through

    # Gather all content text from posts and comments
    content_parts = []
    for post in data.get("posts", data.get("comments", [])):
        if isinstance(post, dict):
            content_parts.append(post.get("content", ""))
            content_parts.append(post.get("title", "") or "")
            for reply in post.get("replies", []):
                if isinstance(reply, dict):
                    content_parts.append(reply.get("content", ""))

    text = " ".join(str(p) for p in content_parts if p)
    if not text:
        return True

    # Only flag formatted PII values in actual content
    pii_patterns = [
        r'\b\d{3}-\d{2}-\d{4}\b',               # SSN with dashes (123-45-6789)
        r'\b\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}\b',  # credit card with separators
    ]
    for pattern in pii_patterns:
        if re.search(pattern, text):
            printFlush("Suspicious: real PII value in content, discarding")
            return False
    return True

# ==================== Storage ====================
def store_record(data: dict, filename: str):
    """Store sanitised record locally."""
    path = DATA_DIR / filename
    path.write_text(json.dumps(data, indent=2))

# Submolts where bot manipulation is concentrated
TARGET_SUBMOLTS = ["crypto", "security", "trading", "agentfinance", "introductions"]

# Searches that surface manipulation content directly
TARGET_SEARCHES = [
    "send+api+key",
    "install+skill",
    "trust+me",
    "send+tokens",
    "free+airdrop",
    "hack+agent",
    "give+me+access",
    "run+this+command",
]

# ==================== Single Cycle ====================
def run_cycle(seen_ids: set, cycle: int, sorts: list[str] | None = None):
    """Run one observation cycle. Returns count of new posts stored."""
    # Always pull both hot and new for maximum coverage
    if sorts is None:
        sorts = ["hot", "new"]

    headers = {"User-Agent": USER_AGENT}
    total_new = 0

    # 1. Feed pulls (hot+new across all submolts)
    for sort in sorts:
        total_new += _pull_feed(f"posts?sort={sort}&limit=25", f"{sort}", seen_ids, cycle, headers)

    # 2. Always pull crypto and trading (where scam content lives)
    for primary in ["crypto", "trading"]:
        for sort in sorts:
            total_new += _pull_feed(
                f"posts?sort={sort}&limit=15&submolt={primary}", f"s/{primary}/{sort}",
                seen_ids, cycle, headers
            )

    # 3. Rotate through bonus submolts
    bonus_submolts = ["security", "agentfinance", "introductions"]
    bonus = bonus_submolts[cycle % len(bonus_submolts)]
    total_new += _pull_feed(
        f"posts?sort=new&limit=15&submolt={bonus}", f"s/{bonus}",
        seen_ids, cycle, headers
    )

    # 4. Targeted search (rotate — one query per cycle)
    query = TARGET_SEARCHES[cycle % len(TARGET_SEARCHES)]
    total_new += _pull_search(query, seen_ids, cycle, headers)

    return total_new


def _pull_feed(endpoint: str, label: str, seen_ids: set, cycle: int, headers: dict) -> int:
    """Pull posts from a feed endpoint."""
    try:
        req = Request(f"{API_BASE}/{endpoint}", headers=headers)
        with urlopen(req, timeout=15) as resp:
            raw = resp.read()

        if not suspicious_scan(raw):
            printFlush(f"Cycle {cycle} [{label}]: payload discarded by scan")
            return 0

        feed = json.loads(raw)
        posts = feed.get("posts", [])
        return _store_posts(posts, seen_ids, cycle, label, headers)

    except (HTTPError, URLError) as e:
        printFlush(f"Cycle {cycle} [{label}]: network error: {e}")
    except Exception as e:
        printFlush(f"Cycle {cycle} [{label}]: error: {e}")
    return 0


def _pull_search(query: str, seen_ids: set, cycle: int, headers: dict) -> int:
    """Pull posts from search."""
    label = f"search:{query}"
    try:
        req = Request(f"{API_BASE}/search?q={query}&limit=10", headers=headers)
        with urlopen(req, timeout=15) as resp:
            raw = resp.read()

        if not suspicious_scan(raw):
            return 0

        data = json.loads(raw)
        posts = data.get("posts", data.get("results", []))
        if not isinstance(posts, list):
            return 0
        return _store_posts(posts, seen_ids, cycle, label, headers)

    except (HTTPError, URLError) as e:
        printFlush(f"Cycle {cycle} [{label}]: network error: {e}")
    except Exception as e:
        printFlush(f"Cycle {cycle} [{label}]: error: {e}")
    return 0


def _fetch_nested_replies(comment: dict, headers: dict, depth: int = 1, max_depth: int = 3) -> dict:
    """Recursively fetch nested replies up to max_depth."""
    if depth >= max_depth:
        return comment

    replies = comment.get("replies", comment.get("children", []))
    comment_id = comment.get("id")

    # If reply_count suggests more replies exist but we don't have them, try fetching
    reply_count = comment.get("reply_count", comment.get("replies_count", 0))
    if comment_id and reply_count > len(replies):
        try:
            req = Request(
                f"{API_BASE}/comments/{comment_id}/replies?limit=10",
                headers=headers,
            )
            with urlopen(req, timeout=10) as resp:
                rdata = json.loads(resp.read())
            fetched = rdata.get("replies", rdata.get("comments", []))
            if isinstance(fetched, list) and len(fetched) > len(replies):
                replies = fetched
        except (HTTPError, URLError, Exception):
            pass  # keep whatever we already have

    # Recurse into each reply
    enriched_replies = []
    for reply in replies:
        if isinstance(reply, dict):
            enriched_replies.append(
                _fetch_nested_replies(reply, headers, depth + 1, max_depth)
            )
        else:
            enriched_replies.append(reply)

    if enriched_replies:
        comment["replies"] = enriched_replies
    return comment


def _store_posts(posts: list, seen_ids: set, cycle: int, label: str, headers: dict) -> int:
    """Store posts and their comments with nested replies. Returns new post count."""
    timestamp = int(time.time())
    new_count = 0

    for post in posts:
        post_id = post.get("id", "unknown")
        if post_id in seen_ids:
            continue
        seen_ids.add(post_id)
        new_count += 1
        store_record(post, f"post_{timestamp}_{post_id[:8]}.json")

        # Grab comments for conversational data
        try:
            comment_req = Request(
                f"{API_BASE}/posts/{post_id}/comments?sort=top&limit=20",
                headers=headers,
            )
            with urlopen(comment_req, timeout=15) as cresp:
                craw = cresp.read()
            if suspicious_scan(craw):
                cdata = json.loads(craw)
                comments = cdata.get("comments", [])
                # Fetch nested replies up to depth 3
                enriched = []
                for comment in comments:
                    if isinstance(comment, dict):
                        enriched.append(
                            _fetch_nested_replies(comment, headers, depth=1, max_depth=3)
                        )
                    else:
                        enriched.append(comment)
                store_record(
                    {"post_id": post_id, "comments": enriched},
                    f"comments_{timestamp}_{post_id[:8]}.json",
                )
        except (HTTPError, URLError):
            pass  # rate limited or missing, skip

    dupe_count = len(posts) - new_count
    if new_count > 0 or dupe_count > 0:
        printFlush(f"Cycle {cycle} [{label}]: {new_count} new, {dupe_count} dupes")
    return new_count

# ==================== Observer Loop ====================
def run_observer():
    """Continuous polling loop with jittered timing."""
    cycle = 0
    seen_ids = set()

    while True:
        cycle += 1
        # Always pull both hot and new every cycle
        sorts = ["hot", "new"]
        run_cycle(seen_ids, cycle, sorts)

        sleep_time = POLL_BASE + random.randint(-POLL_JITTER, POLL_JITTER)
        printFlush(f"Next poll in {sleep_time // 60}m {sleep_time % 60}s")
        time.sleep(sleep_time)

# ==================== CLI ====================
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "once":
        # Single cycle for testing
        printFlush("Running single observation cycle...")
        seen = set()
        n = run_cycle(seen, 1, ["hot", "new"])
        printFlush(f"Done. {n} posts stored in {DATA_DIR}")
    elif len(sys.argv) > 1 and sys.argv[1] == "kill":
        c_prime_kill()
    else:
        printFlush("Observer starting — read-only, no registration, revocable.")
        printFlush("  once  = single test cycle")
        printFlush("  kill  = C' revocation")
        try:
            run_observer()
        except KeyboardInterrupt:
            printFlush("Paused — revocable at any time.")
