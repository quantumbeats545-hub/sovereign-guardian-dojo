#!/usr/bin/env python3
"""
Public Scam Intelligence Bridge — pulls real-world scam data from open sources.

Sources (all public, no auth, no API keys):
  - Scamwatch (Australian ACCC): scam types, examples, statistics
  - PhishTank: verified phishing URLs + metadata
  - OpenPhish: real-time phishing feed (updated every 15 min)
  - URLhaus (abuse.ch): malware/scam hosting URLs

Ghost fetches → Suspicious scans every byte → only sanitised patterns reach the Dojos.
100% on-device. Revocable by single C' tap. The tool never becomes the master.
"""

import json
import re
import sys
import time
import random
import hashlib
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

# ==================== CONFIG ====================
DATA_DIR = Path.home() / ".config" / "observer" / "raw"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Polling: 6 hours base ± 1 hour jitter (these sources update daily, not every 30 min)
POLL_BASE = 21600
POLL_JITTER = 3600

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/18.4 Safari/605.1.15"
)

# ==================== SOURCES ====================
SCAMWATCH_PAGES = [
    ("https://www.scamwatch.gov.au/types-of-scams/text-or-sms-scams", "sms_scams"),
    ("https://www.scamwatch.gov.au/types-of-scams/phone-scams", "phone_scams"),
    ("https://www.scamwatch.gov.au/types-of-scams/email-scams", "email_scams"),
    ("https://www.scamwatch.gov.au/types-of-scams/investment-scams", "investment_scams"),
    ("https://www.scamwatch.gov.au/types-of-scams/buying-or-selling-scams", "buying_scams"),
    ("https://www.scamwatch.gov.au/types-of-scams/romance-scams", "romance_scams"),
]

PHISHTANK_FEED = "http://data.phishtank.com/data/online-valid.csv"
OPENPHISH_FEED = "https://openphish.com/feed.txt"
URLHAUS_FEED = "https://urlhaus.abuse.ch/downloads/csv_recent/"


def _log(*args):
    print(f"[{datetime.now(timezone.utc).isoformat()}]", *args, flush=True)


# ==================== C' REVOCATION ====================
def c_prime_kill():
    """One biometric tap → all cached data destroyed. No recovery."""
    for f in DATA_DIR.glob("scam_*.json"):
        f.unlink()
    _log("REVOKED — all public scam cache destroyed.")
    sys.exit(0)


# ==================== SUSPICIOUS SCAN ====================
def suspicious_scan(text: str) -> str:
    """Strip any real PII before storage. Returns sanitised text."""
    # Remove SSNs, credit card numbers, phone numbers with area codes, email addresses
    text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED-SSN]', text)
    text = re.sub(r'\b\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}\b', '[REDACTED-CC]', text)
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[REDACTED-EMAIL]', text)
    # Remove Australian phone numbers (04xx xxx xxx, +614xx xxx xxx)
    text = re.sub(r'\b(?:\+?61|0)4\d{2}[\s-]?\d{3}[\s-]?\d{3}\b', '[REDACTED-PHONE]', text)
    # Remove any 10+ digit number sequences (potential account numbers)
    text = re.sub(r'\b\d{10,}\b', '[REDACTED-NUM]', text)
    return text


# ==================== HTML PARSING ====================
class ScamPageParser(HTMLParser):
    """Extract text content from Scamwatch HTML pages, stripping tags."""

    def __init__(self):
        super().__init__()
        self._text_parts = []
        self._skip_tags = {"script", "style", "nav", "header", "footer"}
        self._in_skip = 0
        self._in_main = False

    def handle_starttag(self, tag, attrs):
        if tag in self._skip_tags:
            self._in_skip += 1
        attr_dict = dict(attrs)
        if tag == "main" or attr_dict.get("role") == "main":
            self._in_main = True
        if tag in ("article", "section") and "content" in attr_dict.get("class", ""):
            self._in_main = True

    def handle_endtag(self, tag):
        if tag in self._skip_tags:
            self._in_skip = max(0, self._in_skip - 1)
        if tag == "main":
            self._in_main = False

    def handle_data(self, data):
        if self._in_skip == 0:
            stripped = data.strip()
            if stripped:
                self._text_parts.append(stripped)

    def get_text(self) -> str:
        return "\n".join(self._text_parts)


def _extract_scam_examples(text: str) -> list[dict]:
    """Extract individual scam examples from page text.
    Looks for quoted examples, bullet points, and numbered lists."""
    examples = []

    # Quoted examples (often in blockquotes or with quotation marks)
    quoted = re.findall(r'["""](.{20,300}?)["""]', text)
    for q in quoted:
        examples.append({"type": "quoted_example", "text": q.strip()})

    # Bullet-style scam message patterns
    bullets = re.findall(r'(?:^|\n)\s*[•\-\*]\s*(.{20,500})', text)
    for b in bullets:
        if any(kw in b.lower() for kw in ["scam", "fake", "fraud", "phish", "urgent", "click",
                                            "verify", "suspended", "account", "payment", "prize"]):
            examples.append({"type": "bullet_pattern", "text": b.strip()})

    # "Example:" or "For example" blocks
    example_blocks = re.findall(r'(?:example|for instance|such as)[:\s]+(.{20,500})', text, re.IGNORECASE)
    for eb in example_blocks:
        examples.append({"type": "example_block", "text": eb.strip()})

    return examples


# ==================== FETCHERS ====================
def fetch_scamwatch(seen_hashes: set) -> int:
    """Fetch scam type pages from Scamwatch (Australian ACCC). Returns new record count."""
    new_count = 0
    headers = {"User-Agent": USER_AGENT}

    for url, category in SCAMWATCH_PAGES:
        try:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=30) as resp:
                html = resp.read().decode("utf-8", errors="replace")

            parser = ScamPageParser()
            parser.feed(html)
            raw_text = parser.get_text()

            # Suspicious scan — strip PII
            clean_text = suspicious_scan(raw_text)

            # Extract scam examples
            examples = _extract_scam_examples(clean_text)
            if not examples:
                _log(f"  Scamwatch/{category}: no examples found")
                continue

            # Deduplicate by content hash
            content_hash = hashlib.sha256(clean_text[:2000].encode()).hexdigest()[:16]
            if content_hash in seen_hashes:
                continue
            seen_hashes.add(content_hash)

            ts = int(time.time())
            record = {
                "source": "scamwatch",
                "category": category,
                "url": url,
                "examples": examples,
                "full_text": clean_text[:5000],  # Cap at 5KB
                "fetched_at": datetime.now(timezone.utc).isoformat(),
            }

            filename = f"scam_scamwatch_{ts}_{content_hash}.json"
            (DATA_DIR / filename).write_text(json.dumps(record, indent=2))
            new_count += 1
            _log(f"  Scamwatch/{category}: {len(examples)} examples")

        except (HTTPError, URLError, TimeoutError) as e:
            _log(f"  Scamwatch/{category}: fetch failed — {e}")
        except Exception as e:
            _log(f"  Scamwatch/{category}: parse error — {e}")

        # Polite delay between pages
        time.sleep(random.uniform(2, 5))

    return new_count


def fetch_phishtank(seen_hashes: set) -> int:
    """Fetch verified phishing URLs from PhishTank public feed. Returns new record count."""
    headers = {"User-Agent": USER_AGENT}
    try:
        req = Request(PHISHTANK_FEED, headers=headers)
        with urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError) as e:
        _log(f"  PhishTank: fetch failed — {e}")
        return 0

    lines = raw.strip().split("\n")
    if len(lines) < 2:
        _log("  PhishTank: empty feed")
        return 0

    # CSV header: phish_id,url,phish_detail_url,submission_time,verified,verified_time,online,target
    new_count = 0
    entries = []
    for line in lines[1:201]:  # Cap at 200 entries per fetch
        parts = line.split(",")
        if len(parts) < 8:
            continue
        phish_id = parts[0].strip('"')
        url = parts[1].strip('"')
        target = parts[7].strip('"') if len(parts) > 7 else "unknown"
        verified = parts[4].strip('"').lower() == "yes"

        if not verified:
            continue

        content_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
        if content_hash in seen_hashes:
            continue
        seen_hashes.add(content_hash)
        entries.append({
            "phish_id": phish_id,
            "url": suspicious_scan(url),
            "target": target,
            "verified": True,
        })

    if entries:
        ts = int(time.time())
        batch_hash = hashlib.sha256(str(len(entries)).encode()).hexdigest()[:8]
        record = {
            "source": "phishtank",
            "entries": entries,
            "entry_count": len(entries),
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        filename = f"scam_phishtank_{ts}_{batch_hash}.json"
        (DATA_DIR / filename).write_text(json.dumps(record, indent=2))
        new_count = len(entries)
        _log(f"  PhishTank: {new_count} verified phishing URLs")

    return new_count


def fetch_openphish(seen_hashes: set) -> int:
    """Fetch real-time phishing feed from OpenPhish. Returns new record count."""
    headers = {"User-Agent": USER_AGENT}
    try:
        req = Request(OPENPHISH_FEED, headers=headers)
        with urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError) as e:
        _log(f"  OpenPhish: fetch failed — {e}")
        return 0

    urls = [u.strip() for u in raw.strip().split("\n") if u.strip()]
    if not urls:
        _log("  OpenPhish: empty feed")
        return 0

    new_urls = []
    for url in urls[:200]:  # Cap at 200
        content_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
        if content_hash not in seen_hashes:
            seen_hashes.add(content_hash)
            new_urls.append(suspicious_scan(url))

    if new_urls:
        ts = int(time.time())
        batch_hash = hashlib.sha256(str(len(new_urls)).encode()).hexdigest()[:8]
        record = {
            "source": "openphish",
            "urls": new_urls,
            "url_count": len(new_urls),
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        filename = f"scam_openphish_{ts}_{batch_hash}.json"
        (DATA_DIR / filename).write_text(json.dumps(record, indent=2))
        _log(f"  OpenPhish: {len(new_urls)} phishing URLs")

    return len(new_urls)


def fetch_urlhaus(seen_hashes: set) -> int:
    """Fetch recent malware/scam URLs from URLhaus (abuse.ch). Returns new record count."""
    headers = {"User-Agent": USER_AGENT}
    try:
        req = Request(URLHAUS_FEED, headers=headers)
        with urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError) as e:
        _log(f"  URLhaus: fetch failed — {e}")
        return 0

    lines = raw.strip().split("\n")
    entries = []
    for line in lines:
        if line.startswith("#") or not line.strip():
            continue
        # CSV: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
        parts = line.split('","')
        if len(parts) < 7:
            continue
        url = parts[2].strip('"') if len(parts) > 2 else ""
        threat = parts[5].strip('"') if len(parts) > 5 else "unknown"
        tags = parts[6].strip('"') if len(parts) > 6 else ""

        content_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
        if content_hash in seen_hashes:
            continue
        seen_hashes.add(content_hash)
        entries.append({
            "url": suspicious_scan(url),
            "threat": threat,
            "tags": tags,
        })
        if len(entries) >= 200:
            break

    if entries:
        ts = int(time.time())
        batch_hash = hashlib.sha256(str(len(entries)).encode()).hexdigest()[:8]
        record = {
            "source": "urlhaus",
            "entries": entries,
            "entry_count": len(entries),
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        filename = f"scam_urlhaus_{ts}_{batch_hash}.json"
        (DATA_DIR / filename).write_text(json.dumps(record, indent=2))
        _log(f"  URLhaus: {len(entries)} malware/scam URLs")

    return len(entries)


# ==================== SINGLE CYCLE ====================
def run_cycle(seen_hashes: set, cycle: int) -> int:
    """Run one observation cycle across all public sources. Returns total new records."""
    _log(f"=== Public Scam Bridge — Cycle {cycle} ===")
    total = 0

    # Scamwatch: rotate 2 pages per cycle (polite to gov site)
    start_idx = (cycle * 2) % len(SCAMWATCH_PAGES)
    pages_this_cycle = SCAMWATCH_PAGES[start_idx:start_idx + 2]
    if not pages_this_cycle:
        pages_this_cycle = SCAMWATCH_PAGES[:2]

    _log("Fetching Scamwatch...")
    # Temporarily override the global list for this cycle
    original = list(SCAMWATCH_PAGES)
    SCAMWATCH_PAGES.clear()
    SCAMWATCH_PAGES.extend(pages_this_cycle)
    total += fetch_scamwatch(seen_hashes)
    SCAMWATCH_PAGES.clear()
    SCAMWATCH_PAGES.extend(original)

    # PhishTank + OpenPhish: alternate each cycle (both update frequently)
    if cycle % 2 == 0:
        _log("Fetching PhishTank...")
        total += fetch_phishtank(seen_hashes)
    else:
        _log("Fetching OpenPhish...")
        total += fetch_openphish(seen_hashes)

    # URLhaus: every 3rd cycle
    if cycle % 3 == 0:
        _log("Fetching URLhaus...")
        total += fetch_urlhaus(seen_hashes)

    _log(f"Cycle {cycle} complete: {total} new records")
    return total


# ==================== MAIN LOOP ====================
def main():
    if len(sys.argv) > 1 and sys.argv[1] == "kill":
        c_prime_kill()

    once = len(sys.argv) > 1 and sys.argv[1] == "once"

    _log("Public Scam Intelligence Bridge starting")
    _log(f"  Data dir: {DATA_DIR}")
    _log(f"  Mode: {'single cycle' if once else 'continuous polling'}")
    _log("  Sources: Scamwatch, PhishTank, OpenPhish, URLhaus")
    _log("  100% on-device. Ghost gloves on. Your device. Your rules.")

    # Load seen hashes to avoid re-fetching
    seen_file = DATA_DIR.parent / "scam_seen.json"
    seen_hashes = set()
    if seen_file.exists():
        try:
            seen_hashes = set(json.loads(seen_file.read_text()))
        except (json.JSONDecodeError, TypeError):
            pass

    cycle = 0
    while True:
        try:
            total = run_cycle(seen_hashes, cycle)

            # Persist seen hashes
            seen_file.write_text(json.dumps(list(seen_hashes)[-10000:]))  # Cap at 10K

            if once:
                _log(f"Single cycle done. {total} new records.")
                break

            cycle += 1
            sleep_time = POLL_BASE + random.randint(-POLL_JITTER, POLL_JITTER)
            _log(f"Sleeping {sleep_time // 60} min until next cycle...")
            time.sleep(sleep_time)

        except KeyboardInterrupt:
            _log("Interrupted — shutting down cleanly.")
            seen_file.write_text(json.dumps(list(seen_hashes)[-10000:]))
            break
        except Exception as e:
            _log(f"Cycle error: {e}")
            if once:
                break
            time.sleep(300)  # Back off 5 min on error
            cycle += 1


if __name__ == "__main__":
    main()
