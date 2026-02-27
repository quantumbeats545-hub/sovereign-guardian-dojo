#!/usr/bin/env python3
"""
World Data Bridge — pulls financial threat intel, regulatory warnings, crypto market
context, news sentiment, and legitimate baseline data from public sources.

Sources (all public, no auth, no API keys):
  - Reddit r/Scams, r/CryptoCurrency, r/personalfinance — scam reports + crypto context
  - CoinGecko — price data for pump & dump detection
  - CoinDesk RSS — crypto news sentiment
  - CoinTelegraph RSS — crypto news sentiment
  - SEC EDGAR — enforcement actions + investor alerts
  - FCA Warning List — unauthorised firms (UK regulator)
  - ASIC Warnings — unauthorised firms (Australian regulator)
  - SFC Alert List — unauthorised firms / suspicious VA platforms (Hong Kong regulator)
  - FMA Warnings — unauthorised firms (New Zealand regulator)
  - CBI Unauthorised Firms — unauthorised firms (Ireland regulator)
  - Government Baseline — ACCC, MoneySmart, FTC, FMA, SFC consumer advice (legitimate patterns)

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
import xml.etree.ElementTree as ET

# ==================== CONFIG ====================
DATA_DIR = Path.home() / ".config" / "observer" / "raw"
DATA_DIR.mkdir(parents=True, exist_ok=True)

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/18.4 Safari/605.1.15"
)

# Per-source polling intervals (seconds)
SCHEDULES = {
    "reddit":     1800,   # 30 min — rate limited, be polite
    "coingecko":  900,    # 15 min — price data needs freshness
    "news_rss":   1800,   # 30 min — CoinDesk + CoinTelegraph
    "sec_edgar":  3600,   # 1 hour — only updates during market hours
    "regulators": 21600,  # 6 hours — FCA, ASIC pages update slowly
    "baseline":   86400,  # 24 hours — gov advice pages rarely change
}

# Reddit subreddits to scrape
REDDIT_SUBS = ["Scams", "CryptoCurrency", "personalfinance"]

# CoinGecko coins to track
COINGECKO_COINS = "bitcoin,ethereum,solana,bnb,cardano,dogecoin"

# RSS feeds
RSS_FEEDS = [
    ("https://www.coindesk.com/arc/outboundfeeds/rss/", "coindesk"),
    ("https://cointelegraph.com/rss", "cointelegraph"),
]

# SEC EDGAR RSS for enforcement/alerts
SEC_FEED = "https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&type=&dateb=&owner=include&count=20&search_text=&action=getcompany&output=atom"

# Regulator warning pages
FCA_URL = "https://www.fca.org.uk/consumers/warning-list-unauthorised-firms"
ASIC_URL = "https://asic.gov.au/online-services/search-asic-s-registers/"
SFC_URL = "https://www.sfc.hk/en/alert-list"
FMA_URL = "https://www.fma.govt.nz/library/warnings-and-alerts/"
CBI_URL = "https://www.centralbank.ie/regulation/how-we-regulate/authorisation/unauthorised-firms/search-unauthorised-firms"

# Government baseline pages (legitimate communication patterns)
BASELINE_PAGES = [
    ("https://www.scamwatch.gov.au/get-help/protect-yourself-from-scams", "accc_protect"),
    ("https://moneysmart.gov.au/banking", "moneysmart_banking"),
    ("https://moneysmart.gov.au/investment-warnings/investment-scams", "moneysmart_invest"),
    ("https://consumer.ftc.gov/articles/how-avoid-scam", "ftc_avoid"),
    ("https://www.fma.govt.nz/consumer/", "fma_consumer_nz"),
    ("https://www.sfc.hk/en/Regulatory-functions/Intermediaries/Licensing/Do-you-need-a-licence-or-registration", "sfc_licensing_hk"),
]


def _log(*args):
    print(f"[{datetime.now(timezone.utc).isoformat()}]", *args, flush=True)


# ==================== C' REVOCATION ====================
def c_prime_kill():
    """One biometric tap → all world data destroyed. No recovery."""
    patterns = ["reddit_*.json", "coingecko_*.json", "news_*.json",
                "sec_*.json", "fca_*.json", "asic_*.json",
                "sfc_*.json", "fma_*.json", "cbi_*.json", "baseline_*.json"]
    count = 0
    for pat in patterns:
        for f in DATA_DIR.glob(pat):
            f.unlink()
            count += 1
    seen_file = DATA_DIR.parent / "world_seen.json"
    if seen_file.exists():
        seen_file.unlink()
    _log(f"REVOKED — {count} world data files destroyed.")
    sys.exit(0)


# ==================== SUSPICIOUS SCAN ====================
def suspicious_scan(text: str) -> str:
    """Strip any real PII before storage. Returns sanitised text."""
    text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED-SSN]', text)
    text = re.sub(r'\b\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}\b', '[REDACTED-CC]', text)
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[REDACTED-EMAIL]', text)
    text = re.sub(r'\b(?:\+?61|0)4\d{2}[\s-]?\d{3}[\s-]?\d{3}\b', '[REDACTED-PHONE]', text)
    text = re.sub(r'\b(?:\+?1)?[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4}\b', '[REDACTED-PHONE]', text)
    text = re.sub(r'\b\d{10,}\b', '[REDACTED-NUM]', text)
    return text


# ==================== HTML PARSING ====================
class PageParser(HTMLParser):
    """Extract text content from HTML, stripping tags."""

    def __init__(self):
        super().__init__()
        self._text_parts = []
        self._skip_tags = {"script", "style", "nav", "header", "footer"}
        self._in_skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in self._skip_tags:
            self._in_skip += 1

    def handle_endtag(self, tag):
        if tag in self._skip_tags:
            self._in_skip = max(0, self._in_skip - 1)

    def handle_data(self, data):
        if self._in_skip == 0:
            stripped = data.strip()
            if stripped:
                self._text_parts.append(stripped)

    def get_text(self) -> str:
        return "\n".join(self._text_parts)


def _content_hash(text: str) -> str:
    """SHA-256 content hash (16 hex chars) for deduplication."""
    return hashlib.sha256(text[:3000].encode("utf-8", errors="replace")).hexdigest()[:16]


def _fetch_url(url: str, timeout: int = 30) -> bytes:
    """Fetch URL with spoofed UA. Returns raw bytes."""
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _store(record: dict, filename: str):
    """Store sanitised record to DATA_DIR."""
    (DATA_DIR / filename).write_text(json.dumps(record, indent=2))


# ==================== SOURCE: REDDIT ====================
def pull_reddit(seen: set) -> int:
    """Pull recent posts from r/Scams, r/CryptoCurrency, r/personalfinance."""
    new_count = 0
    ts = int(time.time())

    for sub in REDDIT_SUBS:
        try:
            url = f"https://www.reddit.com/r/{sub}/new.json?limit=25"
            raw = _fetch_url(url)
            data = json.loads(raw)

            children = data.get("data", {}).get("children", [])
            for child in children:
                post = child.get("data", {})
                post_id = post.get("id", "")
                if not post_id or post_id in seen:
                    continue

                title = suspicious_scan(post.get("title", ""))
                selftext = suspicious_scan(post.get("selftext", "")[:3000])
                score = post.get("score", 0)

                # Skip very low quality
                if score < 1 and not selftext:
                    continue

                record = {
                    "source": "reddit",
                    "subreddit": sub,
                    "post_id": post_id,
                    "title": title,
                    "selftext": selftext,
                    "score": score,
                    "num_comments": post.get("num_comments", 0),
                    "url": post.get("url", ""),
                    "created_utc": post.get("created_utc", 0),
                    "link_flair_text": post.get("link_flair_text", ""),
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                }

                h = _content_hash(f"{post_id}{title}")
                filename = f"reddit_{ts}_{post_id[:8]}.json"
                _store(record, filename)
                seen.add(post_id)
                new_count += 1

            _log(f"  Reddit r/{sub}: {len(children)} posts, {new_count} new")

        except (HTTPError, URLError, TimeoutError) as e:
            _log(f"  Reddit r/{sub}: fetch failed — {e}")
        except Exception as e:
            _log(f"  Reddit r/{sub}: parse error — {e}")

        # Reddit rate limit: 1 request per 2 seconds minimum
        time.sleep(random.uniform(2, 4))

    return new_count


# ==================== SOURCE: COINGECKO ====================
def pull_coingecko(seen: set) -> int:
    """Pull crypto prices for pump & dump detection (>20% swing in 24h)."""
    try:
        url = (f"https://api.coingecko.com/api/v3/simple/price"
               f"?ids={COINGECKO_COINS}&vs_currencies=usd"
               f"&include_24hr_change=true&include_24hr_vol=true")
        raw = _fetch_url(url)
        data = json.loads(raw)

        ts = int(time.time())
        record = {
            "source": "coingecko",
            "prices": {},
            "alerts": [],
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }

        for coin, info in data.items():
            price = info.get("usd", 0)
            change_24h = info.get("usd_24h_change", 0)
            vol_24h = info.get("usd_24h_vol", 0)

            record["prices"][coin] = {
                "usd": price,
                "change_24h_pct": round(change_24h, 2) if change_24h else 0,
                "volume_24h": vol_24h,
            }

            # Flag pump & dump signals (>20% swing either direction)
            if change_24h and abs(change_24h) > 20:
                direction = "PUMP" if change_24h > 0 else "DUMP"
                record["alerts"].append({
                    "coin": coin,
                    "direction": direction,
                    "change_pct": round(change_24h, 2),
                    "price_usd": price,
                })

        filename = f"coingecko_{ts}.json"
        _store(record, filename)
        _log(f"  CoinGecko: {len(data)} coins, {len(record['alerts'])} alerts")
        return 1

    except (HTTPError, URLError, TimeoutError) as e:
        _log(f"  CoinGecko: fetch failed — {e}")
    except Exception as e:
        _log(f"  CoinGecko: parse error — {e}")
    return 0


# ==================== SOURCE: RSS FEEDS ====================
def pull_rss_feeds(seen: set) -> int:
    """Pull CoinDesk + CoinTelegraph RSS for news sentiment."""
    new_count = 0
    ts = int(time.time())

    for feed_url, source_name in RSS_FEEDS:
        try:
            raw = _fetch_url(feed_url)
            text = raw.decode("utf-8", errors="replace")

            # Parse RSS XML
            root = ET.fromstring(text)

            # Handle both RSS 2.0 (<channel><item>) and Atom (<entry>)
            items = root.findall(".//item") or root.findall(".//{http://www.w3.org/2005/Atom}entry")

            feed_new = 0
            for item in items[:20]:  # Cap at 20 per feed
                # RSS 2.0
                title_el = item.find("title")
                link_el = item.find("link")
                desc_el = item.find("description")
                pub_el = item.find("pubDate")

                # Atom fallback
                if title_el is None:
                    title_el = item.find("{http://www.w3.org/2005/Atom}title")
                if link_el is None:
                    link_el = item.find("{http://www.w3.org/2005/Atom}link")
                if desc_el is None:
                    desc_el = item.find("{http://www.w3.org/2005/Atom}summary")
                if pub_el is None:
                    pub_el = item.find("{http://www.w3.org/2005/Atom}published") or \
                             item.find("{http://www.w3.org/2005/Atom}updated")

                title = title_el.text.strip() if title_el is not None and title_el.text else ""
                link = ""
                if link_el is not None:
                    link = link_el.text.strip() if link_el.text else link_el.get("href", "")
                description = desc_el.text.strip() if desc_el is not None and desc_el.text else ""
                pub_date = pub_el.text.strip() if pub_el is not None and pub_el.text else ""

                if not title:
                    continue

                content_id = _content_hash(f"{source_name}{title}")
                if content_id in seen:
                    continue

                # Sanitise
                title = suspicious_scan(title)
                description = suspicious_scan(description[:2000])

                record = {
                    "source": f"news_{source_name}",
                    "title": title,
                    "link": link,
                    "description": description,
                    "pub_date": pub_date,
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                }

                filename = f"news_{source_name}_{ts}_{content_id[:8]}.json"
                _store(record, filename)
                seen.add(content_id)
                feed_new += 1

            new_count += feed_new
            _log(f"  RSS {source_name}: {len(items)} items, {feed_new} new")

        except (HTTPError, URLError, TimeoutError) as e:
            _log(f"  RSS {source_name}: fetch failed — {e}")
        except ET.ParseError as e:
            _log(f"  RSS {source_name}: XML parse error — {e}")
        except Exception as e:
            _log(f"  RSS {source_name}: error — {e}")

        time.sleep(random.uniform(1, 3))

    return new_count


# ==================== SOURCE: SEC EDGAR ====================
def pull_sec_alerts(seen: set) -> int:
    """Pull SEC enforcement actions and investor alerts."""
    new_count = 0
    ts = int(time.time())

    try:
        # SEC EDGAR full-text search RSS for fraud/enforcement
        urls = [
            "https://efts.sec.gov/LATEST/search-index?q=%22investor+alert%22&dateRange=custom&startdt=2024-01-01&forms=&hits=20",
            "https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&type=&dateb=&owner=include&count=20&search_text=&action=getcompany&output=atom",
        ]

        # Try the EDGAR full-text search first
        try:
            url = "https://efts.sec.gov/LATEST/search-index?q=%22enforcement+action%22&dateRange=custom&startdt=2024-01-01&enddt=2026-12-31"
            raw = _fetch_url(url, timeout=30)
            data = json.loads(raw)

            hits = data.get("hits", {}).get("hits", [])
            for hit in hits[:15]:
                source = hit.get("_source", {})
                file_num = source.get("file_num", "")
                title = source.get("display_names", [""])[0] if source.get("display_names") else ""
                form_type = source.get("form_type", "")
                filed_date = source.get("file_date", "")

                content_id = _content_hash(f"sec_{file_num}_{title}")
                if content_id in seen:
                    continue

                record = {
                    "source": "sec_edgar",
                    "file_num": file_num,
                    "title": suspicious_scan(title),
                    "form_type": form_type,
                    "filed_date": filed_date,
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                }

                filename = f"sec_{ts}_{content_id[:8]}.json"
                _store(record, filename)
                seen.add(content_id)
                new_count += 1

            _log(f"  SEC EDGAR: {len(hits)} filings, {new_count} new")

        except (HTTPError, URLError, TimeoutError) as e:
            _log(f"  SEC EDGAR search: {e}")

        # Also try the Atom feed
        try:
            raw = _fetch_url(SEC_FEED, timeout=30)
            text = raw.decode("utf-8", errors="replace")
            root = ET.fromstring(text)

            ns = {"atom": "http://www.w3.org/2005/Atom"}
            entries = root.findall("atom:entry", ns)

            for entry in entries[:15]:
                title_el = entry.find("atom:title", ns)
                updated_el = entry.find("atom:updated", ns)
                summary_el = entry.find("atom:summary", ns)

                title = title_el.text.strip() if title_el is not None and title_el.text else ""
                if not title:
                    continue

                content_id = _content_hash(f"sec_atom_{title}")
                if content_id in seen:
                    continue

                record = {
                    "source": "sec_edgar_atom",
                    "title": suspicious_scan(title),
                    "updated": updated_el.text.strip() if updated_el is not None and updated_el.text else "",
                    "summary": suspicious_scan(summary_el.text[:2000]) if summary_el is not None and summary_el.text else "",
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                }

                filename = f"sec_{ts}_{content_id[:8]}.json"
                _store(record, filename)
                seen.add(content_id)
                new_count += 1

        except (HTTPError, URLError, TimeoutError, ET.ParseError) as e:
            _log(f"  SEC EDGAR Atom: {e}")

    except Exception as e:
        _log(f"  SEC EDGAR: error — {e}")

    return new_count


# ==================== SOURCE: FCA WARNING LIST ====================
def pull_fca_warnings(seen: set) -> int:
    """Pull FCA (UK) unauthorised firm warnings."""
    new_count = 0
    ts = int(time.time())

    try:
        raw = _fetch_url(FCA_URL, timeout=30)
        html = raw.decode("utf-8", errors="replace")

        # Extract warning entries from the page
        # FCA uses structured warning cards with firm names, types, dates
        # Pattern: firm name in <h3> or <strong>, followed by details
        firm_patterns = [
            # Table rows with firm names
            re.findall(r'<td[^>]*>([^<]{5,100})</td>\s*<td[^>]*>(Clone|Unauthorised|Warning)[^<]*</td>', html, re.I),
            # Warning list items
            re.findall(r'(?:firm|company|entity)[:\s]*([^<\n]{5,100}).*?(?:unauthorised|clone|warning)', html, re.I),
        ]

        firms = set()
        for matches in firm_patterns:
            for match in matches:
                if isinstance(match, tuple):
                    firm_name = match[0].strip()
                    warning_type = match[1].strip()
                else:
                    firm_name = match.strip()
                    warning_type = "warning"

                firm_name = re.sub(r'<[^>]+>', '', firm_name).strip()
                if len(firm_name) < 3 or firm_name in firms:
                    continue
                firms.add(firm_name)

                content_id = _content_hash(f"fca_{firm_name}")
                if content_id in seen:
                    continue

                record = {
                    "source": "fca_warning",
                    "firm_name": suspicious_scan(firm_name),
                    "warning_type": warning_type.lower(),
                    "url": FCA_URL,
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                }

                filename = f"fca_{ts}_{content_id[:8]}.json"
                _store(record, filename)
                seen.add(content_id)
                new_count += 1

        _log(f"  FCA: {len(firms)} firms found, {new_count} new")

    except (HTTPError, URLError, TimeoutError) as e:
        _log(f"  FCA: fetch failed — {e}")
    except Exception as e:
        _log(f"  FCA: parse error — {e}")

    return new_count


# ==================== SOURCE: ASIC WARNINGS ====================
def pull_asic_warnings(seen: set) -> int:
    """Pull ASIC (Australian) unauthorised firm warnings."""
    new_count = 0
    ts = int(time.time())

    try:
        # ASIC has a companies/people search and warning notices
        urls = [
            "https://asic.gov.au/about-asic/news-centre/",
            "https://asic.gov.au/regulatory-resources/financial-services/",
        ]

        for page_url in urls:
            try:
                raw = _fetch_url(page_url, timeout=30)
                html = raw.decode("utf-8", errors="replace")

                parser = PageParser()
                parser.feed(html)
                text = parser.get_text()

                # Extract enforcement actions and warnings
                # Look for company names near warning keywords
                warning_blocks = re.findall(
                    r'(?:warning|enforcement|banned|revoked|cancelled|suspended)'
                    r'[^.]{0,200}?(?:company|firm|entity|person|director)[:\s]*([^\n.]{5,100})',
                    text, re.I
                )

                for block in warning_blocks[:20]:
                    entity = suspicious_scan(block.strip())
                    content_id = _content_hash(f"asic_{entity}")
                    if content_id in seen:
                        continue

                    record = {
                        "source": "asic_warning",
                        "entity": entity,
                        "url": page_url,
                        "fetched_at": datetime.now(timezone.utc).isoformat(),
                    }

                    filename = f"asic_{ts}_{content_id[:8]}.json"
                    _store(record, filename)
                    seen.add(content_id)
                    new_count += 1

            except (HTTPError, URLError, TimeoutError) as e:
                _log(f"  ASIC ({page_url}): fetch failed — {e}")

            time.sleep(random.uniform(2, 5))

        _log(f"  ASIC: {new_count} new warnings")

    except Exception as e:
        _log(f"  ASIC: error — {e}")

    return new_count


# ==================== SOURCE: SFC ALERT LIST (HONG KONG) ====================
def pull_sfc_warnings(seen: set) -> int:
    """Pull SFC (Hong Kong) alert list — unlicensed firms, suspicious VA platforms."""
    new_count = 0
    ts = int(time.time())

    try:
        raw = _fetch_url(SFC_URL, timeout=30)
        html = raw.decode("utf-8", errors="replace")

        # SFC alert list is a <table> with rows: entity name | category | date
        rows = re.findall(r'<tr[^>]*>(.*?)</tr>', html, re.S)

        entities = set()
        for row in rows:
            cells = re.findall(r'<td[^>]*>(.*?)</td>', row, re.S)
            if len(cells) < 2:
                continue

            entity_name = re.sub(r'<[^>]+>', '', cells[0]).strip()
            category = re.sub(r'<[^>]+>', '', cells[1]).strip()
            date_str = re.sub(r'<[^>]+>', '', cells[2]).strip() if len(cells) > 2 else ""

            # Strip "(New)" suffix
            entity_name = re.sub(r'\s*\(New\)\s*$', '', entity_name, flags=re.I).strip()

            if len(entity_name) < 3 or entity_name in entities:
                continue
            entities.add(entity_name)

            content_id = _content_hash(f"sfc_{entity_name}")
            if content_id in seen:
                continue

            record = {
                "source": "sfc_warning",
                "entity_name": suspicious_scan(entity_name),
                "category": category.lower(),
                "date": date_str,
                "jurisdiction": "HK",
                "url": SFC_URL,
                "fetched_at": datetime.now(timezone.utc).isoformat(),
            }

            filename = f"sfc_{ts}_{content_id[:8]}.json"
            _store(record, filename)
            seen.add(content_id)
            new_count += 1

        _log(f"  SFC: {len(entities)} entities found, {new_count} new")

    except (HTTPError, URLError, TimeoutError) as e:
        _log(f"  SFC: fetch failed — {e}")
    except Exception as e:
        _log(f"  SFC: parse error — {e}")

    return new_count


# ==================== SOURCE: FMA WARNINGS (NEW ZEALAND) ====================
def pull_fma_warnings(seen: set) -> int:
    """Pull FMA (New Zealand) warnings and alerts — unauthorised firms."""
    new_count = 0
    ts = int(time.time())

    try:
        raw = _fetch_url(FMA_URL, timeout=30)
        html = raw.decode("utf-8", errors="replace")

        # FMA uses <article> blocks with <h3><a> titles and date spans
        articles = re.findall(r'<article[^>]*>(.*?)</article>', html, re.S)

        firms = set()
        for art in articles:
            # Title from <h3><a href="...">Title</a></h3>
            title_m = re.search(r'<h3[^>]*>\s*<a[^>]*>([^<]+)</a>', art, re.S)
            if not title_m:
                continue
            firm_name = title_m.group(1).strip()

            # Date from <span class="search-results-semantic__date">
            date_m = re.search(r'class="search-results-semantic__date"[^>]*>\s*(\d{1,2}\s+\w+\s+\d{4})', art, re.S)
            date_str = date_m.group(1).strip() if date_m else ""

            firm_name = re.sub(r'<[^>]+>', '', firm_name).strip()
            if len(firm_name) < 3 or firm_name in firms:
                continue
            firms.add(firm_name)

            content_id = _content_hash(f"fma_{firm_name}")
            if content_id in seen:
                continue

            record = {
                "source": "fma_warning",
                "firm_name": suspicious_scan(firm_name),
                "date": date_str,
                "jurisdiction": "NZ",
                "url": FMA_URL,
                "fetched_at": datetime.now(timezone.utc).isoformat(),
            }

            filename = f"fma_{ts}_{content_id[:8]}.json"
            _store(record, filename)
            seen.add(content_id)
            new_count += 1

        _log(f"  FMA: {len(firms)} firms found, {new_count} new")

    except (HTTPError, URLError, TimeoutError) as e:
        _log(f"  FMA: fetch failed — {e}")
    except Exception as e:
        _log(f"  FMA: parse error — {e}")

    return new_count


# ==================== SOURCE: CBI UNAUTHORISED FIRMS (IRELAND) ====================
def pull_cbi_warnings(seen: set) -> int:
    """Pull CBI (Ireland) unauthorised firms list from embedded appData JSON."""
    new_count = 0
    ts = int(time.time())

    try:
        raw = _fetch_url(CBI_URL, timeout=30)
        html = raw.decode("utf-8", errors="replace")

        # CBI embeds firm data as a JS array: var appData = [ { ... }, ... ];
        # Values are wrapped in decodeTitle("...") calls
        firms_data = []
        app_data_match = re.search(r'var\s+appData\s*=\s*(\[.+?\])\s*;', html, re.S)

        if app_data_match:
            js_array = app_data_match.group(1)
            # Strip decodeTitle() wrappers to produce valid JSON
            clean_json = re.sub(r'decodeTitle\("([^"]*)"\)', r'"\1"', js_array)
            # Escape stray control characters (tabs etc.) that break JSON parsing
            clean_json = re.sub(r'[\x00-\x09\x0b\x0c\x0e-\x1f]', lambda m: f'\\u{ord(m.group()):04x}', clean_json)
            try:
                entries = json.loads(clean_json)
                for entry in entries:
                    name = entry.get("firmName", "").strip()
                    if len(name) >= 3:
                        firms_data.append({
                            "name": name,
                            "country": entry.get("country", "").strip(),
                            "date": entry.get("warningDate", "").strip(),
                        })
            except (json.JSONDecodeError, KeyError) as e:
                _log(f"  CBI: JSON parse failed — {e}")

        for firm in firms_data:
            firm_name = firm.get("name", "").strip()
            if len(firm_name) < 3:
                continue

            content_id = _content_hash(f"cbi_{firm_name}")
            if content_id in seen:
                continue

            record = {
                "source": "cbi_warning",
                "firm_name": suspicious_scan(firm_name),
                "country": firm.get("country", ""),
                "date": firm.get("date", ""),
                "jurisdiction": "IE",
                "url": CBI_URL,
                "fetched_at": datetime.now(timezone.utc).isoformat(),
            }

            filename = f"cbi_{ts}_{content_id[:8]}.json"
            _store(record, filename)
            seen.add(content_id)
            new_count += 1

        _log(f"  CBI: {len(firms_data)} firms found, {new_count} new")

    except (HTTPError, URLError, TimeoutError) as e:
        _log(f"  CBI: fetch failed — {e}")
    except Exception as e:
        _log(f"  CBI: parse error — {e}")

    return new_count


# ==================== SOURCE: GOVERNMENT BASELINE ====================
def pull_gov_baseline(seen: set) -> int:
    """Pull legitimate consumer advice pages as golden-path training data.
    These represent how real institutions communicate — no urgency, verifiable contact."""
    new_count = 0
    ts = int(time.time())

    for page_url, source_id in BASELINE_PAGES:
        try:
            raw = _fetch_url(page_url, timeout=30)
            html = raw.decode("utf-8", errors="replace")

            parser = PageParser()
            parser.feed(html)
            text = parser.get_text()

            if len(text) < 100:
                _log(f"  Baseline {source_id}: too short, skipping")
                continue

            content_id = _content_hash(f"baseline_{source_id}_{text[:500]}")
            if content_id in seen:
                continue

            # Extract legitimacy markers
            legitimacy_markers = []
            if re.search(r'\.gov\.', page_url):
                legitimacy_markers.append("official_government_domain")
            if re.search(r'contact|phone|email|visit', text[:1000], re.I):
                legitimacy_markers.append("verifiable_contact_info")
            if not re.search(r'urgent|immediately|act now|limited time', text[:2000], re.I):
                legitimacy_markers.append("no_urgency_pressure")
            if re.search(r'report|complaint|ombudsman', text[:2000], re.I):
                legitimacy_markers.append("dispute_resolution_info")

            clean_text = suspicious_scan(text[:5000])

            record = {
                "source": "gov_baseline",
                "source_id": source_id,
                "url": page_url,
                "content": clean_text,
                "is_legitimate": True,
                "legitimacy_markers": legitimacy_markers,
                "institution_type": _classify_institution(page_url),
                "fetched_at": datetime.now(timezone.utc).isoformat(),
            }

            filename = f"baseline_{source_id}_{ts}_{content_id[:8]}.json"
            _store(record, filename)
            seen.add(content_id)
            new_count += 1
            _log(f"  Baseline {source_id}: stored ({len(legitimacy_markers)} markers)")

        except (HTTPError, URLError, TimeoutError) as e:
            _log(f"  Baseline {source_id}: fetch failed — {e}")
        except Exception as e:
            _log(f"  Baseline {source_id}: error — {e}")

        time.sleep(random.uniform(2, 5))

    return new_count


def _classify_institution(url: str) -> str:
    """Classify the type of institution from URL."""
    if "scamwatch" in url or "accc" in url:
        return "consumer_protection_au"
    if "moneysmart" in url:
        return "financial_regulator_au"
    if "ftc.gov" in url:
        return "consumer_protection_us"
    if "sec.gov" in url:
        return "securities_regulator_us"
    if "fca.org.uk" in url:
        return "financial_regulator_uk"
    if "asic.gov.au" in url:
        return "securities_regulator_au"
    if "sfc.hk" in url:
        return "securities_regulator_hk"
    if "fma.govt.nz" in url:
        return "financial_regulator_nz"
    if "centralbank.ie" in url:
        return "financial_regulator_ie"
    return "government"


# ==================== CYCLE RUNNER ====================
def run_cycle(seen: set, cycle: int, last_run: dict) -> int:
    """Run one observation cycle. Check which sources are due based on schedule."""
    now = time.time()
    total = 0

    # Reddit — 30 min
    if now - last_run.get("reddit", 0) >= SCHEDULES["reddit"]:
        _log("Fetching Reddit...")
        total += pull_reddit(seen)
        last_run["reddit"] = now

    # CoinGecko — 15 min
    if now - last_run.get("coingecko", 0) >= SCHEDULES["coingecko"]:
        _log("Fetching CoinGecko...")
        total += pull_coingecko(seen)
        last_run["coingecko"] = now

    # News RSS — 30 min
    if now - last_run.get("news_rss", 0) >= SCHEDULES["news_rss"]:
        _log("Fetching News RSS...")
        total += pull_rss_feeds(seen)
        last_run["news_rss"] = now

    # SEC EDGAR — 1 hour
    if now - last_run.get("sec_edgar", 0) >= SCHEDULES["sec_edgar"]:
        _log("Fetching SEC EDGAR...")
        total += pull_sec_alerts(seen)
        last_run["sec_edgar"] = now

    # FCA + ASIC + SFC + FMA + CBI — 6 hours
    if now - last_run.get("regulators", 0) >= SCHEDULES["regulators"]:
        _log("Fetching FCA warnings...")
        total += pull_fca_warnings(seen)
        _log("Fetching ASIC warnings...")
        total += pull_asic_warnings(seen)
        _log("Fetching SFC warnings...")
        total += pull_sfc_warnings(seen)
        _log("Fetching FMA warnings...")
        total += pull_fma_warnings(seen)
        _log("Fetching CBI warnings...")
        total += pull_cbi_warnings(seen)
        last_run["regulators"] = now

    # Government baseline — 24 hours
    if now - last_run.get("baseline", 0) >= SCHEDULES["baseline"]:
        _log("Fetching government baseline...")
        total += pull_gov_baseline(seen)
        last_run["baseline"] = now

    return total


# ==================== MAIN LOOP ====================
def main():
    if len(sys.argv) > 1 and sys.argv[1] == "kill":
        c_prime_kill()

    once = len(sys.argv) > 1 and sys.argv[1] == "once"

    _log("World Data Bridge starting")
    _log(f"  Data dir: {DATA_DIR}")
    _log(f"  Mode: {'single cycle' if once else 'continuous polling'}")
    _log("  Sources: Reddit, CoinGecko, CoinDesk, CoinTelegraph, SEC, FCA, ASIC, SFC, FMA, CBI, Gov Baseline")
    _log("  100% on-device. Ghost gloves on. Your device. Your rules.")

    # Load seen hashes for dedup
    seen_file = DATA_DIR.parent / "world_seen.json"
    seen = set()
    if seen_file.exists():
        try:
            seen = set(json.loads(seen_file.read_text()))
        except (json.JSONDecodeError, TypeError):
            pass

    last_run = {source: 0 for source in SCHEDULES}  # Force all sources on first run
    cycle = 0

    while True:
        try:
            cycle += 1
            _log(f"=== Cycle {cycle} ===")
            total = run_cycle(seen, cycle, last_run)

            # Persist seen hashes (cap at 20K)
            seen_file.write_text(json.dumps(list(seen)[-20000:]))
            _log(f"Cycle {cycle} complete: {total} new records (seen: {len(seen)})")

            if once:
                break

            # Check every 60 seconds which sources are due
            jitter = random.randint(-10, 10)
            time.sleep(60 + jitter)

        except KeyboardInterrupt:
            _log("Interrupted — shutting down cleanly.")
            seen_file.write_text(json.dumps(list(seen)[-20000:]))
            break
        except Exception as e:
            _log(f"Cycle error: {e}")
            if once:
                break
            time.sleep(300)  # Back off 5 min on error
            cycle += 1


if __name__ == "__main__":
    main()
