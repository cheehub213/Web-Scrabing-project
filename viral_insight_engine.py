"""
╔══════════════════════════════════════════════════════════════════╗
║         SECURE VIRAL INSIGHT ENGINE  —  Beginner Version        ║
║  Group: Chiheb Bahri, Rissen Guermzei, Najmedine Zahra,         ║
║         Skandar Turki, Mouheb Oueslati  |  AY 2025-2026         ║
╚══════════════════════════════════════════════════════════════════╝

HOW TO RUN:
    1. Install dependencies:
       pip install requests beautifulsoup4 vaderSentiment

    2. Make sure Ollama is running locally:
       https://ollama.com  →  download & install
       then run:  ollama pull qwen2.5
       then run:  ollama serve

    3. Run this script:
       python viral_insight_engine.py

    4. Open  dashboard.html  in your browser to see the results!
"""

# ─────────────────────────────────────────────
#  IMPORTS  (standard library + 3 pip packages)
# ─────────────────────────────────────────────
import re           # for pattern matching (PII masking)
import time         # for polite delays between requests
import json         # for talking to Ollama
import html         # for XSS protection in the dashboard
import sqlite3      # built-in database (no install needed)
from collections import Counter          # counts word frequencies
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

import requests                          # pip install requests
from bs4 import BeautifulSoup            # pip install beautifulsoup4
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer  # pip install vaderSentiment


# ══════════════════════════════════════════════════════════════════
#  STEP 0 — CONFIGURATION
#  Change these settings before running!
# ══════════════════════════════════════════════════════════════════

TARGET_URL   = "https://jcitbs-elmourouj.tn"   # ← put your target website here
CRAWL_DEPTH  = 1                       # how many "levels" of links to follow
RATE_LIMIT   = 2.0                     # seconds to wait between each request (be polite!)
OLLAMA_MODEL = "qwen2.5"               # the AI model name in Ollama
OLLAMA_URL   = "http://localhost:11434/api/chat"  # local Ollama server
DB_FILE      = "results.db"            # SQLite database file
DASHBOARD    = "dashboard.html"        # output dashboard file

CTA_PATTERNS = {
    "contact", "subscribe", "sign up", "signup", "register", "buy", "shop",
    "order", "book", "start", "trial", "download", "learn more", "read more",
    "request", "quote", "demo", "apply", "join", "donate", "login", "log in",
}


# ══════════════════════════════════════════════════════════════════
#  STEP 1 — CRAWLER
#  Fetches web pages safely and politely
# ══════════════════════════════════════════════════════════════════

def clean_text_value(value):
    """Normalize short text values extracted from HTML."""
    return " ".join(value.strip().split()) if value else ""


def get_meta_content(soup, name=None, prop=None):
    """Return content from a meta tag by name or property."""
    attrs = {}
    if name:
        attrs["name"] = name
    if prop:
        attrs["property"] = prop

    tag = soup.find("meta", attrs=attrs)
    return clean_text_value(tag.get("content", "")) if tag else ""


def is_internal_link(base_domain, link):
    """Check whether a link stays on the crawled website."""
    parsed = urlparse(link)
    return parsed.netloc == "" or parsed.netloc == base_domain


def fetch_page(url, session):
    """
    Download one webpage and return text plus SEO-aware page signals.
    Returns None if anything goes wrong.
    """
    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()  # raises an error for 404, 500, etc.

        # Only process HTML pages (skip PDFs, images, etc.)
        if "text/html" not in response.headers.get("Content-Type", ""):
            return None

        soup = BeautifulSoup(response.text, "html.parser")
        base_domain = urlparse(url).netloc

        title = clean_text_value(soup.title.string) if soup.title else url
        meta_description = get_meta_content(soup, name="description")
        canonical_tag = soup.find("link", rel=lambda value: value and "canonical" in value)
        canonical = urljoin(url, canonical_tag.get("href", "")) if canonical_tag else ""

        headings = {
            level: [clean_text_value(tag.get_text(" ", strip=True)) for tag in soup.find_all(level)]
            for level in ("h1", "h2", "h3")
        }

        open_graph = {}
        for meta in soup.find_all("meta", property=True):
            prop = meta.get("property", "")
            if prop.startswith("og:"):
                open_graph[prop] = clean_text_value(meta.get("content", ""))

        schema_count = len([
            script for script in soup.find_all("script", type="application/ld+json")
            if script.get_text(strip=True)
        ])

        images = []
        missing_alt_count = 0
        for img in soup.find_all("img"):
            alt = clean_text_value(img.get("alt", ""))
            if not alt:
                missing_alt_count += 1
            images.append({
                "src": urljoin(url, img.get("src", "")),
                "alt": alt,
            })

        links = []
        internal_links = []
        external_links = []
        cta_texts = []
        for a in soup.find_all("a", href=True):
            full_link = urljoin(url, a["href"])
            label = clean_text_value(a.get_text(" ", strip=True))
            links.append(full_link)
            if is_internal_link(base_domain, full_link):
                internal_links.append(full_link)
            else:
                external_links.append(full_link)
            if label and any(pattern in label.lower() for pattern in CTA_PATTERNS):
                cta_texts.append(label)

        for button in soup.find_all("button"):
            label = clean_text_value(button.get_text(" ", strip=True))
            if label and any(pattern in label.lower() for pattern in CTA_PATTERNS):
                cta_texts.append(label)

        # Remove noisy tags after SEO extraction so readable content stays clean.
        for tag in soup(["script", "style", "nav", "footer", "header"]):
            tag.decompose()

        text = " ".join(soup.stripped_strings)

        return {
            "url": url,
            "title": title,
            "meta_description": meta_description,
            "headings": headings,
            "links": links,
            "internal_links": internal_links,
            "external_links": external_links,
            "images": images,
            "missing_alt_count": missing_alt_count,
            "canonical": canonical,
            "open_graph": open_graph,
            "schema_count": schema_count,
            "cta_texts": list(dict.fromkeys(cta_texts))[:10],
            "text": text,
        }

    except Exception as error:
        print(f"  [!] Could not fetch {url}: {error}")
        return None


def crawl(start_url, depth=1, delay=2.0):
    """
    Visit pages starting from start_url, following links up to 'depth' levels.
    Respects robots.txt and waits 'delay' seconds between each request.
    """
    print(f"\n🌐 Starting crawler on: {start_url}")
    base_domain = urlparse(start_url).netloc

    # Check robots.txt (the polite thing to do!)
    robot_parser = RobotFileParser()
    robot_parser.set_url(urljoin(start_url, "/robots.txt"))
    try:
        robot_parser.read()
        print("  ✓ robots.txt loaded")
    except Exception:
        print("  ⚠ Could not load robots.txt, continuing anyway")

    session = requests.Session()
    session.headers["User-Agent"] = "ViralInsightBot/1.0 (academic project)"

    visited = set()
    pages = []
    queue = [(start_url, 0)]  # (url, current_depth)

    while queue and len(pages) < 20:  # max 20 pages to be safe
        url, current_depth = queue.pop(0)

        if url in visited:
            continue
        visited.add(url)

        # Skip URLs that are not on the same website
        if urlparse(url).netloc != base_domain:
            continue

        # Respect robots.txt
        if not robot_parser.can_fetch("*", url):
            print(f"  ⛔ robots.txt blocks: {url}")
            continue

        print(f"  📄 Fetching [{current_depth}/{depth}]: {url}")
        page = fetch_page(url, session)

        if page:
            pages.append(page)

            # If we haven't reached max depth, add child links to the queue
            if current_depth < depth:
                for link in page["links"]:
                    if link not in visited:
                        queue.append((link, current_depth + 1))

        time.sleep(delay)  # polite delay!

    print(f"  ✓ Crawled {len(pages)} page(s)")
    return pages


# ══════════════════════════════════════════════════════════════════
#  STEP 2 — PII SANITIZER (Security!)
#  Removes personal information from text before analysis
# ══════════════════════════════════════════════════════════════════

# Patterns to detect and remove PII (Personally Identifiable Information)
PII_PATTERNS = [
    (r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", "<EMAIL>"),
    (r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",                     "<PHONE>"),
    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b",                            "<IP_ADDRESS>"),
    (r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b",                          "<SSN>"),
]

def sanitize(text):
    """
    Replace any detected PII with safe placeholder tokens.
    This keeps us GDPR-compliant!
    """
    for pattern, replacement in PII_PATTERNS:
        text = re.sub(pattern, replacement, text)
    return text


# ══════════════════════════════════════════════════════════════════
#  STEP 3a — FEATURE EXTRACTION
#  Pulls out keywords and interesting signals from the text
# ══════════════════════════════════════════════════════════════════

# Common words we don't care about
STOP_WORDS = {
    "a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "this", "that", "these", "those", "it", "its",
    "we", "you", "he", "she", "they", "i", "my", "our", "your", "his", "her",
    "not", "no", "so", "if", "as", "from", "up", "about", "than", "more",
}

# Words that often signal viral / engaging content
VIRAL_WORDS = {
    "breaking", "exclusive", "viral", "shocking", "amazing", "incredible",
    "secret", "revealed", "exposed", "urgent", "free", "trending", "popular",
    "best", "top", "worst", "never", "everyone", "instant", "proven",
}

def extract_features(page):
    """
    Analyse the page and return SEO, content, technical, and UX signals.
    """
    text = page["text"].lower()

    words = re.findall(r"\b[a-z]{3,}\b", text)
    keywords = [w for w in words if w not in STOP_WORDS]
    keyword_counts = Counter(keywords)
    top_keywords = keyword_counts.most_common(10)

    engagement_words = [w for w in keywords if w in VIRAL_WORDS]
    sentences = re.split(r"[.!?]+", page["text"])
    sentences = [s.strip() for s in sentences if s.strip()]
    avg_sentence_length = (
        sum(len(s.split()) for s in sentences) / len(sentences)
    ) if sentences else 0

    title = page.get("title", "")
    meta_description = page.get("meta_description", "")
    headings = page.get("headings", {})
    h1_values = headings.get("h1", [])
    h2_values = headings.get("h2", [])
    h1_count = len(headings.get("h1", []))
    h2_count = len(headings.get("h2", []))
    image_count = len(page.get("images", []))
    missing_alt_count = page.get("missing_alt_count", 0)
    missing_alt_examples = [
        image.get("src", "") for image in page.get("images", [])
        if not image.get("alt")
    ][:5]
    cta_count = len(page.get("cta_texts", []))

    title_score = 25 if 30 <= len(title) <= 65 else 12 if title else 0
    meta_score = 25 if 70 <= len(meta_description) <= 160 else 12 if meta_description else 0
    heading_score = 25 if h1_count == 1 and h2_count > 0 else 12 if h1_count >= 1 else 0
    link_score = 25 if page.get("internal_links") else 0
    seo_score = title_score + meta_score + heading_score + link_score

    readability_score = 35 if 8 <= avg_sentence_length <= 22 else 20 if avg_sentence_length <= 30 else 10
    length_score = 25 if len(words) >= 300 else 15 if len(words) >= 100 else 5
    structure_score = 25 if h2_count >= 2 else 15 if h2_count == 1 else 5
    focus_score = 15 if top_keywords else 0
    content_quality_score = min(readability_score + length_score + structure_score + focus_score, 100)

    alt_score = 25 if image_count == 0 or missing_alt_count == 0 else max(0, 25 - int((missing_alt_count / image_count) * 25))
    canonical_score = 25 if page.get("canonical") else 0
    schema_score = 25 if page.get("schema_count", 0) > 0 else 0
    og_score = 25 if page.get("open_graph") else 0
    technical_score = alt_score + canonical_score + schema_score + og_score

    engagement_score = min(len(engagement_words) * 8 + cta_count * 12 + min(len(page.get("internal_links", [])), 10) * 2, 100)
    ux_score = min((30 if cta_count else 0) + (25 if h1_count == 1 else 10 if h1_count else 0) + readability_score + (10 if page.get("internal_links") else 0), 100)

    return {
        "top_keywords": top_keywords,
        "title": title,
        "meta_description": meta_description,
        "h1_values": h1_values,
        "h2_values": h2_values,
        "engagement_words": list(set(engagement_words)),
        "seo_score": seo_score,
        "content_quality_score": content_quality_score,
        "technical_score": technical_score,
        "engagement_score": engagement_score,
        "ux_score": ux_score,
        "title_length": len(title),
        "meta_description_length": len(meta_description),
        "h1_count": h1_count,
        "h2_count": h2_count,
        "image_count": image_count,
        "missing_alt_count": missing_alt_count,
        "missing_alt_examples": missing_alt_examples,
        "internal_link_count": len(page.get("internal_links", [])),
        "external_link_count": len(page.get("external_links", [])),
        "schema_count": page.get("schema_count", 0),
        "cta_count": cta_count,
        "cta_texts": page.get("cta_texts", []),
        "sentence_count": len(sentences),
        "avg_sentence_length": round(avg_sentence_length, 1),
        "total_words": len(words),
    }


# ══════════════════════════════════════════════════════════════════
#  STEP 3b — SENTIMENT ANALYSIS
#  Determines if the page content is positive, negative, or neutral
# ══════════════════════════════════════════════════════════════════

sentiment_analyzer = SentimentIntensityAnalyzer()

def analyze_sentiment(text):
    """
    Use VADER to score the sentiment of the text.
    Returns a score from -1.0 (very negative) to +1.0 (very positive).
    """
    scores = sentiment_analyzer.polarity_scores(text[:5000])  # limit to 5000 chars
    compound = scores["compound"]

    if compound >= 0.05:
        label = "POSITIVE"
    elif compound <= -0.05:
        label = "NEGATIVE"
    else:
        label = "NEUTRAL"

    return {
        "compound": round(compound, 3),
        "positive": round(scores["pos"], 3),
        "negative": round(scores["neg"], 3),
        "neutral":  round(scores["neu"], 3),
        "label": label,
    }


# ══════════════════════════════════════════════════════════════════
#  STEP 3c — AI ANALYSIS (via Ollama — runs 100% locally!)
#  Sends structured data to a local LLM for deeper insights
# ══════════════════════════════════════════════════════════════════

def primary_keyword(features):
    """Return the strongest detected keyword for page-level recommendations."""
    return features["top_keywords"][0][0] if features.get("top_keywords") else "primary keyword"


def generate_action_plan(features):
    """Create concrete implementation steps from measured page signals."""
    keyword = primary_keyword(features)
    actions = []

    title = features.get("title", "")
    title_length = features.get("title_length", 0)
    if not title:
        actions.append(f"Add a <title> tag of 50-60 characters that includes '{keyword}' and the page purpose.")
    elif title_length < 30:
        actions.append(f"Expand the title from {title_length} to 50-60 characters. Current title: '{title}'. Include '{keyword}' plus a clear benefit.")
    elif title_length > 65:
        actions.append(f"Shorten the title from {title_length} to under 60 characters so it does not get truncated in search results.")

    meta = features.get("meta_description", "")
    meta_length = features.get("meta_description_length", 0)
    if not meta:
        actions.append(f"Add a meta description of 120-155 characters. Include '{keyword}', the target audience, and one clear reason to visit the page.")
    elif meta_length < 70:
        actions.append(f"Rewrite the meta description from {meta_length} to 120-155 characters. Mention '{keyword}' and add a clear value proposition.")
    elif meta_length > 160:
        actions.append(f"Shorten the meta description from {meta_length} to 155 characters or less to avoid search-result truncation.")

    h1_count = features.get("h1_count", 0)
    h1_values = features.get("h1_values", [])
    if h1_count == 0:
        actions.append(f"Add exactly one H1 near the top of the page, for example: '{keyword.title()} for Students and Young Professionals'.")
    elif h1_count > 1:
        actions.append(f"Keep only one H1. Convert the extra {h1_count - 1} H1 heading(s) to H2 so the page hierarchy is clear.")
    elif keyword not in " ".join(h1_values).lower():
        actions.append(f"Update the H1 to include the main topic '{keyword}' while keeping it readable.")

    if features.get("h2_count", 0) < 2:
        actions.append("Add at least two H2 sections that answer user questions, such as 'What We Offer' and 'How To Join'.")

    missing_alt_count = features.get("missing_alt_count", 0)
    image_count = features.get("image_count", 0)
    if missing_alt_count:
        example = features.get("missing_alt_examples", [""])[0]
        target = f" Example image: {example}" if example else ""
        actions.append(f"Add descriptive alt text to {missing_alt_count} of {image_count} image(s). Use short descriptions like 'JCI training event participants'.{target}")

    if features.get("schema_count", 0) == 0:
        actions.append("Add JSON-LD schema markup. Use Organization schema for the homepage and Event schema for event pages.")

    if features.get("internal_link_count", 0) < 3:
        actions.append("Add 3-5 internal links from this page to important pages such as events, training, membership, contact, or about pages.")

    if features.get("cta_count", 0) == 0:
        actions.append("Add a visible CTA button above the fold, such as 'Join JCI', 'Contact Us', or 'Register for an Event'.")
    elif features.get("cta_count", 0) == 1:
        actions.append("Add a second CTA after the main content so users have a next step after reading.")

    avg_sentence_length = features.get("avg_sentence_length", 0)
    if avg_sentence_length > 25:
        actions.append(f"Reduce average sentence length from {avg_sentence_length} words to under 20 words by splitting long paragraphs.")

    total_words = features.get("total_words", 0)
    if total_words < 300:
        actions.append(f"Expand the page from {total_words} to at least 300 words with practical details, FAQs, benefits, and next steps.")

    if not actions:
        actions.append("Page basics are healthy. Next improvement: add richer FAQs, stronger internal links, and more specific conversion copy.")

    return actions[:8]


def ask_ai(features, sentiment, url):
    """
    Send our extracted features to the local Ollama AI model.
    The model returns structured recommendations in JSON format.
    Data NEVER leaves your machine — full privacy!
    """
    keywords_str = ", ".join(f"{w}({c})" for w, c in features["top_keywords"][:8])
    cta_str = ", ".join(features.get("cta_texts", [])[:5]) or "None detected"
    prompt = f"""You are an SEO, UX, and digital marketing analyst. Analyze this webpage data and reply ONLY with JSON.

Important:
- Give specific implementation steps, not generic advice.
- Every recommendation must mention the exact detected problem, target range, or concrete HTML/content change.
- Avoid vague phrases such as "improve SEO", "optimize content", "enhance UX", or "consider improving".
- Good example: "Add alt text to 4 images, using descriptions such as 'JCI training participants in El Mourouj'."
- Good example: "Rewrite the meta description from 42 to 120-155 characters and include 'training' and 'community'."

URL: {url}
Top Keywords: {keywords_str}
Sentiment: {sentiment["label"]} (score: {sentiment["compound"]})
SEO Score: {features["seo_score"]}/100
Content Quality Score: {features["content_quality_score"]}/100
Technical SEO Score: {features["technical_score"]}/100
Engagement Score: {features["engagement_score"]}/100
UX Score: {features["ux_score"]}/100
Title Length: {features["title_length"]}
Meta Description Length: {features["meta_description_length"]}
H1 Count: {features["h1_count"]}
H2 Count: {features["h2_count"]}
Images: {features["image_count"]} total, {features["missing_alt_count"]} missing alt text
Internal Links: {features["internal_link_count"]}
External Links: {features["external_link_count"]}
Schema Markup Count: {features["schema_count"]}
CTA Texts: {cta_str}
Avg Sentence Length: {features["avg_sentence_length"]} words

Reply with this exact JSON structure (no extra text):
{{
  "seo_score": <number 0-100>,
  "content_quality_score": <number 0-100>,
  "technical_score": <number 0-100>,
  "engagement_score": <number 0-100>,
  "ux_score": <number 0-100>,
  "search_intent": "<Informational | Navigational | Commercial | Transactional>",
  "summary": "<one sentence summary of the page>",
  "strengths": ["<strength 1>", "<strength 2>"],
  "seo_recommendations": ["<specific implementation step 1>", "<specific implementation step 2>"],
  "content_recommendations": ["<specific implementation step 1>", "<specific implementation step 2>"],
  "ux_recommendations": ["<specific implementation step 1>", "<specific implementation step 2>"],
  "technical_issues": ["<specific issue with exact fix 1>", "<specific issue with exact fix 2>"]
}}"""

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "options": {"temperature": 0.3},
            },
            timeout=60,
        )
        response.raise_for_status()
        content = response.json()["message"]["content"].strip()

        # Remove markdown code fences if the model added them
        if content.startswith("```"):
            content = "\n".join(
                line for line in content.splitlines()
                if not line.strip().startswith("```")
            ).strip()

        return normalize_ai_result(json.loads(content), features)

    except requests.ConnectionError:
        print("  ⚠ Cannot connect to Ollama. Is it running? (ollama serve)")
        return _fallback_ai_result(features)
    except (json.JSONDecodeError, KeyError) as e:
        print(f"  ⚠ AI returned unexpected format: {e}")
        return _fallback_ai_result(features)
    except Exception as e:
        print(f"  ⚠ AI error: {e}")
        return _fallback_ai_result(features)


def normalize_ai_result(ai_result, features):
    """Fill any missing AI fields with deterministic local scores."""
    defaults = _fallback_ai_result(features)
    defaults.update(ai_result)
    defaults["action_plan"] = generate_action_plan(features)
    return defaults


def _fallback_ai_result(features=None):
    """Return a safe default when Ollama is unavailable."""
    features = features or {}
    return {
        "seo_score": features.get("seo_score", 0),
        "content_quality_score": features.get("content_quality_score", 0),
        "technical_score": features.get("technical_score", 0),
        "engagement_score": features.get("engagement_score", 0),
        "ux_score": features.get("ux_score", 0),
        "search_intent": "Unknown",
        "summary": "AI analysis unavailable (Ollama not running).",
        "action_plan": generate_action_plan(features),
        "strengths": [],
        "seo_recommendations": ["Start Ollama and re-run to get AI-powered recommendations."],
        "content_recommendations": [],
        "ux_recommendations": [],
        "technical_issues": [],
    }


# ══════════════════════════════════════════════════════════════════
#  STEP 4a — DATABASE STORAGE
#  Saves everything to a simple SQLite database file
# ══════════════════════════════════════════════════════════════════

def init_database(db_file):
    """Create the database table if it doesn't exist yet."""
    conn = sqlite3.connect(db_file)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS website_results (
            id                       INTEGER PRIMARY KEY AUTOINCREMENT,
            url                      TEXT,
            title                    TEXT,
            meta_description         TEXT,
            sentiment_label          TEXT,
            sentiment_score          REAL,
            seo_score                INTEGER,
            content_quality_score    INTEGER,
            technical_score          INTEGER,
            engagement_score         INTEGER,
            ux_score                 INTEGER,
            search_intent            TEXT,
            top_keywords             TEXT,
            extracted_signals        TEXT,
            ai_summary               TEXT,
            action_plan              TEXT,
            strengths                TEXT,
            seo_recommendations      TEXT,
            content_recommendations  TEXT,
            ux_recommendations       TEXT,
            technical_issues         TEXT,
            analyzed_at              TEXT DEFAULT (datetime('now'))
        )
    """)
    existing_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(website_results)")
    }
    if "action_plan" not in existing_columns:
        conn.execute("ALTER TABLE website_results ADD COLUMN action_plan TEXT")
    conn.commit()
    return conn


def save_to_database(conn, page, sentiment, ai_result, features):
    """Save one page's results into the database."""
    conn.execute(
        """INSERT INTO website_results
           (url, title, meta_description, sentiment_label, sentiment_score,
            seo_score, content_quality_score, technical_score, engagement_score,
            ux_score, search_intent, top_keywords, extracted_signals, ai_summary,
            action_plan, strengths, seo_recommendations, content_recommendations,
            ux_recommendations, technical_issues)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            page["url"],
            page["title"],
            page.get("meta_description", ""),
            sentiment["label"],
            sentiment["compound"],
            ai_result.get("seo_score", features["seo_score"]),
            ai_result.get("content_quality_score", features["content_quality_score"]),
            ai_result.get("technical_score", features["technical_score"]),
            ai_result.get("engagement_score", features["engagement_score"]),
            ai_result.get("ux_score", features["ux_score"]),
            ai_result.get("search_intent", "Unknown"),
            json.dumps([kw for kw, _ in features["top_keywords"][:5]]),
            json.dumps({
                "title_length": features["title_length"],
                "meta_description_length": features["meta_description_length"],
                "h1_count": features["h1_count"],
                "h2_count": features["h2_count"],
                "image_count": features["image_count"],
                "missing_alt_count": features["missing_alt_count"],
                "internal_link_count": features["internal_link_count"],
                "external_link_count": features["external_link_count"],
                "schema_count": features["schema_count"],
                "cta_count": features["cta_count"],
            }),
            ai_result.get("summary", ""),
            json.dumps(ai_result.get("action_plan", [])),
            json.dumps(ai_result.get("strengths", [])),
            json.dumps(ai_result.get("seo_recommendations", [])),
            json.dumps(ai_result.get("content_recommendations", [])),
            json.dumps(ai_result.get("ux_recommendations", [])),
            json.dumps(ai_result.get("technical_issues", [])),
        ),
    )
    conn.commit()


# ══════════════════════════════════════════════════════════════════
#  STEP 4b — DASHBOARD
#  Generates a nice HTML report you can open in any browser
#  Every value is HTML-escaped to prevent XSS attacks!
# ══════════════════════════════════════════════════════════════════

def e(value):
    """Safely escape any value for insertion into HTML (prevents XSS)."""
    return html.escape(str(value), quote=True)


def build_dashboard_legacy(all_results, output_file):
    """
    Write a self-contained HTML dashboard from all analysis results.
    """

    def sentiment_color(label):
        return {"POSITIVE": "#56d4a0", "NEGATIVE": "#f76c6c"}.get(label, "#8892a4")

    def virality_color(score):
        if score >= 70: return "#56d4a0"
        if score >= 40: return "#f7c56c"
        return "#f76c6c"

    cards_html = ""
    for r in all_results:
        sent    = r["sentiment"]
        feat    = r["features"]
        ai      = r["ai_result"]
        vscore  = ai.get("virality_score", 0)
        scol    = sentiment_color(sent["label"])
        vcol    = virality_color(vscore)

        keywords_html = "".join(
            f'<span class="tag">{e(kw)} <small>×{c}</small></span>'
            for kw, c in feat["top_keywords"][:8]
        )
        viral_html = "".join(
            f'<span class="tag viral">{e(w)}</span>'
            for w in feat["viral_words"]
        ) or '<span style="color:#555">none detected</span>'

        strengths_html = "".join(
            f"<li>✅ {e(s)}</li>" for s in ai.get("strengths", [])
        )
        improvements_html = "".join(
            f"<li>💡 {e(imp)}</li>" for imp in ai.get("improvements", [])
        )

        cards_html += f"""
        <div class="card">
          <div class="card-header">
            <div>
              <div class="card-title">{e(r['title'])}</div>
              <div class="card-url">{e(r['url'])}</div>
            </div>
            <span class="badge" style="background:{e(scol)}20;color:{e(scol)}">{e(sent['label'])}</span>
          </div>

          <div class="scores">
            <div class="score-box">
              <div class="score-value" style="color:{e(vcol)}">{e(vscore)}</div>
              <div class="score-label">Virality Score</div>
            </div>
            <div class="score-box">
              <div class="score-value" style="color:{e(scol)}">{e(sent['compound'])}</div>
              <div class="score-label">Sentiment Score</div>
            </div>
            <div class="score-box">
              <div class="score-value">{e(feat['total_words'])}</div>
              <div class="score-label">Total Words</div>
            </div>
          </div>

          <div class="bar-wrap">
            <div style="font-size:.75rem;color:#888;margin-bottom:4px">Virality</div>
            <div class="bar"><div class="bar-fill" style="width:{e(vscore)}%;background:{e(vcol)}"></div></div>
          </div>

          <p class="summary">{e(ai.get('summary', ''))}</p>

          <div class="section-title">📝 Top Keywords</div>
          <div class="tags">{keywords_html}</div>

          <div class="section-title">⚡ Viral Signal Words</div>
          <div class="tags">{viral_html}</div>

          {"<div class='section-title'>👍 Strengths</div><ul>" + strengths_html + "</ul>" if strengths_html else ""}
          {"<div class='section-title'>🔧 Improvements</div><ul>" + improvements_html + "</ul>" if improvements_html else ""}
        </div>"""

    total = len(all_results)
    avg_virality = round(
        sum(r["ai_result"].get("virality_score", 0) for r in all_results) / total
    ) if total else 0

    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'unsafe-inline';">
  <title>Secure Viral Insight Engine — Results</title>
  <style>
    * {{ box-sizing:border-box; margin:0; padding:0 }}
    body {{ font-family: system-ui, sans-serif; background:#0f1117; color:#e2e8f0; padding:24px; }}
    h1   {{ font-size:1.7rem; color:#6c8ef7; margin-bottom:4px }}
    .sub {{ color:#8892a4; font-size:.9rem; margin-bottom:28px }}
    .summary-row {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:32px }}
    .stat {{ background:#1a1d27; border:1px solid #2d3454; border-radius:10px;
             padding:18px 24px; text-align:center; flex:1; min-width:140px }}
    .stat .val {{ font-size:2rem; font-weight:700; color:#56d4a0 }}
    .stat .lbl {{ font-size:.75rem; color:#8892a4; margin-top:4px }}
    .card {{ background:#1a1d27; border:1px solid #2d3454; border-radius:12px;
             padding:24px; margin-bottom:20px }}
    .card-header {{ display:flex; justify-content:space-between;
                    align-items:flex-start; flex-wrap:wrap; gap:12px; margin-bottom:16px }}
    .card-title {{ font-size:1.05rem; font-weight:600 }}
    .card-url   {{ font-size:.75rem; color:#8892a4; word-break:break-all; margin-top:4px }}
    .badge {{ padding:4px 12px; border-radius:99px; font-size:.75rem; font-weight:600 }}
    .scores {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:16px }}
    .score-box {{ background:#0f1117; border-radius:8px; padding:12px 20px; text-align:center; flex:1; min-width:100px }}
    .score-value {{ font-size:1.6rem; font-weight:700 }}
    .score-label {{ font-size:.7rem; color:#8892a4; margin-top:2px }}
    .bar-wrap {{ margin-bottom:16px }}
    .bar {{ height:8px; background:#0f1117; border-radius:4px }}
    .bar-fill {{ height:100%; border-radius:4px; transition:width .3s }}
    .summary {{ color:#b0bec5; font-size:.88rem; margin:12px 0; font-style:italic }}
    .section-title {{ font-size:.72rem; font-weight:700; text-transform:uppercase;
                      letter-spacing:.08em; color:#8892a4; margin:14px 0 8px }}
    .tags {{ display:flex; flex-wrap:wrap; gap:6px; margin-bottom:8px }}
    .tag  {{ background:#0f1117; border:1px solid #2d3454; border-radius:6px;
             padding:3px 9px; font-size:.78rem }}
    .tag.viral {{ border-color:#f7c56c; color:#f7c56c }}
    .section-title.priority {{ color:#56d4a0 }}
    ul, ol {{ list-style:none; padding:0 }}
    li {{ padding:6px 0; font-size:.85rem; border-bottom:1px solid #2d3454 }}
    li:last-child {{ border-bottom:none }}
    .action-list li {{ background:#111827; border:1px solid #2d3454; border-radius:6px; margin-bottom:8px; padding:10px 12px; line-height:1.45 }}
    .action-list strong {{ color:#56d4a0 }}
    footer {{ text-align:center; font-size:.75rem; color:#555; margin-top:40px }}
  </style>
</head>
<body>
  <h1>🔍 Secure Viral Insight Engine</h1>
  <p class="sub">Target: {e(TARGET_URL)} — {e(total)} page(s) analysed</p>

  <div class="summary-row">
    <div class="stat"><div class="val">{e(total)}</div><div class="lbl">Pages Analysed</div></div>
    <div class="stat"><div class="val">{e(avg_virality)}</div><div class="lbl">Avg Virality Score</div></div>
    <div class="stat"><div class="val">{e(sum(1 for r in all_results if r['sentiment']['label']=='POSITIVE'))}</div><div class="lbl">Positive Pages</div></div>
    <div class="stat"><div class="val">{e(sum(1 for r in all_results if r['sentiment']['label']=='NEGATIVE'))}</div><div class="lbl">Negative Pages</div></div>
  </div>

  {cards_html}

  <footer>Secure Viral Insight Engine · Chiheb Bahri, Rissen Guermzei,
  Najmedine Zahra, Skandar Turki, Mouheb Oueslati · AY 2025-2026</footer>
</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(full_html)

    print(f"\n  ✓ Dashboard saved → {output_file}")
    print(f"    Open it in your browser!")


# ══════════════════════════════════════════════════════════════════
#  MAIN — runs all 4 steps in order
# ══════════════════════════════════════════════════════════════════

def build_dashboard(all_results, output_file):
    """
    Write a self-contained HTML website intelligence dashboard.
    """

    def sentiment_color(label):
        return {"POSITIVE": "#56d4a0", "NEGATIVE": "#f76c6c"}.get(label, "#8892a4")

    def score_color(score):
        if score >= 70:
            return "#56d4a0"
        if score >= 40:
            return "#f7c56c"
        return "#f76c6c"

    def ai_score(ai, feat, key):
        return int(ai.get(key, feat.get(key, 0)) or 0)

    def list_html(items):
        return "".join(f"<li>{e(item)}</li>" for item in items)

    cards_html = ""
    for r in all_results:
        sent = r["sentiment"]
        feat = r["features"]
        ai = r["ai_result"]
        seo_score = ai_score(ai, feat, "seo_score")
        content_score = ai_score(ai, feat, "content_quality_score")
        technical_score = ai_score(ai, feat, "technical_score")
        engagement_score = ai_score(ai, feat, "engagement_score")
        ux_score = ai_score(ai, feat, "ux_score")
        intent = ai.get("search_intent", "Unknown")
        scol = sentiment_color(sent["label"])
        seo_col = score_color(seo_score)

        keywords_html = "".join(
            f'<span class="tag">{e(kw)} <small>x{c}</small></span>'
            for kw, c in feat["top_keywords"][:8]
        )
        engagement_html = "".join(
            f'<span class="tag accent">{e(w)}</span>'
            for w in feat["engagement_words"]
        ) or '<span style="color:#555">none detected</span>'
        cta_html = "".join(
            f'<span class="tag cta">{e(cta)}</span>'
            for cta in feat.get("cta_texts", [])
        ) or '<span style="color:#555">none detected</span>'

        signals_html = f"""
          <div class="signals">
            <span>Title: {e(feat['title_length'])} chars</span>
            <span>Meta: {e(feat['meta_description_length'])} chars</span>
            <span>H1: {e(feat['h1_count'])}</span>
            <span>H2: {e(feat['h2_count'])}</span>
            <span>Images missing alt: {e(feat['missing_alt_count'])}/{e(feat['image_count'])}</span>
            <span>Internal links: {e(feat['internal_link_count'])}</span>
            <span>Schema blocks: {e(feat['schema_count'])}</span>
          </div>"""

        strengths_html = list_html(ai.get("strengths", []))
        action_plan_html = "".join(
            f"<li><strong>Step {i}:</strong> {e(action)}</li>"
            for i, action in enumerate(ai.get("action_plan", []), start=1)
        )
        seo_recs_html = list_html(ai.get("seo_recommendations", []))
        content_recs_html = list_html(ai.get("content_recommendations", []))
        ux_recs_html = list_html(ai.get("ux_recommendations", []))
        technical_issues_html = list_html(ai.get("technical_issues", []))

        cards_html += f"""
        <article class="card">
          <div class="card-header">
            <div>
              <div class="eyebrow">Page Audit</div>
              <div class="card-title">{e(r['title'])}</div>
              <div class="card-url">{e(r['url'])}</div>
            </div>
            <div class="badges">
              <span class="badge" style="background:{e(seo_col)}20;color:{e(seo_col)}">SEO {e(seo_score)}</span>
              <span class="badge">Intent: {e(intent)}</span>
              <span class="badge" style="background:{e(scol)}20;color:{e(scol)}">{e(sent['label'])}</span>
            </div>
          </div>

          <div class="scores">
            <div class="score-box"><div class="score-label">SEO</div><div class="score-value" style="color:{e(score_color(seo_score))}">{e(seo_score)}</div><div class="mini-bar"><span style="width:{e(seo_score)}%;background:{e(score_color(seo_score))}"></span></div></div>
            <div class="score-box"><div class="score-label">Content</div><div class="score-value" style="color:{e(score_color(content_score))}">{e(content_score)}</div><div class="mini-bar"><span style="width:{e(content_score)}%;background:{e(score_color(content_score))}"></span></div></div>
            <div class="score-box"><div class="score-label">Technical</div><div class="score-value" style="color:{e(score_color(technical_score))}">{e(technical_score)}</div><div class="mini-bar"><span style="width:{e(technical_score)}%;background:{e(score_color(technical_score))}"></span></div></div>
            <div class="score-box"><div class="score-label">UX</div><div class="score-value" style="color:{e(score_color(ux_score))}">{e(ux_score)}</div><div class="mini-bar"><span style="width:{e(ux_score)}%;background:{e(score_color(ux_score))}"></span></div></div>
            <div class="score-box"><div class="score-label">Engagement</div><div class="score-value" style="color:{e(score_color(engagement_score))}">{e(engagement_score)}</div><div class="mini-bar"><span style="width:{e(engagement_score)}%;background:{e(score_color(engagement_score))}"></span></div></div>
            <div class="score-box"><div class="score-label">Words</div><div class="score-value neutral">{e(feat['total_words'])}</div><div class="mini-bar"><span style="width:100%;background:#8b5cf6"></span></div></div>
          </div>

          <div class="bar-wrap">
            <div class="bar-label">SEO audit score</div>
            <div class="bar"><div class="bar-fill" style="width:{e(seo_score)}%;background:{e(seo_col)}"></div></div>
          </div>

          <p class="summary"><span>Insight</span>{e(ai.get('summary', ''))}</p>
          {signals_html}

          <div class="section-title"><span></span>Top Keywords</div>
          <div class="tags">{keywords_html}</div>

          <div class="section-title"><span></span>Engagement Signals</div>
          <div class="tags">{engagement_html}</div>

          <div class="section-title"><span></span>Detected CTAs</div>
          <div class="tags">{cta_html}</div>

          {"<div class='section-title priority'><span></span>Priority Action Plan</div><ol class='action-list'>" + action_plan_html + "</ol>" if action_plan_html else ""}
          {"<div class='section-title'><span></span>Strengths</div><ul class='note-list'>" + strengths_html + "</ul>" if strengths_html else ""}
          {"<div class='section-title'><span></span>SEO Recommendations</div><ul class='note-list'>" + seo_recs_html + "</ul>" if seo_recs_html else ""}
          {"<div class='section-title'><span></span>Content Recommendations</div><ul class='note-list'>" + content_recs_html + "</ul>" if content_recs_html else ""}
          {"<div class='section-title'><span></span>UX Recommendations</div><ul class='note-list'>" + ux_recs_html + "</ul>" if ux_recs_html else ""}
          {"<div class='section-title danger'><span></span>Technical Issues</div><ul class='note-list issues'>" + technical_issues_html + "</ul>" if technical_issues_html else ""}
        </article>"""

    total = len(all_results)
    avg_seo = round(sum(ai_score(r["ai_result"], r["features"], "seo_score") for r in all_results) / total) if total else 0
    avg_content = round(sum(ai_score(r["ai_result"], r["features"], "content_quality_score") for r in all_results) / total) if total else 0
    avg_ux = round(sum(ai_score(r["ai_result"], r["features"], "ux_score") for r in all_results) / total) if total else 0

    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'unsafe-inline';">
  <title>Secure Website Intelligence Engine - Results</title>
  <style>
    :root {{
      --bg:#101113; --panel:#181a20; --panel-2:#20232b; --ink:#f5f0e8;
      --muted:#a7adba; --line:#343842; --green:#52d273; --amber:#f2b84b;
      --red:#ef6461; --violet:#9b7cff; --cyan:#5ec8d8;
    }}
    * {{ box-sizing:border-box; margin:0; padding:0 }}
    body {{
      font-family: Inter, ui-sans-serif, system-ui, Segoe UI, sans-serif;
      background:
        linear-gradient(135deg, rgba(82,210,115,.08), transparent 28%),
        linear-gradient(315deg, rgba(155,124,255,.10), transparent 32%),
        var(--bg);
      color:var(--ink);
      padding:28px;
    }}
    body::before {{
      content:""; position:fixed; inset:0; pointer-events:none; opacity:.12;
      background-image:linear-gradient(var(--line) 1px, transparent 1px), linear-gradient(90deg, var(--line) 1px, transparent 1px);
      background-size:42px 42px;
    }}
    .shell {{ position:relative; max-width:1280px; margin:0 auto }}
    .hero {{
      border:1px solid var(--line); border-radius:8px; padding:28px;
      background:linear-gradient(135deg, rgba(32,35,43,.96), rgba(18,19,23,.94));
      box-shadow:0 24px 80px rgba(0,0,0,.28); margin-bottom:18px;
    }}
    .kicker {{ color:var(--green); text-transform:uppercase; font-size:.72rem; font-weight:800; letter-spacing:.14em; margin-bottom:8px }}
    h1 {{ font-size:clamp(1.9rem, 4vw, 3.4rem); line-height:1; max-width:760px }}
    .sub {{ color:var(--muted); font-size:.98rem; max-width:820px; line-height:1.6; margin-top:12px }}
    .summary-row {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:12px; margin:18px 0 26px }}
    .stat {{
      background:linear-gradient(180deg, rgba(32,35,43,.94), rgba(20,21,25,.96));
      border:1px solid var(--line); border-radius:8px; padding:18px 18px 16px;
      box-shadow:0 14px 34px rgba(0,0,0,.18);
    }}
    .stat .val {{ font-size:2.15rem; font-weight:850; color:var(--green); line-height:1 }}
    .stat .lbl {{ font-size:.72rem; color:var(--muted); margin-top:8px; text-transform:uppercase; letter-spacing:.1em }}
    .card {{
      background:linear-gradient(180deg, rgba(27,29,36,.98), rgba(20,21,26,.98));
      border:1px solid var(--line); border-radius:8px; padding:24px; margin-bottom:18px;
      box-shadow:0 18px 54px rgba(0,0,0,.22);
    }}
    .card-header {{ display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:18px; margin-bottom:18px }}
    .eyebrow {{ color:var(--cyan); font-size:.7rem; font-weight:800; text-transform:uppercase; letter-spacing:.14em; margin-bottom:6px }}
    .card-title {{ font-size:1.25rem; font-weight:800; line-height:1.25 }}
    .card-url {{ font-size:.78rem; color:var(--muted); word-break:break-all; margin-top:6px }}
    .badges {{ display:flex; flex-wrap:wrap; gap:8px; justify-content:flex-end }}
    .badge {{ background:#111318; border:1px solid var(--line); padding:6px 10px; border-radius:6px; font-size:.75rem; font-weight:800 }}
    .scores {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(132px,1fr)); gap:10px; margin-bottom:18px }}
    .score-box {{ background:#111318; border:1px solid #2b3039; border-radius:8px; padding:13px; min-height:96px }}
    .score-label {{ font-size:.68rem; color:var(--muted); text-transform:uppercase; letter-spacing:.1em; font-weight:800 }}
    .score-value {{ font-size:2rem; line-height:1.1; font-weight:900; margin:8px 0 10px }}
    .score-value.neutral {{ color:var(--violet) }}
    .mini-bar,.bar {{ overflow:hidden; background:#292d35; border-radius:99px }}
    .mini-bar {{ height:5px }}
    .mini-bar span,.bar-fill {{ display:block; height:100%; border-radius:99px }}
    .bar-wrap {{ margin-bottom:18px }}
    .bar-label {{ font-size:.72rem; color:var(--muted); margin-bottom:7px; text-transform:uppercase; letter-spacing:.1em; font-weight:800 }}
    .bar {{ height:10px }}
    .summary {{
      display:flex; gap:12px; align-items:flex-start; color:#d8d1c7; background:#12151a;
      border:1px solid var(--line); border-left:4px solid var(--violet); border-radius:8px;
      padding:13px 14px; font-size:.92rem; line-height:1.55; margin:16px 0;
    }}
    .summary span {{ color:var(--violet); text-transform:uppercase; font-size:.68rem; font-weight:900; letter-spacing:.12em; padding-top:3px }}
    .section-title {{ display:flex; align-items:center; gap:8px; font-size:.72rem; font-weight:900; text-transform:uppercase; letter-spacing:.1em; color:var(--muted); margin:18px 0 9px }}
    .section-title span {{ width:8px; height:8px; background:var(--cyan); border-radius:2px }}
    .section-title.priority {{ color:var(--green) }}
    .section-title.priority span {{ background:var(--green) }}
    .section-title.danger {{ color:var(--red) }}
    .section-title.danger span {{ background:var(--red) }}
    .tags {{ display:flex; flex-wrap:wrap; gap:7px; margin-bottom:8px }}
    .tag {{ background:#111318; border:1px solid #3a3f4a; border-radius:6px; padding:5px 10px; font-size:.8rem }}
    .tag.accent {{ border-color:var(--amber); color:var(--amber) }}
    .tag.cta {{ border-color:var(--green); color:var(--green) }}
    .signals {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:8px; margin:16px 0 }}
    .signals span {{ background:#111318; border:1px solid #2d323b; border-radius:8px; padding:10px; font-size:.77rem; color:#d5d0c8 }}
    ul, ol {{ list-style:none; padding:0 }}
    li {{ padding:8px 0; font-size:.9rem; line-height:1.45; border-bottom:1px solid #303541 }}
    li:last-child {{ border-bottom:none }}
    .action-list {{ display:grid; gap:8px }}
    .action-list li {{ background:#111b16; border:1px solid rgba(82,210,115,.28); border-radius:8px; padding:12px 13px }}
    .action-list strong {{ color:var(--green) }}
    .note-list {{ background:#12151a; border:1px solid var(--line); border-radius:8px; padding:4px 14px }}
    .note-list.issues {{ border-color:rgba(239,100,97,.34) }}
    footer {{ text-align:center; font-size:.75rem; color:#777f8d; margin-top:40px }}
    @media (max-width:720px) {{ body {{ padding:14px }} .hero,.card {{ padding:18px }} .summary {{ display:block }} .summary span {{ display:block; margin-bottom:6px }} }}
  </style>
</head>
<body>
  <main class="shell">
  <section class="hero">
    <div class="kicker">Secure AI Website Audit</div>
    <h1>Website Intelligence Report</h1>
    <p class="sub">Target: {e(TARGET_URL)} - {e(total)} page(s) analysed with secure crawling, SEO extraction, and local AI recommendations.</p>
  </section>

  <div class="summary-row">
    <div class="stat"><div class="val">{e(total)}</div><div class="lbl">Pages Analysed</div></div>
    <div class="stat"><div class="val">{e(avg_seo)}</div><div class="lbl">Avg SEO Score</div></div>
    <div class="stat"><div class="val">{e(avg_content)}</div><div class="lbl">Avg Content Score</div></div>
    <div class="stat"><div class="val">{e(avg_ux)}</div><div class="lbl">Avg UX Score</div></div>
  </div>

  {cards_html}

  <footer>Secure Website Intelligence Engine - Chiheb Bahri, Rissen Guermzei,
  Najmedine Zahra, Skandar Turki, Mouheb Oueslati - AY 2025-2026</footer>
  </main>
</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(full_html)

    print(f"\n  Dashboard saved -> {output_file}")
    print("    Open it in your browser.")


def main():
    print("╔══════════════════════════════════════════════╗")
    print("║    Secure Website Intelligence Engine v2.0   ║")
    print("╚══════════════════════════════════════════════╝")

    # ── Step 1: Crawl the website ──────────────────────────────
    pages = crawl(TARGET_URL, depth=CRAWL_DEPTH, delay=RATE_LIMIT)

    if not pages:
        print("\n❌ No pages fetched. Check your URL and internet connection.")
        return

    # ── Set up database ────────────────────────────────────────
    conn = init_database(DB_FILE)
    print(f"\n💾 Database ready: {DB_FILE}")

    # ── Steps 2, 3, 4 for each page ───────────────────────────
    all_results = []

    for i, page in enumerate(pages, start=1):
        print(f"\n─── Analysing page {i}/{len(pages)}: {page['url'][:60]} ───")

        # Step 2: Sanitize (remove PII)
        clean_text = sanitize(page["text"])
        print("  ✓ PII sanitized")

        # Step 3a: Extract keywords and signals
        features = extract_features({**page, "text": clean_text})
        print(f"  ✓ Website intelligence signals extracted — top keyword: "
              f"'{features['top_keywords'][0][0] if features['top_keywords'] else 'none'}'")

        # Step 3b: Sentiment analysis
        sentiment = analyze_sentiment(clean_text)
        print(f"  ✓ Sentiment: {sentiment['label']} ({sentiment['compound']})")

        # Step 3c: Ask the local AI for insights
        print(f"  🤖 Asking AI ({OLLAMA_MODEL})...")
        ai_result = ask_ai(features, sentiment, page["url"])
        print(f"  ✓ AI SEO score: {ai_result.get('seo_score', features['seo_score'])}/100")

        # Step 4a: Save to database
        save_to_database(conn, page, sentiment, ai_result, features)
        print("  ✓ Saved to database")

        all_results.append({
            "url":      page["url"],
            "title":    page["title"],
            "sentiment": sentiment,
            "features":  features,
            "ai_result": ai_result,
        })

    conn.close()

    # ── Step 4b: Build the HTML dashboard ─────────────────────
    print("\n📊 Building dashboard...")
    build_dashboard(all_results, DASHBOARD)

    print("\n✅ All done!")
    print(f"   📁 Database : {DB_FILE}")
    print(f"   🌐 Dashboard: {DASHBOARD}  ← open this in your browser")


# This is the standard Python way to say "run main() when you execute this file"
if __name__ == "__main__":
    main()
