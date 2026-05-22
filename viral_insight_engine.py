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

TARGET_URL   = "https://blog.python.org"   # ← put your target website here
CRAWL_DEPTH  = 1                       # how many "levels" of links to follow
RATE_LIMIT   = 2.0                     # seconds to wait between each request (be polite!)
OLLAMA_MODEL = "qwen2.5"               # the AI model name in Ollama
OLLAMA_URL   = "http://localhost:11434/api/chat"  # local Ollama server
DB_FILE      = "results.db"            # SQLite database file
DASHBOARD    = "dashboard.html"        # output dashboard file


# ══════════════════════════════════════════════════════════════════
#  STEP 1 — CRAWLER
#  Fetches web pages safely and politely
# ══════════════════════════════════════════════════════════════════

def fetch_page(url, session):
    """
    Download one webpage and return its text + links.
    Returns None if anything goes wrong.
    """
    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()  # raises an error for 404, 500, etc.

        # Only process HTML pages (skip PDFs, images, etc.)
        if "text/html" not in response.headers.get("Content-Type", ""):
            return None

        soup = BeautifulSoup(response.text, "html.parser")

        # Get the page title
        title = soup.title.string.strip() if soup.title else url

        # Remove script/style tags so we only get readable text
        for tag in soup(["script", "style", "nav", "footer", "header"]):
            tag.decompose()

        # Extract all visible text
        text = " ".join(soup.stripped_strings)

        # Collect all links on this page
        links = []
        for a in soup.find_all("a", href=True):
            full_link = urljoin(url, a["href"])
            links.append(full_link)

        return {"url": url, "title": title, "text": text, "links": links}

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
    Analyse the page text and return a dictionary of useful signals.
    """
    text = page["text"].lower()

    # Split into individual words, remove punctuation
    words = re.findall(r"\b[a-z]{3,}\b", text)
    # Remove stop words
    keywords = [w for w in words if w not in STOP_WORDS]

    # Count how often each keyword appears
    keyword_counts = Counter(keywords)
    top_keywords = keyword_counts.most_common(10)

    # Find viral signal words in the text
    viral_found = [w for w in keywords if w in VIRAL_WORDS]

    # Basic text statistics
    sentences = re.split(r"[.!?]+", page["text"])
    sentences = [s.strip() for s in sentences if s.strip()]
    avg_sentence_length = (
        sum(len(s.split()) for s in sentences) / len(sentences)
    ) if sentences else 0

    return {
        "top_keywords": top_keywords,                   # e.g. [("python", 8), ...]
        "viral_words":  list(set(viral_found)),          # e.g. ["trending", "best"]
        "viral_score":  min(len(viral_found) * 5, 100), # 0-100
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

def ask_ai(features, sentiment, url):
    """
    Send our extracted features to the local Ollama AI model.
    The model returns structured recommendations in JSON format.
    Data NEVER leaves your machine — full privacy!
    """
    # Build a clear prompt for the AI
    keywords_str = ", ".join(f"{w}({c})" for w, c in features["top_keywords"][:8])
    prompt = f"""You are a web analyst. Analyze this webpage data and reply ONLY with JSON.

URL: {url}
Top Keywords: {keywords_str}
Viral Words Found: {features["viral_words"]}
Sentiment: {sentiment["label"]} (score: {sentiment["compound"]})
Avg Sentence Length: {features["avg_sentence_length"]} words
Viral Signal Score: {features["viral_score"]}/100

Reply with this exact JSON structure (no extra text):
{{
  "virality_score": <number 0-100>,
  "summary": "<one sentence summary of the page>",
  "strengths": ["<strength 1>", "<strength 2>"],
  "improvements": ["<improvement 1>", "<improvement 2>", "<improvement 3>"]
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

        return json.loads(content)

    except requests.ConnectionError:
        print("  ⚠ Cannot connect to Ollama. Is it running? (ollama serve)")
        return _fallback_ai_result()
    except (json.JSONDecodeError, KeyError) as e:
        print(f"  ⚠ AI returned unexpected format: {e}")
        return _fallback_ai_result()
    except Exception as e:
        print(f"  ⚠ AI error: {e}")
        return _fallback_ai_result()


def _fallback_ai_result():
    """Return a safe default when Ollama is unavailable."""
    return {
        "virality_score": 0,
        "summary": "AI analysis unavailable (Ollama not running).",
        "strengths": [],
        "improvements": ["Start Ollama and re-run to get AI-powered recommendations."],
    }


# ══════════════════════════════════════════════════════════════════
#  STEP 4a — DATABASE STORAGE
#  Saves everything to a simple SQLite database file
# ══════════════════════════════════════════════════════════════════

def init_database(db_file):
    """Create the database table if it doesn't exist yet."""
    conn = sqlite3.connect(db_file)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            url             TEXT,
            title           TEXT,
            sentiment_label TEXT,
            sentiment_score REAL,
            virality_score  INTEGER,
            top_keywords    TEXT,
            ai_summary      TEXT,
            improvements    TEXT,
            analyzed_at     TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    return conn


def save_to_database(conn, url, title, sentiment, ai_result, features):
    """Save one page's results into the database."""
    conn.execute(
        """INSERT INTO results
           (url, title, sentiment_label, sentiment_score,
            virality_score, top_keywords, ai_summary, improvements)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            url,
            title,
            sentiment["label"],
            sentiment["compound"],
            ai_result.get("virality_score", 0),
            json.dumps([kw for kw, _ in features["top_keywords"][:5]]),
            ai_result.get("summary", ""),
            json.dumps(ai_result.get("improvements", [])),
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


def build_dashboard(all_results, output_file):
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
    ul {{ list-style:none; padding:0 }}
    li {{ padding:6px 0; font-size:.85rem; border-bottom:1px solid #2d3454 }}
    li:last-child {{ border-bottom:none }}
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

def main():
    print("╔══════════════════════════════════════════════╗")
    print("║    Secure Viral Insight Engine  v1.0         ║")
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
        print(f"  ✓ Features extracted — top keyword: "
              f"'{features['top_keywords'][0][0] if features['top_keywords'] else 'none'}'")

        # Step 3b: Sentiment analysis
        sentiment = analyze_sentiment(clean_text)
        print(f"  ✓ Sentiment: {sentiment['label']} ({sentiment['compound']})")

        # Step 3c: Ask the local AI for insights
        print(f"  🤖 Asking AI ({OLLAMA_MODEL})...")
        ai_result = ask_ai(features, sentiment, page["url"])
        print(f"  ✓ AI virality score: {ai_result.get('virality_score', '?')}/100")

        # Step 4a: Save to database
        save_to_database(conn, page["url"], page["title"], sentiment, ai_result, features)
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
