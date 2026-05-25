# Secure AI Website Intelligence Engine

A secure AI-powered website analysis tool that crawls a target website, extracts SEO and UX signals, sanitizes sensitive data, generates local AI recommendations with Ollama, stores results in SQLite, and creates a professional HTML dashboard.

## Features

- Secure crawler with `robots.txt` checking and rate limiting
- Same-domain crawling to avoid uncontrolled scanning
- SEO-aware extraction: title, meta description, headings, links, images, alt text, canonical tags, Open Graph tags, schema markup, and CTAs
- PII sanitization for emails, phone numbers, IP addresses, and SSN-like values
- SEO, content, technical, UX, and engagement scoring
- Local AI recommendations through Ollama
- Specific priority action plan for each analyzed page
- SQLite result storage
- Self-contained HTML dashboard

## Requirements

- Python 3.10+
- Ollama installed locally
- Qwen model pulled in Ollama

Install Python packages:

```powershell
pip install -r requirements.txt
```

Install and start Ollama:

```powershell
ollama pull qwen2.5
ollama serve
```

## Run

Edit `TARGET_URL` in `viral_insight_engine.py` if needed, then run:

```powershell
python viral_insight_engine.py
```

Open the generated dashboard:

```powershell
start dashboard.html
```

## Project Pipeline

```text
Website
↓
Secure Crawler
↓
SEO-Aware Extraction
↓
PII Sanitizer
↓
Feature Scoring
↓
Local AI Analysis
↓
SQLite Database
↓
HTML Dashboard
```

## Security Notes

The project is designed for responsible academic use. It respects `robots.txt`, limits crawling speed, sanitizes sensitive data before analysis, avoids cloud AI by using local Ollama, and escapes dashboard output to reduce XSS risk.
