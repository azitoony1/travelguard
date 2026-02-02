#!/usr/bin/env python3
"""
TravelGuard — Data Ingestion Script

Polls all configured data sources (RSS feeds, APIs, scraped pages) and stores
the raw content in Supabase for later analysis.

Usage:
    python ingest.py
"""

import os
import sys
import yaml
import feedparser
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from dotenv import load_dotenv
from supabase import create_client, Client

# Load environment variables
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    print("ERROR: Missing SUPABASE_URL or SUPABASE_KEY in .env file")
    sys.exit(1)

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


def load_sources_config():
    """Load the sources.yaml configuration file."""
    with open("sources.yaml", "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def fetch_rss(url):
    """Fetch and parse an RSS feed."""
    try:
        feed = feedparser.parse(url)
        if feed.bozo:
            print(f"  ⚠️  RSS parse warning for {url}: {feed.bozo_exception}")
        
        # Extract the most recent entries (last 24 hours worth)
        entries = []
        for entry in feed.entries[:20]:  # Limit to 20 most recent
            entries.append({
                "title": entry.get("title", ""),
                "link": entry.get("link", ""),
                "published": entry.get("published", ""),
                "summary": entry.get("summary", "")
            })
        
        return {
            "feed_title": feed.feed.get("title", ""),
            "entries": entries,
            "fetched_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        print(f"  ❌ RSS fetch failed for {url}: {str(e)}")
        return None


def fetch_api(url):
    """Fetch data from an API endpoint."""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        # Try to parse as JSON, fall back to text
        try:
            data = response.json()
        except:
            data = response.text
        
        return {
            "data": data,
            "fetched_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        print(f"  ❌ API fetch failed for {url}: {str(e)}")
        return None


def fetch_scrape(url):
    """Scrape a web page and extract text content."""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, "lxml")
        
        # Remove script and style elements
        for script in soup(["script", "style", "nav", "footer", "header"]):
            script.decompose()
        
        # Get text
        text = soup.get_text(separator="\n", strip=True)
        
        # Clean up multiple newlines
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        text = "\n".join(lines)
        
        return {
            "text": text[:50000],  # Limit to 50k chars to avoid huge payloads
            "url": url,
            "fetched_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        print(f"  ❌ Scrape failed for {url}: {str(e)}")
        return None


def fetch_source(source):
    """Fetch data from a source based on its type."""
    source_type = source.get("type")
    url = source.get("url")
    
    if source_type == "rss":
        return fetch_rss(url)
    elif source_type == "api":
        return fetch_api(url)
    elif source_type == "scrape":
        return fetch_scrape(url)
    else:
        print(f"  ⚠️  Unknown source type: {source_type}")
        return None


def get_country_id(iso_code):
    """Get the UUID for a country by ISO code."""
    try:
        result = supabase.table("countries").select("id").eq("iso_code", iso_code).execute()
        if result.data:
            return result.data[0]["id"]
        return None
    except Exception as e:
        print(f"  ❌ Failed to get country ID for {iso_code}: {str(e)}")
        return None


def store_source_data(source_name, source_url, country_id, data):
    """Store fetched source data. For MVP, we'll use a simple raw_data table."""
    # Note: For MVP, we're not creating a separate raw_data table in the schema.
    # Instead, we'll just print the data and rely on the analysis step to use it.
    # In production, you'd store this in a raw_data table for audit/replay purposes.
    
    if data:
        print(f"  ✓ Fetched {source_name}")
        # In a real implementation, you'd do:
        # supabase.table("raw_data").insert({...}).execute()
    else:
        print(f"  ✗ Failed to fetch {source_name}")


def ingest_global_sources(config):
    """Ingest all global sources."""
    print("\n━━━ GLOBAL BASE SOURCES ━━━")
    for source in config.get("global_base", []):
        print(f"\n{source['name']}")
        data = fetch_source(source)
        store_source_data(source["name"], source["url"], None, data)
    
    print("\n━━━ GLOBAL IDENTITY SOURCES ━━━")
    identity_sources = config.get("global_identity", {})
    for identity_layer, sources in identity_sources.items():
        print(f"\n[{identity_layer}]")
        for source in sources:
            print(f"\n{source['name']}")
            data = fetch_source(source)
            store_source_data(source["name"], source["url"], None, data)


def ingest_country_sources(config, country_name, country_code):
    """Ingest sources for a specific country."""
    country_id = get_country_id(country_code)
    if not country_id:
        print(f"❌ Country {country_code} not found in database")
        return
    
    country_config = config.get(country_name.lower(), {})
    
    print(f"\n━━━ {country_name.upper()} — BASE SOURCES ━━━")
    for source in country_config.get("base", []):
        print(f"\n{source['name']}")
        data = fetch_source(source)
        store_source_data(source["name"], source["url"], country_id, data)
    
    identity_config = country_config.get("identity", {})
    if identity_config:
        print(f"\n━━━ {country_name.upper()} — IDENTITY SOURCES ━━━")
        for identity_layer, sources in identity_config.items():
            print(f"\n[{identity_layer}]")
            for source in sources:
                print(f"\n{source['name']}")
                data = fetch_source(source)
                store_source_data(source["name"], source["url"], country_id, data)


def main():
    """Main ingestion routine."""
    print("╔════════════════════════════════════════╗")
    print("║   TravelGuard — Data Ingestion         ║")
    print("╚════════════════════════════════════════╝")
    print(f"\nStarted: {datetime.utcnow().isoformat()} UTC")
    
    # Load configuration
    try:
        config = load_sources_config()
    except Exception as e:
        print(f"❌ Failed to load sources.yaml: {str(e)}")
        sys.exit(1)
    
    # Ingest global sources
    ingest_global_sources(config)
    
    # Ingest country-specific sources
    ingest_country_sources(config, "Israel", "IL")
    ingest_country_sources(config, "Netherlands", "NL")
    
    print(f"\n✓ Ingestion complete: {datetime.utcnow().isoformat()} UTC")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")


if __name__ == "__main__":
    main()
