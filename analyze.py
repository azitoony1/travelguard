#!/usr/bin/env python3
"""
TravelGuard — AI Analysis Pipeline (Gemini)

Takes raw data from ingestion and generates:
- 5-level threat scores (GREEN/YELLOW/ORANGE/RED/PURPLE) per category
- Base layer assessment (general travellers)
- Jewish/Israeli identity layer assessment
- AI summaries and recommendations

Usage:
    python analyze.py
"""

import os
import sys
import json
from datetime import datetime, timezone
from dotenv import load_dotenv
from supabase import create_client, Client
from google import genai
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib

# Load environment variables
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not all([SUPABASE_URL, SUPABASE_KEY, GEMINI_API_KEY]):
    print("ERROR: Missing environment variables")
    sys.exit(1)

# Initialize clients
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
client = genai.Client(api_key=GEMINI_API_KEY)


def load_israeli_nsc_warnings():
    """Load Israeli NSC warnings config."""
    import yaml
    try:
        with open("israeli_nsc_warnings.yaml", "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            return data.get("countries", {})
    except FileNotFoundError:
        return {}


def get_nsc_level_for_country(country_name, nsc_data):
    """Get NSC threat level for a country."""
    return nsc_data.get(country_name, {}).get("level", None)


def build_analysis_prompt(country_name, identity_layer, nsc_level=None, base_analysis=None):
    """Build the Gemini analysis prompt."""
    
    base_prompt = f"""You are a travel security analyst. Analyze the current threat situation in {country_name} for {'general travelers' if identity_layer == 'base' else ('solo women travelers' if identity_layer == 'solo_women' else 'Jewish and Israeli travelers')}.

IMPORTANT: Use the 5-level threat scale:
- GREEN (1): Safe / Normal conditions
- YELLOW (2): Exercise Caution / Minor concerns
- ORANGE (3): Heightened Risk / Significant concerns  
- RED (4): High Risk / Reconsider travel
- PURPLE (5): Extreme Risk / Do not travel (war zones, active genocide, zero consular protection)

Analyze these 7 threat categories independently:
1. Armed Conflict
2. Regional Instability
3. Terrorism
4. Civil Strife
5. Crime
6. Health
7. Infrastructure

For each category, assign a threat level (GREEN/YELLOW/ORANGE/RED/PURPLE) based on current conditions.

"""

    if identity_layer == "solo_women":
        base_prompt += f"""
IDENTITY-SPECIFIC ANALYSIS:
You are analyzing threats specifically for SOLO WOMEN TRAVELERS.

CRITICAL: Use the base layer assessment as your starting point and ONLY adjust categories where there are REAL gender-specific threats.

Base layer assessment for reference:
{format_base_analysis(base_analysis) if base_analysis else "Not available"}

Consider gender-specific factors:
- Gender-based violence and harassment
- Sexual assault rates and legal protections
- Cultural attitudes toward women (dress codes, behavior restrictions)
- Women's rights and freedoms (can women travel alone legally?)
- Safety of public transport/taxis for women
- Availability of women-only accommodations/transport
- Police response to crimes against women
- Healthcare access for women

IMPORTANT:
- Most categories should be IDENTICAL to base layer unless there's a clear gender-specific difference
- Don't invent differences where none exist  
- Regional Instability, Infrastructure, Health are usually the same UNLESS they specifically affect women differently
- Crime and Civil Strife are most likely to differ due to gender-based threats
"""

    elif identity_layer == "jewish_israeli":
        base_prompt += f"""
IDENTITY-SPECIFIC ANALYSIS:
You are analyzing threats specifically for Jewish and Israeli travelers. 

CRITICAL: Use the base layer assessment as your starting point and ONLY adjust categories where there are REAL identity-specific threats.

Base layer assessment for reference:
{format_base_analysis(base_analysis) if base_analysis else "Not available"}

Consider identity-specific factors:
- Antisemitic incidents and hate crimes
- Legal barriers (countries that ban Israeli passport holders)
- Institutional hostility toward Jews/Israelis
- Consular protection availability (Israeli embassy presence)
- Community infrastructure (synagogues, kosher food, Jewish organizations)
- Recent protests or violence targeting Jews/Israelis

IMPORTANT: 
- Most categories should be IDENTICAL to the base layer unless there's a clear identity-specific difference
- Don't invent differences where none exist
- Regional Instability, Infrastructure, Health are almost always the same as base layer
- Only Armed Conflict, Terrorism, Civil Strife, and Crime might differ if there's targeted antisemitism
"""
        
        if nsc_level:
            base_prompt += f"""
Israeli National Security Council (NSC) Travel Warning Level: {nsc_level}/4
(1=Safe, 2=Caution, 3=Reconsider, 4=Do Not Travel)

Use this as a baseline but adjust based on current news. If recent events contradict the NSC level, note this discrepancy.
"""

    base_prompt += """
Return your analysis as valid JSON with this exact structure:
{
  "armed_conflict": "GREEN|YELLOW|ORANGE|RED|PURPLE",
  "regional_instability": "GREEN|YELLOW|ORANGE|RED|PURPLE",
  "terrorism": "GREEN|YELLOW|ORANGE|RED|PURPLE",
  "civil_strife": "GREEN|YELLOW|ORANGE|RED|PURPLE",
  "crime": "GREEN|YELLOW|ORANGE|RED|PURPLE",
  "health": "GREEN|YELLOW|ORANGE|RED|PURPLE",
  "infrastructure": "GREEN|YELLOW|ORANGE|RED|PURPLE",
  "reasoning": "Brief explanation of key threats driving the scores",
  "summary": "2-3 paragraph plain-English summary of the current situation",
  "recommendations": {
    "movement_access": "One sentence recommendation",
    "emergency_preparedness": "One sentence recommendation",
    "communications": "One sentence recommendation",
    "health_medical": "One sentence recommendation",
    "crime_personal_safety": "One sentence recommendation",
    "travel_logistics": "One sentence recommendation"
  }
}

Be specific, factual, and direct. Cite recent incidents when relevant.
"""
    
    return base_prompt


def format_base_analysis(analysis):
    """Format base analysis for inclusion in identity prompt."""
    if not analysis:
        return "Not available"
    
    return f"""
Armed Conflict: {analysis.get('armed_conflict', 'N/A')}
Regional Instability: {analysis.get('regional_instability', 'N/A')}
Terrorism: {analysis.get('terrorism', 'N/A')}
Civil Strife: {analysis.get('civil_strife', 'N/A')}
Crime: {analysis.get('crime', 'N/A')}
Health: {analysis.get('health', 'N/A')}
Infrastructure: {analysis.get('infrastructure', 'N/A')}
"""


def analyze_country(country_name, identity_layer="base", base_analysis=None):
    """Run Gemini analysis for a country."""
    
    print(f"\n{'='*60}")
    print(f"Analyzing: {country_name} ({identity_layer} layer)")
    print('='*60)
    
    # Load NSC warnings if analyzing Jewish/Israeli layer
    nsc_data = {}
    nsc_level = None
    if identity_layer == "jewish_israeli":
        nsc_data = load_israeli_nsc_warnings()
        nsc_level = get_nsc_level_for_country(country_name, nsc_data)
        if nsc_level:
            print(f"Israeli NSC Warning Level: {nsc_level}/4")
    
    # Build prompt
    prompt = build_analysis_prompt(country_name, identity_layer, nsc_level, base_analysis)
    
    # Note: In a real implementation, you'd include the actual ingested data here
    # For now, we're using Gemini's knowledge + the NSC warnings
    prompt += f"\n\nAnalyze {country_name} based on your knowledge of current events as of February 2026."
    
    try:
        print("Sending request to Gemini 2.5 Flash...")
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt
        )
        
        # Parse JSON response
        response_text = response.text.strip()
        
        # Remove markdown code fences if present
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        
        response_text = response_text.strip()
        
        analysis = json.loads(response_text)
        
        print("[OK] Analysis complete")
        print(f"  Armed Conflict: {analysis.get('armed_conflict')}")
        print(f"  Terrorism: {analysis.get('terrorism')}")
        print(f"  Crime: {analysis.get('crime')}")
        
        return analysis
        
    except json.JSONDecodeError as e:
        print(f"[X] JSON parsing failed: {e}")
        print(f"Raw response: {response_text[:500]}")
        return None
    except Exception as e:
        print(f"[X] Analysis failed: {e}")
        return None


def calculate_total_score(category_scores):
    """
    Apply veto logic to calculate total country score.
    
    Veto-class categories: Armed Conflict, Regional Instability, Terrorism, Civil Strife
    
    Rules:
    - If any veto category is RED or PURPLE → total is at least that level
    - If highest veto category is ORANGE or below → use weighted average of all categories
    - Non-veto categories (Crime, Health, Infrastructure) never trigger veto
    """
    
    veto_categories = ["armed_conflict", "regional_instability", "terrorism", "civil_strife"]
    all_categories = ["armed_conflict", "regional_instability", "terrorism", "civil_strife", 
                      "crime", "health", "infrastructure"]
    
    # Score hierarchy
    level_hierarchy = {"GREEN": 1, "YELLOW": 2, "ORANGE": 3, "RED": 4, "PURPLE": 5}
    reverse_hierarchy = {1: "GREEN", 2: "YELLOW", 3: "ORANGE", 4: "RED", 5: "PURPLE"}
    
    # Check if any veto category is RED or PURPLE
    max_veto_level = 1
    for category in veto_categories:
        score = category_scores.get(category, "GREEN")
        level_value = level_hierarchy.get(score, 1)
        if level_value >= 4:  # RED (4) or PURPLE (5)
            if level_value > max_veto_level:
                max_veto_level = level_value
    
    # If veto triggered (RED or PURPLE found), return that level
    if max_veto_level >= 4:
        return reverse_hierarchy[max_veto_level]
    
    # Otherwise, calculate weighted average
    # Veto categories count double
    total_weight = 0
    weighted_sum = 0
    
    for category in all_categories:
        score = category_scores.get(category, "GREEN")
        level_value = level_hierarchy.get(score, 1)
        weight = 2 if category in veto_categories else 1
        weighted_sum += level_value * weight
        total_weight += weight
    
    # Calculate average and round
    avg = weighted_sum / total_weight
    
    # Round to nearest level
    if avg <= 1.4:
        return "GREEN"
    elif avg <= 2.4:
        return "YELLOW"
    elif avg <= 3.4:
        return "ORANGE"
    elif avg <= 4.4:
        return "RED"
    else:
        return "PURPLE"


def store_analysis(country_id, identity_layer, analysis):
    """Store analysis results in Supabase."""
    
    total_score = calculate_total_score(analysis)
    
    data = {
        "country_id": country_id,
        "identity_layer": identity_layer,
        "total_score": total_score,
        "armed_conflict": analysis.get("armed_conflict"),
        "regional_instability": analysis.get("regional_instability"),
        "terrorism": analysis.get("terrorism"),
        "civil_strife": analysis.get("civil_strife"),
        "crime": analysis.get("crime"),
        "health": analysis.get("health"),
        "infrastructure": analysis.get("infrastructure"),
        "ai_summary": analysis.get("summary"),
        "veto_explanation": analysis.get("reasoning"),
        "recommendations": json.dumps(analysis.get("recommendations", {})),
        "scored_at": datetime.now(timezone.utc).isoformat()
    }
    
    try:
        # Use upsert with on_conflict parameter to update existing records
        result = supabase.table("scores").upsert(
            data,
            on_conflict="country_id,identity_layer"
        ).execute()
        
        print(f"[OK] Stored in database: {total_score}")
        return True
    except Exception as e:
        print(f"[X] Database error: {e}")
        return False


def get_country_id(iso_code):
    """Get country UUID from database."""
    try:
        result = supabase.table("countries").select("id").eq("iso_code", iso_code).execute()
        if result.data:
            return result.data[0]["id"]
        return None
    except Exception as e:
        print(f"[X] Failed to get country ID: {e}")
        return None


def should_analyze_country(country_name, country_id):
    """
    Determine if a country needs re-analysis based on whether
    new headlines have been ingested since last analysis.
    
    Always analyze if country has never been scored before.
    """
    
    # Check if country has ever been analyzed
    try:
        result = supabase.table("scores").select("id").eq("country_id", country_id).limit(1).execute()
        
        if not result.data:
            # Never analyzed before - always analyze
            print(f"  [NEW] {country_name} has never been analyzed - will analyze now")
            return True
            
    except Exception as e:
        print(f"  [!] Could not check analysis history: {e}")
        return True
    
    # Check if headlines file exists and has recent data for this country
    try:
        with open("latest_headlines.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            headlines = data.get("headlines", [])
            
            # Check if any headlines mention this country
            country_headlines = [h for h in headlines if country_name.lower() in h.lower()]
            
            if not country_headlines:
                print(f"  [i]  No new headlines for {country_name} - Using cached analysis")
                return False
            
            print(f"  [OK] Found {len(country_headlines)} new headlines for {country_name}")
            return True
            
    except FileNotFoundError:
        # No headlines file - analyze anyway (scheduled run)
        return True


def analyze_country_layers(country_name, country_id):
    """
    Analyze all three layers (base + jewish_israeli + solo_women) for a single country.
    Returns results for all layers.
    """
    results = []
    
    # Base layer
    print(f"\n[GENERAL] BASE LAYER: {country_name}")
    base_analysis = analyze_country(country_name, "base")
    if base_analysis:
        if store_analysis(country_id, "base", base_analysis):
            results.append(("base", base_analysis))
    
    # Jewish/Israeli layer (with base context)
    print(f"\n[JEWISH]  JEWISH/ISRAELI LAYER: {country_name}")
    identity_analysis = analyze_country(country_name, "jewish_israeli", base_analysis)
    if identity_analysis:
        if store_analysis(country_id, "jewish_israeli", identity_analysis):
            results.append(("jewish_israeli", identity_analysis))
    
    # Solo Women layer (with base context)
    print(f"\n[WOMEN]   SOLO WOMEN LAYER: {country_name}")
    women_analysis = analyze_country(country_name, "solo_women", base_analysis)
    if women_analysis:
        if store_analysis(country_id, "solo_women", women_analysis):
            results.append(("solo_women", women_analysis))
    
    return country_name, results


def main():
    """Main analysis routine with parallel processing."""
    
    print("="*44)
    print("   TravelGuard — AI Analysis (Gemini)   ")
    print("="*44)
    print(f"\nStarted: {datetime.now(timezone.utc).isoformat()} UTC\n")
    
    # MVP: 20 countries for global coverage
    countries = [
        ("Israel", "IL"),
        ("Netherlands", "NL"),
        ("USA", "US"),
        ("France", "FR"),
        ("United Kingdom", "GB"),
        ("Turkey", "TR"),
        ("Thailand", "TH"),
        ("Saudi Arabia", "SA"),
        ("Russia", "RU"),
        ("Democratic Republic of the Congo", "CD"),
        ("Nigeria", "NG"),
        ("Ukraine", "UA"),
        ("Brazil", "BR"),
        ("Australia", "AU"),
        ("China", "CN"),
        ("Egypt", "EG"),
        ("India", "IN"),
        ("Mexico", "MX"),
        ("South Africa", "ZA"),
        ("Poland", "PL"),
        ("Iran", "IR"),
        ("Libya", "LY")
    ]
    
    # Filter countries that need analysis (incremental updates)
    countries_to_analyze = []
    for country_name, iso_code in countries:
        country_id = get_country_id(iso_code)
        if not country_id:
            print(f"[X] Country {country_name} not found in database")
            continue
        
        # Check if analysis needed
        if should_analyze_country(country_name, country_id):
            countries_to_analyze.append((country_name, iso_code, country_id))
        else:
            print(f"[-]  Skipping {country_name} (no new data)")
    
    if not countries_to_analyze:
        print("\n[OK] No countries need re-analysis")
        print(f"[OK] Complete: {datetime.now(timezone.utc).isoformat()} UTC\n")
        return
    
    print(f"\n[*] Analyzing {len(countries_to_analyze)} countries in parallel...\n")
    
    # Analyze countries in parallel (max 10 threads)
    max_workers = min(10, len(countries_to_analyze))
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all country analyses
        future_to_country = {
            executor.submit(analyze_country_layers, name, cid): name
            for name, iso, cid in countries_to_analyze
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_country):
            country_name = future_to_country[future]
            try:
                name, results = future.result()
                print(f"\n[OK] Completed {name}: {len(results)} layers analyzed")
            except Exception as e:
                print(f"\n[X] {country_name} failed: {e}")
    
    print(f"\n{'='*60}")
    print(f"[OK] Analysis complete: {datetime.now(timezone.utc).isoformat()} UTC")
    print('='*60)


if __name__ == "__main__":
    main()
