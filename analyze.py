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
from datetime import datetime
from dotenv import load_dotenv
from supabase import create_client, Client
from google import genai

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


def build_analysis_prompt(country_name, identity_layer, nsc_level=None):
    """Build the Gemini analysis prompt."""
    
    base_prompt = f"""You are a travel security analyst. Analyze the current threat situation in {country_name} for {'general travelers' if identity_layer == 'base' else 'Jewish and Israeli travelers'}.

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

    if identity_layer == "jewish_israeli":
        base_prompt += f"""
IDENTITY-SPECIFIC ANALYSIS:
You are analyzing threats specifically for Jewish and Israeli travelers. Consider:
- Antisemitic incidents and hate crimes
- Legal barriers (countries that ban Israeli passport holders)
- Institutional hostility toward Jews/Israelis
- Consular protection availability (Israeli embassy presence)
- Community infrastructure (synagogues, kosher food, Jewish organizations)
- Recent protests or violence targeting Jews/Israelis
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


def analyze_country(country_name, identity_layer="base"):
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
    prompt = build_analysis_prompt(country_name, identity_layer, nsc_level)
    
    # Note: In a real implementation, you'd include the actual ingested data here
    # For now, we're using Gemini's knowledge + the NSC warnings
    prompt += f"\n\nAnalyze {country_name} based on your knowledge of current events as of February 2026."
    
    try:
        print("Sending request to Gemini 2.5 Pro...")
        response = client.models.generate_content(
            model='gemini-2.5-pro',
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
        
        print("✓ Analysis complete")
        print(f"  Armed Conflict: {analysis.get('armed_conflict')}")
        print(f"  Terrorism: {analysis.get('terrorism')}")
        print(f"  Crime: {analysis.get('crime')}")
        
        return analysis
        
    except json.JSONDecodeError as e:
        print(f"❌ JSON parsing failed: {e}")
        print(f"Raw response: {response_text[:500]}")
        return None
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        return None


def calculate_total_score(category_scores):
    """
    Apply veto logic to calculate total country score.
    
    Veto-class categories: Armed Conflict, Regional Instability, Terrorism, Civil Strife
    If any veto category is RED or PURPLE, total score is at least that level.
    """
    
    veto_categories = ["armed_conflict", "regional_instability", "terrorism", "civil_strife"]
    
    # Score hierarchy
    level_hierarchy = {"GREEN": 1, "YELLOW": 2, "ORANGE": 3, "RED": 4, "PURPLE": 5}
    
    max_veto_level = 1  # Start at GREEN
    
    # Check veto categories
    for category in veto_categories:
        score = category_scores.get(category, "GREEN")
        level_value = level_hierarchy.get(score, 1)
        if level_value > max_veto_level:
            max_veto_level = level_value
    
    # Convert back to color
    reverse_hierarchy = {1: "GREEN", 2: "YELLOW", 3: "ORANGE", 4: "RED", 5: "PURPLE"}
    return reverse_hierarchy[max_veto_level]


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
        "scored_at": datetime.utcnow().isoformat()
    }
    
    try:
        # Upsert (update if exists, insert if not)
        result = supabase.table("scores").upsert(data).execute()
        print(f"✓ Stored in database: {total_score}")
        return True
    except Exception as e:
        print(f"❌ Database error: {e}")
        return False


def get_country_id(iso_code):
    """Get country UUID from database."""
    try:
        result = supabase.table("countries").select("id").eq("iso_code", iso_code).execute()
        if result.data:
            return result.data[0]["id"]
        return None
    except Exception as e:
        print(f"❌ Failed to get country ID: {e}")
        return None


def main():
    """Main analysis routine."""
    
    print("╔════════════════════════════════════════╗")
    print("║   TravelGuard — AI Analysis (Gemini)   ║")
    print("╚════════════════════════════════════════╝")
    print(f"\nStarted: {datetime.utcnow().isoformat()} UTC\n")
    
    # MVP: Analyze Israel and Netherlands
    countries = [
        ("Israel", "IL"),
        ("Netherlands", "NL")
    ]
    
    for country_name, iso_code in countries:
        country_id = get_country_id(iso_code)
        if not country_id:
            print(f"❌ Country {country_name} not found in database")
            continue
        
        # Analyze base layer
        print(f"\n🌍 BASE LAYER: {country_name}")
        base_analysis = analyze_country(country_name, "base")
        if base_analysis:
            store_analysis(country_id, "base", base_analysis)
        
        # Analyze Jewish/Israeli layer
        print(f"\n✡️  JEWISH/ISRAELI LAYER: {country_name}")
        identity_analysis = analyze_country(country_name, "jewish_israeli")
        if identity_analysis:
            store_analysis(country_id, "jewish_israeli", identity_analysis)
    
    print(f"\n{'='*60}")
    print(f"✓ Analysis complete: {datetime.utcnow().isoformat()} UTC")
    print('='*60)


if __name__ == "__main__":
    main()
