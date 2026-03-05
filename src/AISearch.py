# ---------------------------------------------------------------------------------- #
#                            Part of the X3r0Day project.                            #
#              You are free to use, modify, and redistribute this code,              #
#          provided proper credit is given to the original project X3r0Day.          #
# ---------------------------------------------------------------------------------- #

#######################################################################################################
#      So This code basically uses an LLM to provide API keys based on user query cuz why not :3      #
#######################################################################################################

# ---------------------------------------------------------------------------------- #
#                                   DISCLAIMER                                       #
# ---------------------------------------------------------------------------------- #
# This tool is part of the X3r0Day Framework and is intended for educational         #
# security research, and defensive analysis purposes only.                           #
#                                                                                    #
# The script queries publicly available GitHub repository metadata and stores it     #
# locally for further analysis. It does not exploit, access, or modify any system.   #
#                                                                                    #
# Users are solely responsible for how this software is used. The authors of the     #
# X3r0Day project do not encourage or condone misuse, unauthorized access, or any    #
# activity that violates applicable laws, regulations, or the terms of service of    #
# any platform.                                                                      #
#                                                                                    #
# Always respect platform policies, rate limits, and the privacy of developers.      #
# If you discover sensitive information or exposed credentials during research,      #
# follow responsible disclosure practices and notify the affected parties by         #
# opening **Issues**                                                                 #
#                                                                                    #
# By using this software, you acknowledge that you understand these conditions and   #
# accept full responsibility for your actions.                                       #
#                                                                                    #
# Project: X3r0Day Framework                                                         #
# Author: XeroDay                                                                    #
# ---------------------------------------------------------------------------------- #





import os
import json
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt


LEAKS_JSON = "leaked_keys.json"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.3-70b-versatile"


AVAILABLE_CATEGORIES =[
    "OpenAI API Key (Legacy)", "OpenAI API Key (Project)", "Anthropic API Key", 
    "Google API/GCP Key", "OpenRouter API Key", "xAI (Grok) API Key", "Groq API Key", 
    "HuggingFace Token", "Replicate Token", "Cerebras Token", "AWS Access Key ID", 
    "AWS Session Token", "DigitalOcean PAT", "Heroku API Key", "Mapbox API Key", 
    "Sentry Token", "Databricks PAT", "GitHub Classic PAT", "GitHub Fine-Grained PAT", 
    "GitLab PAT", "NPM Access Token", "PyPI Upload Token", "Postman API Key", 
    "Discord Bot Token", "Discord Webhook", "Slack Bot Token", "Slack User Token", 
    "Slack Webhook", "Telegram Bot Token", "Twilio API Key", "SendGrid API Key", 
    "Mailgun API Key", "Stripe Secret Key", "Square Access Token", "Square OAuth Secret", 
    "Shopify Access Token", "Shopify Custom App", "Supabase PAT", "Supabase Anon/Service Role JWT",
    "Firebase Server Key", "Firebase Database URL", "PlanetScale Password", "PlanetScale OAuth Token",
    "Airtable PAT", "Appwrite API Key", "Deta Token", "PocketBase Token"
]

console = Console()

def get_groq_api_key() -> str:
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        console.print("[bold yellow][!] GROQ_API_KEY environment variable not found.[/]")
        api_key = Prompt.ask("[bold cyan]Please enter your Groq API Key (gsk_...)[/]", password=True)
        os.environ["GROQ_API_KEY"] = api_key
    return api_key

def load_database() -> list:
    if not os.path.exists(LEAKS_JSON):
        console.print(f"[bold red][X] Database file '{LEAKS_JSON}' not found. Please run the scanner first.[/]")
        return[]
    try:
        with open(LEAKS_JSON, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        console.print(f"[bold red][X] Error reading database: {e}[/]")
        return[]

def ask_ai_for_pointers(user_query: str, api_key: str) -> dict:
    system_prompt = f"""You are X3r0Day's AI Database Router. 
Your ONLY job is to translate a user's natural language request into exact database category pointers.
You must return a valid JSON object.

AVAILABLE EXACT CATEGORIES:
{json.dumps(AVAILABLE_CATEGORIES)}

INSTRUCTIONS:
1. Analyze what the user is asking for (e.g., "AWS", "discord", "all AI keys", "all Database").
2. Match their intent to the AVAILABLE EXACT CATEGORIES. 
3. If they ask for something broad like "AI keys", include OpenAI, Anthropic, Groq, xAI, Google etc.
4. DO NOT make up categories. If they ask for something not in the list, leave the array empty.
5. You MUST return your answer in the following JSON format ONLY:
{{
    "understanding": "A short 1-sentence confirmation of what you are querying. If users says hello or talks to you, you can talk back!",
    "target_categories":["Exact Category 1", "Exact Category 2"]
}}"""

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": GROQ_MODEL,
        "response_format": {"type": "json_object"},
        "messages":[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_query}
        ],
        "temperature": 0.1
    }

    try:
        response = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        ai_response_text = data["choices"][0]["message"]["content"]
        return json.loads(ai_response_text)
    except Exception as e:
        console.print(f"[bold red][X] Groq API Error: {e}[/]")
        return {}

def search_and_display(target_categories: list, db_data: list):
    if not target_categories:
        console.print("[bold yellow]The AI could not map your query to any known API key signatures in our system.[/]")
        return

    console.print(f"\n[dim]=> Local Script is now scanning database for: {', '.join(target_categories)}[/]")

    table = Table(title="[bold cyan]X3r0Day Database Search Results[/]", border_style="cyan", expand=True)
    table.add_column("Repository", style="magenta", width=25)
    table.add_column("API Type", style="yellow", width=25)
    table.add_column("Secret / Key", style="red")
    table.add_column("File / Origin", style="dim")

    match_count = 0

    for repo_entry in db_data:
        repo_name = repo_entry.get("repo", "Unknown")
        findings = repo_entry.get("findings",[])
        
        for finding in findings:
            if finding.get("type") in target_categories:
                match_count += 1
                secret = finding.get("secret", "N/A")
                file_origin = finding.get("file", "Unknown")
                key_type = finding.get("type", "Unknown")
                
                table.add_row(repo_name, key_type, secret, file_origin)

    if match_count > 0:
        console.print(table)
        console.print(f"[bold green]Successfully pulled {match_count} records from local database.[/]\n")
    else:
        console.print(f"[bold yellow][!] Search finished. 0 records found in the local database for these categories.[/]\n")

def main():
    console.print(Panel.fit("[bold magenta]X3r0Day - AI Database Query Engine[/]\n[dim]Powered by Llama-3 via Groq[/]", border_style="magenta"))
    
    api_key = get_groq_api_key()
    db_data = load_database()
    
    if not db_data:
        return

    console.print(f"[green]Loaded database with {len(db_data)} repository entries.[/]")
    console.print("[dim]Type 'exit' or 'quit' to close the terminal.[/]\n")

    while True:
        try:
            user_input = Prompt.ask("[bold cyan]Ask AI[/]")
            if user_input.lower() in ["exit", "quit"]:
                console.print("[bold magenta]Shutting down AI Engine...[/]")
                break
            
            if not user_input.strip():
                continue

            with console.status("[bold yellow]AI is thinking...[/]", spinner="dots"):
                ai_instructions = ask_ai_for_pointers(user_input, api_key)
            
            if not ai_instructions:
                continue

            understanding = ai_instructions.get("understanding", "")
            target_cats = ai_instructions.get("target_categories",[])

            console.print(f"[bold green]AI:[/] {understanding}")
            
            search_and_display(target_cats, db_data)

        except KeyboardInterrupt:
            console.print("\n[bold magenta]Shutting down AI Engine...[/]")
            break
        except Exception as e:
            console.print(f"[bold red]Unexpected Error: {e}[/]")

if __name__ == "__main__":
    main()