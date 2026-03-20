"""Optional script to verify Gemini API connectivity. Uses .env for API key."""
import os
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("GEMINI_API_KEY", "").strip()

if not api_key:
    print("GEMINI_API_KEY not set in .env. Skipping model list.")
else:
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        for model in genai.list_models():
            print(model.name)
    except Exception as e:
        print("Error:", e)

print("API key set:", bool(api_key))
print("Model:", os.getenv("GEMINI_MODEL", "gemini-1.5-flash"))
