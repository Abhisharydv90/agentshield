import os
from google import genai
from dotenv import load_dotenv

load_dotenv()

# Initialize the client with your key
client = genai.Client(api_key=os.getenv("JUDGE_KEY"))

print("--- AVAILABLE MODELS FOR YOUR KEY ---")
try:
    for model in client.models.list():
        print(model.name)
except Exception as e:
    print(f"Error listing models: {e}")