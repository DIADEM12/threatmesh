from google import genai
import os
from dotenv import load_dotenv

load_dotenv()

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

response = client.models.generate_content(
    model="gemini-2.0-flash",
    contents="You are a cybersecurity analyst. A port scan was detected from IP 192.168.1.100 on port 22. In 2 sentences, describe the threat and recommend one action."
)

print("Gemini response:")
print(response.text)