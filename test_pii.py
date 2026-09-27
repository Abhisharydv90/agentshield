import requests

url = "http://localhost:8000/v1/chat/completions"
headers = {
    "Content-Type": "application/json",
    "X-Trace-Id": "pii-test-001",
    "X-Tenant-Id": "demo",
}
payload = {
    "model": "openai/gpt-oss-120b",
    "messages": [
        {
            "role": "user",
            "content": "Send a refund confirmation to john.doe@acme.com. His card ends in 4242 and his SSN is 123-45-6789."
        }
    ],
}

response = requests.post(url, headers=headers, json=payload)
print(f"Status Code: {response.status_code}")
print(response.text[:2000])