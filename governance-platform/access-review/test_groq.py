"""Test Groq integration."""
import os
import sys

if __name__ != '__main__':
    import unittest
    raise unittest.SkipTest('Explicit live diagnostic; use ai-check for validated inference.')

print("=" * 70)
print("Groq Integration Test")
print("=" * 70)
print()

# Check environment
provider = os.environ.get('IGA_AI_PROVIDER')
api_key = os.environ.get('GROQ_API_KEY', '')
model = os.environ.get('IGA_AI_MODEL', 'llama-3.3-70b-versatile')

print("Environment:")
print(f"  IGA_AI_PROVIDER: {provider}")
print(f"  IGA_AI_MODEL: {model}")
print(f"  GROQ_API_KEY: {'configured (value omitted)' if api_key else 'NOT SET'}")
print()

if provider != 'groq':
    print("⚠️  Set: $env:IGA_AI_PROVIDER = 'groq'")
    sys.exit(1)

if not api_key:
    print("❌ No API key")
    print()
    print("Get one from: https://console.groq.com")
    print("Then: $env:GROQ_API_KEY = 'your-key'")
    sys.exit(1)

# Test Groq API directly
import httpx
import json

print("Testing Groq API connection...")
print()

try:
    response = httpx.post(
        'https://api.groq.com/openai/v1/chat/completions',
        json={
            'model': model,
            'messages': [{'role': 'user', 'content': 'Say "test passed" in JSON'}],
            'response_format': {'type': 'json_object'},
            'max_tokens': 50
        },
        headers={'Authorization': f'Bearer {api_key}'},
        timeout=30.0
    )
    
    print(f"Status: {response.status_code}")
    
    if response.status_code == 200:
        print("✅ Groq API works!")
        print()
        data = response.json()
        content = data['choices'][0]['message']['content']
        print(f"Response: {content[:100]}")
    elif response.status_code == 401:
        print("❌ Invalid API key")
        print("Get a new one: https://console.groq.com")
        sys.exit(1)
    elif response.status_code == 429:
        print("⚠️  Rate limited - inference was not verified")
        print("Wait 60 seconds and try again")
        sys.exit(1)
    else:
        print(f"❌ HTTP {response.status_code}")
        print(response.text[:300])
        sys.exit(1)

except Exception as e:
    print(f"❌ Error: {e}")
    sys.exit(1)

print()
print("=" * 70)
print("Now test with Module 4:")
print("=" * 70)
print()
print("  & .venv\\Scripts\\python.exe -m iga_review.cli ai-check")
print()
