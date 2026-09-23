"""Simple test to verify Gemini API key is valid."""
import os
import sys

if __name__ != '__main__':
    import unittest
    raise unittest.SkipTest('Explicit live key diagnostic, not a unit test.')
import httpx

api_key = os.environ.get('GEMINI_API_KEY')

print("=" * 60)
print("Gemini API Key Test")
print("=" * 60)
print()

if not api_key:
    print("❌ No API key found")
    print("Set it: $env:GEMINI_API_KEY = 'your-key'")
    sys.exit(1)

print('Key configured (value omitted).')
print()

# Simplest possible request
endpoint = "https://generativelanguage.googleapis.com/v1beta/models"

print(f"Testing: GET {endpoint}")
print("This just lists available models - no generation")
print()

try:
    response = httpx.get(
        endpoint,
        headers={'x-goog-api-key': api_key},
        timeout=10.0
    )
    
    print(f"Status: {response.status_code}")
    
    if response.status_code == 200:
        print("✅ API key is VALID!")
        print()
        data = response.json()
        if 'models' in data:
            models = [m['name'] for m in data.get('models', [])]
            print(f"Available models: {len(models)}")
            for model in models[:5]:
                print(f"  - {model}")
        sys.exit(0)
    elif response.status_code == 401:
        print("❌ INVALID API KEY")
        print()
        print("The key is wrong or expired.")
        print("Create a new one: https://aistudio.google.com/apikeys")
    elif response.status_code == 403:
        print("❌ FORBIDDEN")
        print()
        print("API might not be enabled for your project.")
    elif response.status_code == 429:
        print("❌ RATE LIMITED")
        print()
        print("Authentication/inference was not verified. Retry after quota recovers.")
        sys.exit(1)
    else:
        print(f"❌ HTTP {response.status_code}")
        print()
        print(response.text[:300])
    
    sys.exit(1)
    
except httpx.ConnectError:
    print("❌ CONNECTION FAILED")
    print("Check internet/firewall")
    sys.exit(1)
except Exception as e:
    print(f"❌ ERROR: {e}")
    sys.exit(1)
