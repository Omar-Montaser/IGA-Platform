"""Test Gemini API connection with detailed diagnostics."""
import os
import sys
import json
import httpx

print("=" * 70)
print("Gemini API Connection Diagnostics")
print("=" * 70)
print()

# Check environment
api_key = os.environ.get('GEMINI_API_KEY') or os.environ.get('GOOGLE_API_KEY')
provider = os.environ.get('IGA_AI_PROVIDER', 'not set')
model = os.environ.get('IGA_AI_MODEL', 'not set')

print("Environment Variables:")
print(f"  IGA_AI_PROVIDER: {provider}")
print(f"  IGA_AI_MODEL: {model}")

if not api_key:
    print(f"  GEMINI_API_KEY: NOT SET")
    print()
    print("❌ ERROR: No API key found")
    print()
    print("Set it with:")
    print('  $env:GEMINI_API_KEY = "your-key-here"')
    sys.exit(1)
else:
    print(f"  GEMINI_API_KEY: {api_key[:10]}...{api_key[-4:]} (length: {len(api_key)})")

print()
print("Testing Gemini API connection...")
print()

# Test URL
endpoint = "https://generativelanguage.googleapis.com/v1beta/interactions"

# Simple test payload
test_payload = {
    "model": "gemini-3.8-flash",
    "system_instruction": "You are a test assistant.",
    "input": json.dumps({"test": "connection"}),
    "response_format": {
        "type": "text",
        "mime_type": "application/json",
        "schema": {
            "type": "object",
            "properties": {"result": {"type": "string"}},
            "required": ["result"]
        }
    },
    "generation_config": {
        "thinking_level": "high",
        "max_output_tokens": 100
    },
    "store": False
}

try:
    print(f"Sending request to: {endpoint}")
    print(f"Using API key: {api_key[:10]}...{api_key[-4:]}")
    print()
    
    with httpx.Client(timeout=30.0) as client:
        response = client.post(
            endpoint,
            json=test_payload,
            headers={'x-goog-api-key': api_key}
        )
        
        print(f"Response Status: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print()
        
        if response.status_code == 200:
            print("✅ SUCCESS: Connection works!")
            print()
            result = response.json()
            print("Response preview:")
            print(json.dumps(result, indent=2)[:500])
            sys.exit(0)
        elif response.status_code == 400:
            print("❌ ERROR: Bad Request (400)")
            print()
            print("Response body:")
            print(response.text[:500])
            print()
            print("Possible causes:")
            print("  - Invalid model name")
            print("  - Incorrect request format")
            print("  - API endpoint changed")
        elif response.status_code == 401:
            print("❌ ERROR: Unauthorized (401)")
            print()
            print("Response body:")
            print(response.text[:500])
            print()
            print("Possible causes:")
            print("  - Invalid API key")
            print("  - API key not activated")
            print("  - Wrong API key format")
            print()
            print("Steps to fix:")
            print("  1. Go to: https://aistudio.google.com/api-keys")
            print("  2. Create a NEW API key")
            print("  3. Copy the FULL key")
            print("  4. Set: $env:GEMINI_API_KEY = 'new-key'")
        elif response.status_code == 403:
            print("❌ ERROR: Forbidden (403)")
            print()
            print("Response body:")
            print(response.text[:500])
            print()
            print("Possible causes:")
            print("  - API not enabled for your project")
            print("  - Billing required but not set up")
            print("  - Geographic restrictions")
            print()
            print("Steps to fix:")
            print("  1. Go to: https://aistudio.google.com")
            print("  2. Make sure Gemini API is enabled")
            print("  3. Check project settings")
        elif response.status_code == 404:
            print("❌ ERROR: Not Found (404)")
            print()
            print("The API endpoint might have changed.")
            print(f"Tried: {endpoint}")
            print()
            print("Check documentation at:")
            print("  https://ai.google.dev/gemini-api/docs")
        elif response.status_code == 429:
            print("❌ ERROR: Rate Limited (429)")
            print()
            print("Too many requests. Wait 60 seconds and try again.")
        else:
            print(f"❌ ERROR: HTTP {response.status_code}")
            print()
            print("Response body:")
            print(response.text[:500])
        
        sys.exit(1)
        
except httpx.ConnectError as e:
    print("❌ ERROR: Connection Failed")
    print()
    print(f"Details: {e}")
    print()
    print("Possible causes:")
    print("  - No internet connection")
    print("  - Firewall blocking HTTPS")
    print("  - Proxy configuration needed")
    print("  - VPN interference")
    sys.exit(1)
    
except httpx.TimeoutException as e:
    print("❌ ERROR: Request Timed Out")
    print()
    print(f"Details: {e}")
    print()
    print("Possible causes:")
    print("  - Slow internet connection")
    print("  - Google API having issues")
    print("  - Firewall delaying requests")
    sys.exit(1)
    
except Exception as e:
    print("❌ ERROR: Unexpected Error")
    print()
    print(f"Type: {type(e).__name__}")
    print(f"Details: {e}")
    sys.exit(1)
