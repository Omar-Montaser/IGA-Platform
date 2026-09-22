"""Quick check that Gemini AI is working."""
import os
import sys
from pathlib import Path

print("=" * 70)
print("Gemini AI Status Check")
print("=" * 70)
print()

# Check environment
provider = os.environ.get('IGA_AI_PROVIDER', 'not set')
model = os.environ.get('IGA_AI_MODEL', 'not set')
api_key = os.environ.get('GEMINI_API_KEY', '')

print("Environment:")
print(f"  IGA_AI_PROVIDER: {provider}")
print(f"  IGA_AI_MODEL: {model}")
print(f"  GEMINI_API_KEY: {'***' + api_key[-8:] if api_key else 'NOT SET'}")
print()

if provider != 'gemini':
    print("⚠️  Provider is not set to 'gemini'")
    print()
    sys.exit(1)

# Check demo data
demo_path = Path('.demo-review/gemini/reviews.sqlite3')
if not demo_path.exists():
    print("❌ Demo data not found at .demo-review/gemini/")
    print()
    print("Create it with:")
    print("  .venv\\Scripts\\python.exe -m iga_review.cli demo --state-dir .demo-review/gemini")
    sys.exit(1)

print("✅ Demo data found")
print()

# Load service
from iga_review.service import ReviewService
from iga_review.domain import User
import hashlib

users = [User('reviewer:admin', 'Test', 'admin', None, hashlib.sha256(b'test').hexdigest())]
service = ReviewService(
    demo_path,
    users,
    fallback_reviewer_id='reviewer:admin',
    connectors={},
    demo=True
)
admin = users[0]

# Check campaigns
campaigns = service.list_campaigns(admin)
if not campaigns['campaigns']:
    print("❌ No campaigns found")
    sys.exit(1)

campaign_id = campaigns['campaigns'][0]['id']
detail = service.get_campaign(campaign_id, admin)
metadata = detail['metadata']
review_meta = metadata['review']

print("Campaign Review Status:")
print(f"  Provider used: {review_meta['providers'][0]}")
print(f"  Model: {metadata.get('model', 'N/A')}")
print(f"  Total cases: {review_meta['cases']}")
print(f"  AI-reviewed cases: {review_meta['cases'] - review_meta['fallback_cases']}")
print(f"  Fallback cases: {review_meta['fallback_cases']}")
print()

if review_meta['providers'][0] == 'gemini':
    if review_meta['fallback_cases'] < review_meta['cases']:
        print("✅ SUCCESS: Gemini AI is working!")
        print()
        print(f"   {review_meta['cases'] - review_meta['fallback_cases']} cases reviewed by Gemini")
        print(f"   {review_meta['fallback_cases']} cases used fallback (if any)")
    else:
        print("⚠️  All cases used fallback")
        print()
        print("Gemini is configured but all cases fell back to rules.")
        print("This might mean API was unavailable during campaign creation.")
else:
    print(f"❌ Wrong provider: {review_meta['providers'][0]}")
    print()
    print("Campaign was created with a different provider.")
    print("Delete and recreate with Gemini configured.")

print()
print("=" * 70)
print("Next: Open http://127.0.0.1:8040 and test AI explanations")
print("=" * 70)
