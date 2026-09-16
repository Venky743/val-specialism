# Val Specialism — Automatic Payments

Val Specialism keeps the existing validation/reconciliation engine and adds account-based commercial access.

## Pricing
- India: Small & Medium Business — ₹1,499 one-time
- India: Large / Enterprise — ₹3,999 one-time
- International: Business Validation — $149 one-time

The customer selects **India** or **International** during signup. The backend enforces the matching payment provider and prices; the frontend never controls the final amount.

## Payment routing
- India → Razorpay (INR)
- International → PayPal (USD)
- Only verified payments change a validation to `PAID` and unlock PDF export.

## Setup
1. Copy `.env.example` to `.env`.
2. Add PayPal credentials for international sandbox testing.
3. Add Razorpay Test Mode Key ID and Key Secret for India testing.
4. Set a Razorpay webhook secret and create a Razorpay webhook pointing to `/api/razorpay/webhook`.
5. For PayPal, create a webhook pointing to `/api/paypal/webhook` and put its actual webhook configuration ID in `PAYPAL_WEBHOOK_ID` (do not use a simulator event ID).
6. Run `npm install` then `npm start`.

## Local testing
- App: `http://localhost:8080`
- A public HTTPS tunnel is needed for provider webhooks during local testing.
- PayPal sandbox uses international buyer accounts; Indian PayPal-to-Indian-seller payments are restricted by PayPal.

## Security
- Payment amounts and plan eligibility are enforced server-side.
- Razorpay signatures are verified server-side.
- PayPal webhook signatures are verified server-side.
- Payment secrets must remain in `.env` and must never be committed.
