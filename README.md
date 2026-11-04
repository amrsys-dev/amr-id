# AMR ID

Persistent identity layer: one nick for WhatsApp, Telegram, Google — no SIM binding.

## Stack
- Cloudflare Python Workers + FastAPI
- Cloudflare KV (no database)
- PWA interface

## Quick start
1. Create KV namespace in Cloudflare Dashboard, paste ID into `wrangler.toml`
2. `uv run pywrangler secret put TELEGRAM_BOT_TOKEN`
3. `uv run pywrangler dev` — open http://localhost:8787
4. `uv run pywrangler deploy`

## Routes
- `/` — landing (AMR ID + AMR Talking links)
- `/id` — create / sign in
- `/talking` — AMR Talking (coming soon)
- `/api/register`, `/api/login`, `/api/resolve/{nick}`
- `/webhook/sms` — Telnyx/Twilio OTP webhook
- `/otp/{number}` — fetch last OTP
- `/api/bind-number` — map number → Telegram chat_id

## ID format
160-bit entropy · Base58 (no 0/O/I/l) · 4-byte checksum · version byte

## License
Open standard. Spec TBD.
