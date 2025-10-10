# backend/sms_sender.py
import os
import time
import requests
from datetime import datetime, timezone
from supabase import create_client
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
HTTPSMS_API_KEY = os.getenv("HTTPSMS_API_KEY")
# sanitize devices list (remove empty entries / whitespace)
HTTPSMS_DEVICES = [p.strip() for p in os.getenv("HTTPSMS_DEVICES", "").split(",") if p.strip()]
HTTPSMS_DEVICE_MAX_PER_DAY = int(os.getenv("HTTPSMS_DEVICE_MAX_PER_DAY", 80))

if not (SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY):
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in .env.local")

if not HTTPSMS_API_KEY:
    raise RuntimeError("Missing HTTPSMS_API_KEY in .env.local")

if not HTTPSMS_DEVICES:
    raise RuntimeError("No HTTPSMS_DEVICES configured in .env.local (comma-separated E.164 numbers)")

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# in-memory cache
DEVICES = {}
LAST_REFRESH = 0
REFRESH_TTL = 30  # seconds

HTTPSMS_SEND_URL = "https://api.httpsms.com/v1/messages/send"
HEADERS = {"x-api-key": HTTPSMS_API_KEY, "Content-Type": "application/json"}


def _refresh_devices_from_db():
    """Refresh device rows from Supabase into DEVICES cache."""
    global DEVICES, LAST_REFRESH
    try:
        r = supabase.table("sms_devices").select("*").in_("phone", HTTPSMS_DEVICES).execute()
        if getattr(r, "error", None):
            print("[sms_sender] Supabase error when loading devices:", r.error)
            DEVICES = {}
            return

        items = r.data or []
        if not items:
            # fallback: use .env devices as active defaults
            DEVICES = {
                p: {"phone": p, "sent_today": 0, "daily_quota": HTTPSMS_DEVICE_MAX_PER_DAY, "status": "active"}
                for p in HTTPSMS_DEVICES
            }
            LAST_REFRESH = time.time()
            print("[sms_sender] No rows found in sms_devices; using .env fallback devices")
            return

        DEVICES = {}
        for row in items:
            DEVICES[row["phone"]] = {
                "id": row.get("id"),
                "phone": row.get("phone"),
                "label": row.get("label"),
                "last_seen": row.get("last_seen"),
                "daily_quota": row.get("daily_quota") or HTTPSMS_DEVICE_MAX_PER_DAY,
                "sent_today": row.get("sent_today") or 0,
                "status": row.get("status") or "active",
            }
        LAST_REFRESH = time.time()
        print(f"[sms_sender] Refreshed {len(DEVICES)} devices from DB")
    except Exception as e:
        print("[sms_sender] Exception during device refresh:", e)
        DEVICES = {}


def _ensure_devices_in_db():
    """Upsert .env devices into sms_devices table (so DB has rows)."""
    rows = []
    for p in HTTPSMS_DEVICES:
        rows.append({"phone": p, "daily_quota": HTTPSMS_DEVICE_MAX_PER_DAY, "label": f"device-{p}"})
    try:
        supabase.table("sms_devices").upsert(rows, on_conflict="phone").execute()
        _refresh_devices_from_db()
        print("[sms_sender] Ensured devices exist in DB (upserted).")
    except Exception as e:
        print("[sms_sender] Failed to ensure devices in DB:", e)


def _increment_sent_count_in_db(phone: str):
    """Atomically increment sent_today for a device (best-effort)."""
    try:
        r = supabase.table("sms_devices").select("sent_today").eq("phone", phone).single().execute()
        if getattr(r, "error", None):
            print(f"[sms_sender] Error reading sent_today for {phone}:", r.error)
            return
        row = r.data or {}
        current = row.get("sent_today") or 0
        new = current + 1
        supabase.table("sms_devices").update({
            "sent_today": new,
            "last_seen": datetime.now(timezone.utc).isoformat()
        }).eq("phone", phone).execute()
        # refresh cache so distribution stays accurate
        _refresh_devices_from_db()
        print(f"[sms_sender] Incremented sent_today for {phone} -> {new}")
    except Exception as e:
        print("[sms_sender] Exception incrementing sent count:", e)


def _mark_device_offline(phone: str):
    """Mark device as offline in DB to avoid trying invalid 'from' numbers repeatedly."""
    try:
        supabase.table("sms_devices").update({"status": "offline"}).eq("phone", phone).execute()
        _refresh_devices_from_db()
        print(f"[sms_sender] Marked device offline: {phone}")
    except Exception as e:
        print("[sms_sender] Exception marking device offline:", e)


def _get_candidates():
    """Return eligible devices sorted by least sent_today."""
    if not DEVICES or (time.time() - LAST_REFRESH) > REFRESH_TTL:
        _refresh_devices_from_db()
    candidates = [d for d in DEVICES.values() if d["status"] == "active"]
    # sort by sent_today ascending (least used first)
    candidates.sort(key=lambda x: x.get("sent_today", 0))
    # filter those under quota
    under_quota = [d for d in candidates if d.get("sent_today", 0) < (d.get("daily_quota") or HTTPSMS_DEVICE_MAX_PER_DAY)]
    return under_quota if under_quota else candidates  # if none under quota, try active ones anyway


def send_sms_with_fallback(to_phone: str, content: str, try_limit: int = None) -> dict:
    """
    Try sending SMS using the available devices (fallback).
    Returns dict: { success: bool, device: phone-or-None, error: str, raw_response: str|dict }
    """
    if not to_phone:
        return {"success": False, "error": "missing to_phone"}

    candidates = _get_candidates()
    if not candidates:
        return {"success": False, "error": "no active devices available"}

    # limit attempts to number of candidates or try_limit if provided
    attempts_allowed = min(len(candidates), try_limit) if try_limit else len(candidates)
    last_error = None

    for idx, device in enumerate(candidates[:attempts_allowed]):
        from_number = device["phone"]
        payload = {"to": to_phone, "from": from_number, "content": content}
        try:
            resp = requests.post(HTTPSMS_SEND_URL, headers=HEADERS, json=payload, timeout=15)
        except Exception as e:
            last_error = f"request-exception: {e}"
            print(f"[sms_sender] Exception calling HTTPSMS for {from_number} -> {e}")
            continue

        # Try parse JSON if possible
        resp_text = None
        resp_json = None
        try:
            resp_json = resp.json()
            resp_text = resp_json
        except Exception:
            resp_text = resp.text

        # success cases: HTTP 200/201 typically
        if resp.status_code in (200, 201):
            # mark counter in DB
            _increment_sent_count_in_db(from_number)
            print(f"[sms_sender] Sent via {from_number} -> {to_phone} | response: {resp_text}")
            return {"success": True, "device": from_number, "raw_response": resp_text}
        else:
            # log the failure response for debugging
            print(f"[sms_sender] Failed via {from_number} status={resp.status_code} response={resp_text}")

            # If the API says the 'from' field is invalid/required -> mark offline
            if isinstance(resp_json, dict):
                data = resp_json.get("data") or {}
                # commonly errors about 'from' are in data['from']
                if data.get("from"):
                    print(f"[sms_sender] API says 'from' invalid for {from_number}, marking offline.")
                    _mark_device_offline(from_number)

            last_error = {"status": resp.status_code, "response": resp_text}
            # try next device

    # exhausted candidates
    return {"success": False, "error": "all devices failed", "last_error": last_error}
    

# initialize on import
try:
    _ensure_devices_in_db()
except Exception as e:
    print("[sms_sender] Initialization warning:", e)
    # continue; refresh will attempt later
