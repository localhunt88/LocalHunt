# backend/routes/otp_routes.py
from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta, timezone
import hashlib
import os
import random

from supabase_client import supabase
from sms_sender import send_sms_with_fallback

bp = Blueprint("otp", __name__)

# OTP settings
OTP_LENGTH = 4            # 4-digit OTP
OTP_EXPIRE_MINUTES = 2   # expire in 10 minutes
OTP_HASH_SALT = os.getenv("OTP_HASH_SALT", "local-default-salt")  # optional salt from env


def _hash_otp(otp: str) -> str:
    """Return hex sha256 of otp + salt (deterministic to verify later)."""
    s = f"{otp}{OTP_HASH_SALT}"
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


@bp.route("/send-otp", methods=["POST"])
def send_otp():
    """
    Body: { "phone": "+91xxxxxxxxxx" }
    Response: { success, message }
    """
    data = request.get_json() or {}
    phone = data.get("phone")
    if not phone:
        return jsonify({"success": False, "error": "Missing phone"}), 400

    # generate OTP
    otp = str(random.randint(10**(OTP_LENGTH-1), 10**OTP_LENGTH - 1))
    otp_hash = _hash_otp(otp)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=OTP_EXPIRE_MINUTES)

    # Insert OTP record with status PENDING first
    otp_row = {
        "phone": phone,
        "otp_hash": otp_hash,
        "status": "PENDING",
        "attempts": 0,
        "created_at": now.isoformat(),
        "expires_at": expires_at.isoformat()
    }
    try:
        supabase.table("otps").insert(otp_row).execute()
    except Exception as e:
        return jsonify({"success": False, "error": f"DB insert failed: {e}"}), 500

    # send SMS via sms_sender
    content = f"Your confirmation code is: {otp} (valid for {OTP_EXPIRE_MINUTES} minutes)"
    send_result = send_sms_with_fallback(phone, content)

    if send_result.get("success"):
        # update the otps row status -> SENT and set sent_via
        try:
            supabase.table("otps").update({
                "status": "SENT",
                "sent_via": send_result.get("device"),
            }).eq("phone", phone).order("created_at", {"ascending": False}).limit(1).execute()
        except Exception:
            pass
        return jsonify({"success": True, "message": "OTP sent", "debug": {"device": send_result.get("device")}}), 200
    else:
        # mark OTP row failed
        try:
            supabase.table("otps").update({
                "status": "FAILED"
            }).eq("phone", phone).order("created_at", {"ascending": False}).limit(1).execute()
        except Exception:
            pass
        return jsonify({"success": False, "error": "Failed to send SMS", "details": send_result.get("error")}), 502

@bp.route("/verify-otp", methods=["POST"])
def verify_otp():
    """
    Body: { "phone": "+91...", "otp": "1234" }
    Verifies latest OTP for that phone (status SENT or PENDING) and not expired.
    """
    data = request.get_json() or {}
    phone = data.get("phone")
    otp = data.get("otp")
    if not phone or not otp:
        return jsonify({"success": False, "error": "Missing phone or otp"}), 400

    # fetch latest OTP row for this phone that is not VERIFIED/EXPIRED/FAILED
    try:
        q = (
            supabase.table("otps")
            .select("*")
            .eq("phone", phone)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = q.data or []
        if not rows:
            return jsonify({"success": False, "error": "No OTP request found for this number"}), 404
        otp_row = rows[0]
    except Exception as e:
        return jsonify({"success": False, "error": f"DB error: {e}"}), 500

    # check status and expiry
    status = otp_row.get("status")
    expires_at = otp_row.get("expires_at")

    try:
        exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00")) if isinstance(expires_at, str) else None
    except Exception:
        exp_dt = None

    if status in ("VERIFIED", "EXPIRED"):
        return jsonify({"success": False, "error": f"OTP already {status}"}), 400
    if exp_dt and datetime.now(timezone.utc) > exp_dt:
        supabase.table("otps").update({"status": "EXPIRED"}).eq("id", otp_row.get("id")).execute()
        return jsonify({"success": False, "error": "OTP expired"}), 400

    # verify hash
    expected_hash = otp_row.get("otp_hash")
    provided_hash = _hash_otp(otp)
    if provided_hash == expected_hash:
        supabase.table("otps").update({
            "status": "VERIFIED",
            "verified_at": datetime.now(timezone.utc).isoformat()
        }).eq("id", otp_row.get("id")).execute()

        return jsonify({"success": True, "message": "OTP verified"}), 200
    else:
        try:
            supabase.table("otps").update({
                "attempts": otp_row.get("attempts", 0) + 1
            }).eq("id", otp_row.get("id")).execute()
        except Exception:
            pass
        return jsonify({"success": False, "error": "Invalid OTP"}), 400
