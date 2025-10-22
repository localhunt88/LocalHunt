# routes/password_reset_routes.py
from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta, timezone
import hashlib, os, random, uuid
from werkzeug.security import generate_password_hash

from supabase_client import supabase
from sms_sender import send_sms_with_fallback

bp = Blueprint("password_reset", __name__)

OTP_LENGTH = 4
OTP_EXPIRE_MINUTES = 3
OTP_HASH_SALT = os.getenv("OTP_HASH_SALT", "local-default-salt")
TOKEN_EXPIRE_MINUTES = 15


def _hash_otp(otp: str) -> str:
    s = f"{otp}{OTP_HASH_SALT}"
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _phone_exists(phone: str):
    """Return ('user' or 'vendor', row) or (None, None)"""
    try:
        r = supabase.table("users").select("*").eq("phone", phone).execute()
        if r.data:
            return "user", r.data[0]
        r2 = supabase.table("vendors").select("*").eq("phone", phone).execute()
        if r2.data:
            return "vendor", r2.data[0]
        return None, None
    except Exception as e:
        print("phone_exists error:", e)
        return None, None


@bp.route("/password-reset/request", methods=["POST"])
def request_reset():
    data = request.get_json() or {}
    phone = data.get("phone")
    if not phone:
        return jsonify({"success": False, "message": "Missing phone"}), 400

    kind, row = _phone_exists(phone)
    if not kind:
        return jsonify({"success": False, "message": "Account not found for this phone"}), 404

    # generate OTP
    otp = str(random.randint(10**(OTP_LENGTH - 1), 10**OTP_LENGTH - 1))
    otp_hash = _hash_otp(otp)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=OTP_EXPIRE_MINUTES)

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
        return jsonify({"success": False, "message": f"DB insert failed: {e}"}), 500

    content = f"Your Localhunt password reset code is: {otp} (valid for {OTP_EXPIRE_MINUTES} minutes)"
    send_result = send_sms_with_fallback(phone, content)

    if send_result.get("success"):
        # update to SENT for the most recent row
        try:
            supabase.table("otps").update(
                {"status": "SENT", "sent_via": send_result.get("device")}
            ).eq("phone", phone).order("created_at", desc=True).limit(1).execute()
        except Exception:
            pass
        return jsonify({"success": True, "message": "OTP sent", "expires_in": OTP_EXPIRE_MINUTES * 60}), 200
    else:
        # mark failed
        try:
            supabase.table("otps").update({"status": "FAILED"}).eq("phone", phone).order("created_at", desc=True).limit(1).execute()
        except Exception:
            pass
        return jsonify({"success": False, "message": "Failed to send OTP", "error": send_result.get("error")}), 502


@bp.route("/password-reset/verify", methods=["POST"])
def verify_reset_otp():
    data = request.get_json() or {}
    phone = data.get("phone")
    otp = data.get("otp")
    if not phone or not otp:
        return jsonify({"success": False, "message": "Missing phone or otp"}), 400

    # fetch latest otp
    try:
        q = supabase.table("otps").select("*").eq("phone", phone).order("created_at", desc=True).limit(1).execute()
        if q.data:
            otp_row = q.data[0]
        else:
            return jsonify({"success": False, "message": "No OTP request found"}), 404
    except Exception as e:
        return jsonify({"success": False, "message": f"DB error: {e}"}), 500

    # check expiry and status
    status = otp_row.get("status")
    expires_at = otp_row.get("expires_at")
    try:
        exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00")) if isinstance(expires_at, str) else None
    except Exception:
        exp_dt = None

    if status in ("VERIFIED", "EXPIRED"):
        return jsonify({"success": False, "message": f"OTP already {status}"}), 400
    if exp_dt and datetime.now(timezone.utc) > exp_dt:
        supabase.table("otps").update({"status": "EXPIRED"}).eq("id", otp_row.get("id")).execute()
        return jsonify({"success": False, "message": "OTP expired"}), 400

    if _hash_otp(otp) == otp_row.get("otp_hash"):
        # mark verified
        supabase.table("otps").update({"status": "VERIFIED", "verified_at": datetime.now(timezone.utc).isoformat()}).eq("id", otp_row.get("id")).execute()

        # create password reset token
        token = str(uuid.uuid4())
        expires = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
        token_row = {
            "account_type": "USER",  # we'll determine actual below
            "account_id": None,
            "token": token,
            "expires_at": expires.isoformat(),
            "used": False,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        # determine account id and type
        kind, row = _phone_exists(phone)
        if kind and row:
            token_row["account_type"] = "VENDOR" if kind == "vendor" else "USER"
            token_row["account_id"] = row.get("id")

        try:
            supabase.table("password_reset_tokens").insert(token_row).execute()
        except Exception as e:
            print("token insert error:", e)
            # still allow returning token but log this
            return jsonify({"success": True, "token": token, "message": "OTP verified (token creation failed in DB)"}), 200

        return jsonify({"success": True, "token": token, "message": "OTP verified", "expires_in": TOKEN_EXPIRE_MINUTES * 60}), 200
    else:
        # increment attempts
        try:
            supabase.table("otps").update({"attempts": otp_row.get("attempts", 0) + 1}).eq("id", otp_row.get("id")).execute()
        except Exception:
            pass
        return jsonify({"success": False, "message": "Invalid OTP"}), 400


@bp.route("/password-reset/complete", methods=["POST"])
def password_reset_complete():
    data = request.get_json() or {}
    phone = data.get("phone")
    token = data.get("token")
    new_password = data.get("new_password")

    if not phone or not token or not new_password:
        return jsonify({"success": False, "message": "Missing phone, token or new password"}), 400

    # find token row
    try:
        tr = supabase.table("password_reset_tokens").select("*").eq("token", token).single().execute()
        if getattr(tr, "error", None) or not tr.data:
            return jsonify({"success": False, "message": "Invalid token"}), 400
        token_row = tr.data
    except Exception as e:
        return jsonify({"success": False, "message": f"DB error: {e}"}), 500

    # check used & expiry
    if token_row.get("used", False):
        return jsonify({"success": False, "message": "Token already used"}), 400

    expires_at = token_row.get("expires_at")
    try:
        exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00")) if isinstance(expires_at, str) else None
    except Exception:
        exp_dt = None

    if exp_dt and datetime.now(timezone.utc) > exp_dt:
        return jsonify({"success": False, "message": "Token expired"}), 400

    # ensure phone matches account
    acct_type = token_row.get("account_type")
    acct_id = token_row.get("account_id")

    # Fetch account by phone to verify guard
    kind, row = _phone_exists(phone)
    if not kind or not row:
        return jsonify({"success": False, "message": "No account found for phone"}), 404

    if (acct_type == "USER" and kind != "user") or (acct_type == "VENDOR" and kind != "vendor"):
        return jsonify({"success": False, "message": "Token does not match phone"}), 400

    # update password hash
    hash_val = generate_password_hash(new_password)
    table = "users" if kind == "user" else "vendors"
    try:
        supabase.table(table).update({"password_hash": hash_val}).eq("phone", phone).execute()
        # mark token used
        supabase.table("password_reset_tokens").update({"used": True}).eq("id", token_row.get("id")).execute()
        return jsonify({"success": True, "message": "Password updated"}), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"DB update error: {e}"}), 500
