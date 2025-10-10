from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash
from supabase_client import supabase
from datetime import datetime, timezone

signup_bp = Blueprint("signup", __name__)


def _latest_verified_otp(phone: str):
    """
    Return the latest VERIFIED OTP row for a phone number.
    """
    try:
        q = (
            supabase
            .table("otps")
            .select("*")
            .eq("phone", phone)
            .eq("status", "VERIFIED")
            .order("created_at", desc=True)  # ✅ Correct syntax
            .limit(1)
            .execute()
        )
        if q.data:
            return q.data[0]
        return None
    except Exception as e:
        print(f"[signup] _latest_verified_otp error: {e}")
        return None


def _create_user_record(table_name: str, full_name: str, email: str, phone: str, password: str):
    """Helper to insert a new user or vendor."""
    password_hash = generate_password_hash(password)
    payload = {
        "full_name": full_name,
        "email": email,
        "phone": phone,
        "password_hash": password_hash,
        "is_mobile_verified": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    response = supabase.table(table_name).insert(payload).execute()
    if getattr(response, "status_code", 200) >= 400:
        return None, {"message": "Database error", "details": response.data}
    if not response.data:
        return None, {"message": "Insert failed"}
    return response.data[0], None


@signup_bp.route("/signup/user", methods=["POST"])
def signup_user():
    try:
        data = request.get_json() or {}
        full_name = data.get("full_name")
        email = data.get("email")
        phone = data.get("phone")
        password = data.get("password")

        if not all([full_name, phone, password]):
            return jsonify({"success": False, "message": "Missing required fields"}), 400

        # ✅ Verify OTP
        otp_row = _latest_verified_otp(phone)
        if not otp_row:
            return jsonify({"success": False, "message": "Phone not verified. Please verify OTP before signup."}), 400

        user, error = _create_user_record("users", full_name, email, phone, password)
        if error:
            return jsonify({"success": False, **error}), 500

        return jsonify({"success": True, "message": "User registered successfully", "data": user}), 201

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@signup_bp.route("/signup/vendor", methods=["POST"])
def signup_vendor():
    try:
        data = request.get_json() or {}
        full_name = data.get("full_name")
        email = data.get("email")
        phone = data.get("phone")
        password = data.get("password")

        if not all([full_name, phone, password]):
            return jsonify({"success": False, "message": "Missing required fields"}), 400

        otp_row = _latest_verified_otp(phone)
        if not otp_row:
            return jsonify({"success": False, "message": "Phone not verified. Please verify OTP before signup."}), 400

        vendor, error = _create_user_record("vendors", full_name, email, phone, password)
        if error:
            return jsonify({"success": False, **error}), 500

        return jsonify({"success": True, "message": "Vendor registered successfully", "data": vendor}), 201

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
