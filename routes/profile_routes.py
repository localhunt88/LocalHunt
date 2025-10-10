# backend/routes/profile_routes.py
from flask import Blueprint, request, jsonify
from supabase_client import supabase
from sms_sender import send_sms_with_fallback
import hashlib, os, time, random
from werkzeug.security import check_password_hash, generate_password_hash

profile_routes = Blueprint("profile_routes", __name__)

OTP_LENGTH = 4
OTP_EXPIRE_MINUTES = 3
OTP_HASH_SALT = os.getenv("OTP_HASH_SALT", "local-default-salt")
otp_store = {}

# Hash OTP helper
def hash_otp(phone, otp):
    return hashlib.sha256(f"{otp}{phone}{OTP_HASH_SALT}".encode()).hexdigest()

# Strict +91 normalization helper
def normalize_phone(phone: str) -> str:
    if not phone:
        return ""
    phone = phone.strip().replace(" ", "").replace("-", "")
    # Already correct +91XXXXXXXXXX
    if phone.startswith("+91") and len(phone) == 13:
        return phone
    # If starts with 91 and length 12
    if phone.startswith("91") and len(phone) == 12:
        return f"+{phone}"
    # If plain 10-digit
    if len(phone) == 10 and phone.isdigit():
        return f"+91{phone}"
    # If starts with + but not +91 -> extract last 10 digits
    if phone.startswith("+") and not phone.startswith("+91"):
        digits = ''.join(filter(str.isdigit, phone))
        if len(digits) >= 10:
            return f"+91{digits[-10:]}"
        else:
            return f"+91{digits}"
    # Fallback: pick last 10 digits if possible
    digits = ''.join(filter(str.isdigit, phone))
    if len(digits) >= 10:
        return f"+91{digits[-10:]}"
    return f"+91{digits}"

# Generate numeric OTP of 4 digits
def generate_otp():
    return f"{random.randint(1000, 9999)}"

# ---------- Update Name & Email ----------
@profile_routes.route("/update_profile", methods=["POST"])
def update_profile():
    data = request.get_json() or {}
    vendor_id = data.get("vendor_id")
    name = data.get("full_name")
    email = data.get("email")

    if not vendor_id:
        return jsonify({"error": "Missing vendor_id"}), 400

    try:
        res = supabase.table("vendors").update({
            "full_name": name,
            "email": email
        }).eq("id", vendor_id).execute()
        # supabase response may contain .error
        if getattr(res, "error", None):
            return jsonify({"error": str(res.error)}), 500
        return jsonify({"message": "Profile updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------- Send OTP to Current Number ----------
@profile_routes.route("/send_otp_current", methods=["POST"])
def send_otp_current():
    data = request.get_json() or {}
    phone = normalize_phone(data.get("phone"))
    if not phone:
        return jsonify({"error": "Missing phone"}), 400

    otp = generate_otp()
    otp_hash = hash_otp(phone, otp)
    otp_store[phone] = {"otp_hash": otp_hash, "timestamp": time.time()}

    msg = f"Your confirmation code to verify your number is {otp}. It expires in {OTP_EXPIRE_MINUTES} minutes."
    send_sms_with_fallback(phone, msg)
    return jsonify({"message": f"OTP sent to {phone}"}), 200

# ---------- Verify Current Number OTP ----------
@profile_routes.route("/verify_current_otp", methods=["POST"])
def verify_current_otp():
    data = request.get_json() or {}
    phone = normalize_phone(data.get("phone"))
    otp = data.get("otp")

    record = otp_store.get(phone)
    if not record:
        return jsonify({"error": "No OTP found"}), 400

    if time.time() - record["timestamp"] > OTP_EXPIRE_MINUTES * 60:
        del otp_store[phone]
        return jsonify({"error": "OTP expired"}), 400

    if hash_otp(phone, otp) != record["otp_hash"]:
        return jsonify({"error": "Invalid OTP"}), 400

    # keep record for next step (no deletion yet)
    return jsonify({"message": "Old number verified successfully"}), 200

# ---------- Send OTP to New Number ----------
@profile_routes.route("/send_otp_new", methods=["POST"])
def send_otp_new():
    data = request.get_json() or {}
    new_phone_raw = data.get("new_phone")
    vendor_id = data.get("vendor_id")

    new_phone = normalize_phone(new_phone_raw)
    if not new_phone or not vendor_id:
        return jsonify({"error": "Missing required fields"}), 400

    otp = generate_otp()
    otp_hash = hash_otp(new_phone, otp)
    otp_store[new_phone] = {
        "otp_hash": otp_hash,
        "timestamp": time.time(),
        "vendor_id": vendor_id
    }

    msg = f"Your confirmation code to update your number is {otp}. It expires in {OTP_EXPIRE_MINUTES} minutes."
    send_sms_with_fallback(new_phone, msg)
    return jsonify({"message": f"OTP sent to {new_phone}"}), 200

# ---------- Verify and Update New Phone ----------
@profile_routes.route("/verify_new_phone", methods=["POST"])
def verify_new_phone():
    data = request.get_json() or {}
    new_phone_raw = data.get("new_phone")
    otp = data.get("otp")

    new_phone = normalize_phone(new_phone_raw)
    record = otp_store.get(new_phone)
    if not record:
        return jsonify({"error": "No OTP found"}), 400

    if time.time() - record["timestamp"] > OTP_EXPIRE_MINUTES * 60:
        del otp_store[new_phone]
        return jsonify({"error": "OTP expired"}), 400

    if hash_otp(new_phone, otp) != record["otp_hash"]:
        return jsonify({"error": "Invalid OTP"}), 400

    try:
        upd = supabase.table("vendors").update({"phone": new_phone}).eq("id", record["vendor_id"]).execute()
        if getattr(upd, "error", None):
            return jsonify({"error": str(upd.error)}), 500
        del otp_store[new_phone]
        return jsonify({"message": "Phone number updated successfully", "phone": new_phone}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------- Update Password ----------
@profile_routes.route("/update_password", methods=["POST"])
def update_password():
    data = request.get_json() or {}
    vendor_id = data.get("vendor_id")
    current_password = data.get("current_password")
    new_password = data.get("new_password")

    if not all([vendor_id, current_password, new_password]):
        return jsonify({"error": "Missing fields"}), 400

    try:
        # read password_hash from vendors
        vr = supabase.table("vendors").select("password_hash").eq("id", vendor_id).single().execute()
        if getattr(vr, "error", None) or not vr.data:
            return jsonify({"error": "Vendor not found"}), 404
        vendor_row = vr.data
        stored_hash = vendor_row.get("password_hash") or vendor_row.get("password") or ""

        # verify
        if not stored_hash or not check_password_hash(stored_hash, current_password):
            return jsonify({"error": "Current password incorrect"}), 400

        # set new hashed password
        new_hash = generate_password_hash(new_password)
        ur = supabase.table("vendors").update({"password_hash": new_hash}).eq("id", vendor_id).execute()
        if getattr(ur, "error", None):
            return jsonify({"error": str(ur.error)}), 500

        return jsonify({"message": "Password updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
