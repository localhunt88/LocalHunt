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

def hash_otp(phone, otp):
    return hashlib.sha256(f"{otp}{phone}{OTP_HASH_SALT}".encode()).hexdigest()

def normalize_phone(phone: str) -> str:
    if not phone:
        return ""
    phone = phone.strip().replace(" ", "").replace("-", "")
    if phone.startswith("+91") and len(phone) == 13:
        return phone
    if phone.startswith("91") and len(phone) == 12:
        return f"+{phone}"
    if len(phone) == 10 and phone.isdigit():
        return f"+91{phone}"
    if phone.startswith("+") and not phone.startswith("+91"):
        digits = ''.join(filter(str.isdigit, phone))
        if len(digits) >= 10:
            return f"+91{digits[-10:]}"
        else:
            return f"+91{digits}"
    digits = ''.join(filter(str.isdigit, phone))
    if len(digits) >= 10:
        return f"+91{digits[-10:]}"
    return f"+91{digits}"

def generate_otp():
    return f"{random.randint(1000, 9999)}"

# ========== VENDOR PROFILE & OTP ==========

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
            "full_name": name, "email": email
        }).eq("id", vendor_id).execute()
        if getattr(res, "error", None):
            return jsonify({"error": str(res.error)}), 500
        return jsonify({"message": "Profile updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
    return jsonify({"message": "Old number verified successfully"}), 200

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

# ========== USER PROFILE & OTP, SMS FORMAT SAME AS VENDOR ==========

@profile_routes.route("/update_user_profile", methods=["POST"])
def update_user_profile():
    data = request.get_json() or {}
    user_id = data.get("user_id")
    email = data.get("email")
    updates = {"email": email}
    if "full_name" in data:
        updates["full_name"] = data["full_name"]
    if not user_id or not email:
        return jsonify({"error": "Missing user_id or email"}), 400
    try:
        res = supabase.table("users").update(updates).eq("id", user_id).execute()
        if getattr(res, "error", None):
            return jsonify({"error": str(res.error)}), 500
        return jsonify({"message": "User profile updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@profile_routes.route("/send_otp_current_user", methods=["POST"])
def send_otp_current_user():
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

@profile_routes.route("/verify_current_otp_user", methods=["POST"])
def verify_current_otp_user():
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
    return jsonify({"message": "Old number verified successfully"}), 200

@profile_routes.route("/send_otp_new_user", methods=["POST"])
def send_otp_new_user():
    data = request.get_json() or {}
    new_phone_raw = data.get("new_phone")
    user_id = data.get("user_id")
    new_phone = normalize_phone(new_phone_raw)
    if not new_phone or not user_id:
        return jsonify({"error": "Missing required fields"}), 400
    otp = generate_otp()
    otp_hash = hash_otp(new_phone, otp)
    otp_store[new_phone] = {
        "otp_hash": otp_hash,
        "timestamp": time.time(),
        "user_id": user_id
    }
    msg = f"Your confirmation code to update your number is {otp}. It expires in {OTP_EXPIRE_MINUTES} minutes."
    send_sms_with_fallback(new_phone, msg)
    return jsonify({"message": f"OTP sent to {new_phone}"}), 200

@profile_routes.route("/verify_new_phone_user", methods=["POST"])
def verify_new_phone_user():
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
        upd = supabase.table("users").update({"phone": new_phone}).eq("id", record["user_id"]).execute()
        if getattr(upd, "error", None):
            return jsonify({"error": str(upd.error)}), 500
        del otp_store[new_phone]
        return jsonify({"message": "Phone number updated successfully", "phone": new_phone}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
