# routes/login_routes.py
from flask import Blueprint, request, jsonify
from supabase import create_client
from werkzeug.security import check_password_hash
import os

# ✅ Initialize Supabase client
from supabase_client import supabase

login_bp = Blueprint("login_bp", __name__)

# 🔹 HELPER FUNCTION TO FORMAT USER DATA
def format_user_data(user_data, user_type):
    """Format user data for frontend response"""
    return {
        "id": user_data.get("id"),
        "user_id": user_data.get("id"),  # Alternative ID field
        "email": user_data.get("email"),
        "phone": user_data.get("phone"),
        "user_type": user_type,
        "full_name": user_data.get("full_name", ""),
        "avatar_url": user_data.get("avatar_url", ""),
        "shop_built": user_data.get("shop_built", False),
        "created_at": user_data.get("created_at"),
        "updated_at": user_data.get("updated_at")
    }

# 🔹 LOGIN BY EMAIL
@login_bp.route("/login/email", methods=["POST"])
def login_email():
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"success": False, "message": "Email and password required"}), 400

        # 1️⃣ Try USERS table
        user_res = supabase.table("users").select("*").eq("email", email).execute()
        if user_res.data:
            user = user_res.data[0]
            if check_password_hash(user["password_hash"], password):
                # ✅ Return complete user data
                user_data = format_user_data(user, "user")
                return jsonify({
                    "success": True,
                    **user_data,  # Spread all user data
                    "redirect": "/user-dashboard",
                    "message": "User login successful"
                }), 200
            else:
                return jsonify({"success": False, "message": "Invalid password"}), 401

        # 2️⃣ Try VENDORS table
        vendor_res = supabase.table("vendors").select("*").eq("email", email).execute()
        if vendor_res.data:
            vendor = vendor_res.data[0]
            if check_password_hash(vendor["password_hash"], password):
                # ✅ Return complete vendor data
                vendor_data = format_user_data(vendor, "vendor")
                return jsonify({
                    "success": True,
                    **vendor_data,  # Spread all vendor data
                    "redirect": "/vendor-dashboard",
                    "message": "Vendor login successful"
                }), 200
            else:
                return jsonify({"success": False, "message": "Invalid password"}), 401

        return jsonify({"success": False, "message": "Account not found"}), 404

    except Exception as e:
        print("❌ Error in /login/email:", e)
        return jsonify({"success": False, "message": "Server error"}), 500


# 🔹 LOGIN BY PHONE
@login_bp.route("/login/phone", methods=["POST"])
def login_phone():
    try:
        data = request.get_json()
        phone = data.get("phone")
        password = data.get("password")

        if not phone or not password:
            return jsonify({"success": False, "message": "Phone and password required"}), 400

        # 1️⃣ Try USERS table
        user_res = supabase.table("users").select("*").eq("phone", phone).execute()
        if user_res.data:
            user = user_res.data[0]
            if check_password_hash(user["password_hash"], password):
                # ✅ Return complete user data
                user_data = format_user_data(user, "user")
                return jsonify({
                    "success": True,
                    **user_data,  # Spread all user data
                    "redirect": "/user-dashboard",
                    "message": "User login successful"
                }), 200
            else:
                return jsonify({"success": False, "message": "Invalid password"}), 401

        # 2️⃣ Try VENDORS table
        vendor_res = supabase.table("vendors").select("*").eq("phone", phone).execute()
        if vendor_res.data:
            vendor = vendor_res.data[0]
            if check_password_hash(vendor["password_hash"], password):
                # ✅ Return complete vendor data
                vendor_data = format_user_data(vendor, "vendor")
                return jsonify({
                    "success": True,
                    **vendor_data,  # Spread all vendor data
                    "redirect": "/vendor-dashboard",
                    "message": "Vendor login successful"
                }), 200
            else:
                return jsonify({"success": False, "message": "Invalid password"}), 401

        return jsonify({"success": False, "message": "Account not found"}), 404

    except Exception as e:
        print("❌ Error in /login/phone:", e)
        return jsonify({"success": False, "message": "Server error"}), 500