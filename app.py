from flask import Flask, jsonify
from flask_cors import CORS
from routes.otp_routes import bp as otp_bp
from routes.signup_routes import signup_bp
from routes.login_routes import login_bp
from routes.password_reset_routes import bp as password_reset_bp
from routes.profile_routes import profile_routes

app = Flask(__name__)

# Allow all frontend origins (fixes CORS error)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# ✅ Lightweight health-check / warm-up route
@app.route("/ping")
def ping():
    return jsonify({"status": "ok"}), 200

# Register blueprints
app.register_blueprint(otp_bp)
app.register_blueprint(signup_bp)
app.register_blueprint(login_bp)
app.register_blueprint(password_reset_bp)
app.register_blueprint(profile_routes, url_prefix="/profile")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
