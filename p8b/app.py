# app.py
from flask import Flask, request, jsonify
import jwt, datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

JWT_SECRET = "change_this_super_secret_in_prod"
JWT_ALGO = "HS256"
JWT_EXP_MINUTES = 60

app = Flask(__name__)
USERS = {
    "admin": {"password_hash": generate_password_hash("adminpass"), "role": "admin"},
}

def create_token(username, role):
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=JWT_EXP_MINUTES)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def decode_token(token):
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])

def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error":"Missing Bearer token"}), 401
        token = auth.split()[1]
        try:
            payload = decode_token(token)
            request.user = payload
        except Exception as e:
            return jsonify({"error":"Invalid or expired token", "detail":str(e)}), 401
        return f(*args, **kwargs)
    return wrapper

def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if request.user.get("role") != role:
                return jsonify({"error":"Forbidden"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username, password = data.get("username"), data.get("password")
    if username in USERS: return jsonify({"error":"user exists"}), 400
    USERS[username] = {"password_hash": generate_password_hash(password), "role":"user"}
    return jsonify({"ok":True})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username, password = data.get("username"), data.get("password")
    user = USERS.get(username)
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error":"invalid credentials"}), 401
    return jsonify({"access_token": create_token(username, user["role"])})

@app.route("/profile")
@auth_required
def profile():
    return jsonify({"username": request.user["sub"], "role": request.user["role"]})

@app.route("/admin")
@auth_required
@role_required("admin")
def admin_area():
    return jsonify({"msg":"Welcome, admin!"})

if __name__ == "__main__":
    app.run(port=5000, debug=True)
