import os
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

import firebase_admin
from firebase_admin import credentials, db
from flask import Flask, jsonify, request

app = Flask(__name__)

DATABASE_URL = os.environ["FIREBASE_DATABASE_URL"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]
SERVICE_ACCOUNT_JSON = os.environ["FIREBASE_SERVICE_ACCOUNT_JSON"]

credential = credentials.Certificate(
    __import__("json").loads(SERVICE_ACCOUNT_JSON)
)

firebase_admin.initialize_app(
    credential,
    {"databaseURL": DATABASE_URL},
)


def utc_now():
    return datetime.now(timezone.utc)


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        supplied = request.headers.get("X-Admin-Password", "")
        if not hmac.compare_digest(supplied, ADMIN_PASSWORD):
            return jsonify({"error": "Unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper


@app.get("/")
def home():
    return jsonify({
        "name": "Mango-Update",
        "status": "online"
    })


@app.post("/admin/keys")
@admin_required
def create_key():
    data = request.get_json(silent=True) or {}

    try:
        days = int(data.get("days", 1))
    except (TypeError, ValueError):
        return jsonify({"error": "days must be 1, 7, or 30"}), 400

    if days not in (1, 7, 30):
        return jsonify({"error": "days must be 1, 7, or 30"}), 400

    key = "MANGO-" + secrets.token_urlsafe(18)
    expires_at = (utc_now() + timedelta(days=days)).isoformat()

    db.reference("keys/" + key).set({
        "status": "active",
        "days": days,
        "created_at": utc_now().isoformat(),
        "expires_at": expires_at,
        "device_id": None,
    })

    return jsonify({
        "key": key,
        "days": days,
        "expires_at": expires_at,
    }), 201


@app.get("/admin/keys")
@admin_required
def list_keys():
    records = db.reference("keys").get() or {}
    result = []

    for key, value in records.items():
        result.append({
            "key": key,
            "status": value.get("status"),
            "days": value.get("days"),
            "expires_at": value.get("expires_at"),
            "device_locked": bool(value.get("device_id")),
        })

    return jsonify(result)


@app.post("/admin/revoke")
@admin_required
def revoke_key():
    data = request.get_json(silent=True) or {}
    key = str(data.get("key", "")).strip()

    if not key:
        return jsonify({"error": "key required"}), 400

    ref = db.reference("keys/" + key)
    record = ref.get()

    if not record:
        return jsonify({"error": "Key not found"}), 404

    ref.update({"status": "revoked"})
    return jsonify({"status": "revoked", "key": key})


@app.post("/api/validate")
def validate_key():
    data = request.get_json(silent=True) or {}
    key = str(data.get("key", "")).strip()
    device_id = str(data.get("device_id", "")).strip()

    if not key or not device_id or len(device_id) > 256:
        return jsonify({"valid": False, "error": "key and device_id required"}), 400

    ref = db.reference("keys/" + key)
    record = ref.get()

    if not record:
        return jsonify({"valid": False, "error": "Invalid key"}), 403

    if record.get("status") != "active":
        return jsonify({"valid": False, "error": "Key revoked or inactive"}), 403

    try:
        expires_at = datetime.fromisoformat(
            record["expires_at"].replace("Z", "+00:00")
        )
    except (KeyError, ValueError, TypeError):
        return jsonify({"valid": False, "error": "Invalid expiry data"}), 500

    if utc_now() >= expires_at:
        ref.update({"status": "expired"})
        return jsonify({"valid": False, "error": "Key expired"}), 403

    saved_device = record.get("device_id")

    if saved_device and not hmac.compare_digest(saved_device, device_id):
        return jsonify({"valid": False, "error": "Key bound to another device"}), 403

    if not saved_device:
        # Atomic transaction prevents two devices claiming the same key concurrently.
        def bind_device(current):
            if current is None:
                return current
            if current.get("status") != "active":
                return current
            if current.get("device_id") is None:
                current["device_id"] = device_id
            return current

        record = ref.transaction(bind_device)

        if not record or record.get("device_id") != device_id:
            return jsonify({"valid": False, "error": "Device binding failed"}), 403

    return jsonify({
        "valid": True,
        "status": "active",
        "expires_at": record["expires_at"],
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "10000"))
      )
