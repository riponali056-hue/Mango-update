
import os
import json
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

import firebase_admin
from firebase_admin import credentials, db
from flask import Flask, jsonify, request, render_template


app = Flask(__name__)

DATABASE_URL = os.environ["FIREBASE_DATABASE_URL"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]
SERVICE_ACCOUNT_JSON = os.environ["FIREBASE_SERVICE_ACCOUNT_JSON"]


# Firebase initialization
if not firebase_admin._apps:
    service_account = json.loads(SERVICE_ACCOUNT_JSON)
    credential = credentials.Certificate(service_account)
    firebase_admin.initialize_app(
        credential,
        {"databaseURL": DATABASE_URL},
    )


def utc_now():
    return datetime.now(timezone.utc)


def parse_expiry(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        supplied = request.headers.get("X-Admin-Password", "")

        if not hmac.compare_digest(supplied, ADMIN_PASSWORD):
            return jsonify({"error": "Unauthorized"}), 401

        return fn(*args, **kwargs)

    return wrapper


def cleanup_expired_keys():
    """Permanently delete keys whose expiry time has passed."""
    records = db.reference("keys").get() or {}
    now = utc_now()
    deleted = 0

    for key, record in records.items():
        if not isinstance(record, dict):
            continue

        expiry = parse_expiry(record.get("expires_at"))

        if expiry and now >= expiry:
            db.reference("keys").child(key).delete()
            deleted += 1

    return deleted


@app.get("/")
def home():
    return render_template("index.html")


@app.get("/health")
def health():
    return jsonify({"name": "Mango-Update", "status": "online"})


@app.post("/admin/keys")
@admin_required
def create_key():
    data = request.get_json(silent=True) or {}

    try:
        days = int(data.get("days", 1))
    except (TypeError, ValueError):
        return jsonify({"error": "Days must be 1, 7, or 30"}), 400

    if days not in (1, 7, 30):
        return jsonify({"error": "Days must be 1, 7, or 30"}), 400

    key = "MANGO-" + secrets.token_urlsafe(18)
    created = utc_now()
    expires = created + timedelta(days=days)

    db.reference("keys").child(key).set({
        "status": "active",
        "days": days,
        "created_at": created.isoformat(),
        "expires_at": expires.isoformat(),
        "device_id": None,
    })

    return jsonify({
        "key": key,
        "status": "active",
        "days": days,
        "expires_at": expires.isoformat(),
    }), 201


@app.get("/admin/keys")
@admin_required
def list_keys():
    records = db.reference("keys").get() or {}
    result = []

    for key, record in records.items():
        if not isinstance(record, dict):
            continue

        expiry = parse_expiry(record.get("expires_at"))
        status = record.get("status", "unknown")

        if expiry and utc_now() >= expiry:
            status = "expired"

        result.append({
            "key": key,
            "status": status,
            "days": record.get("days"),
            "expires_at": record.get("expires_at"),
            "device_locked": bool(record.get("device_id")),
        })

    return jsonify(result)

@app.post("/admin/revoke")
@admin_required
def revoke_key():
    data = request.get_json(silent=True) or {}
    key = str(data.get("key", "")).strip()

    if not key or "/" in key or "." in key or "#" in key:
        return jsonify({"error": "Invalid key"}), 400

    ref = db.reference("keys").child(key)

    if ref.get() is None:
        return jsonify({"error": "Key not found"}), 404

    ref.update({"status": "revoked"})
    return jsonify({"success": True, "status": "revoked"})


@app.post("/admin/delete")
@admin_required
def delete_key():
    data = request.get_json(silent=True) or {}
    key = str(data.get("key", "")).strip()

    if not key or "/" in key or "." in key or "#" in key:
        return jsonify({"error": "Invalid key"}), 400

    ref = db.reference("keys").child(key)

    if ref.get() is None:
        return jsonify({"error": "Key not found"}), 404

    ref.delete()
    return jsonify({"success": True, "deleted": key})


@app.post("/admin/cleanup")
@admin_required
def cleanup_keys():
    count = cleanup_expired_keys()
    return jsonify({
        "success": True,
        "deleted_count": count,
    })


@app.post("/api/validate")
def validate_key():
    data = request.get_json(silent=True) or {}
    key = str(data.get("key", "")).strip()
    device_id = str(data.get("device_id", "")).strip()

    if not key or not device_id or len(device_id) > 256:
        return jsonify({
            "valid": False,
            "error": "key and device_id required",
        }), 400

    ref = db.reference("keys").child(key)
    record = ref.get()

    if not isinstance(record, dict):
        return jsonify({"valid": False, "error": "Invalid key"}), 403

    if record.get("status") != "active":
        return jsonify({
            "valid": False,
            "error": "Key revoked or inactive",
        }), 403

    expiry = parse_expiry(record.get("expires_at"))

    if not expiry:
        return jsonify({"valid": False, "error": "Invalid expiry"}), 500

    if utc_now() >= expiry:
        ref.update({"status": "expired"})
        return jsonify({"valid": False, "error": "Key expired"}), 403

    saved_device = record.get("device_id")

    if saved_device and not hmac.compare_digest(saved_device, device_id):
        return jsonify({
            "valid": False,
            "error": "Key bound to another device",
        }), 403

    if not saved_device:
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
            return jsonify({
                "valid": False,
                "error": "Device binding failed",
            }), 403

    return jsonify({
        "valid": True,
        "status": "active",
        "expires_at": record["expires_at"],
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "10000")),
    )
