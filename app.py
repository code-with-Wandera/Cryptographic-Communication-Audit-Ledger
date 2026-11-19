import hashlib
import os
from dotenv import load_dotenv
load_dotenv()
from datetime import datetime, timezone
import psycopg
from psycopg.rows import dict_row
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "port": int(os.environ.get("DB_PORT", 5432)),
    "dbname": os.environ.get("DB_NAME", "gov_comm_db"),
    "user": os.environ.get("DB_USER", "postgres"),
    "password": os.environ.get("DB_PASSWORD", "postgres"),
}

GENESIS_HASH = hashlib.sha256(b"GENESIS_GOV_COMM_LEDGER_V1").hexdigest()


def get_db_connection():
    return psycopg.connect(**DB_CONFIG, row_factory=dict_row)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(filepath: str) -> str | None:
    if not filepath or not os.path.exists(filepath):
        return None
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_expected_message_hash(row: dict) -> str:
    created_str = row["created_at"].strftime("%Y-%m-%d %H:%M:%S.%f") if isinstance(row["created_at"], datetime) else str(row["created_at"])
    file_digest = row["file_sha256"] if row["file_sha256"] else "NO_FILE"
    payload = (
        f"{row['sender_id']}|"
        f"{row['channel_name']}|"
        f"{row['message_body']}|"
        f"{file_digest}|"
        f"{row['prev_hash'].strip()}|"
        f"{created_str}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def run_verification(record_alerts: bool = True) -> dict:
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT m.*, u.full_name AS sender_name, u.account_status
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        ORDER BY m.id ASC
    """)
    messages = cur.fetchall()

    cur.execute("""
        SELECT sf.*, u.full_name AS uploader_name
        FROM shared_files sf
        JOIN users u ON sf.uploaded_by = u.id
        ORDER BY sf.id ASC
    """)
    files = cur.fetchall()

    message_results = []
    file_results = []
    issues = []

    expected_prev_hash = GENESIS_HASH

    for msg in messages:
        msg_id = msg["id"]
        stored_prev = (msg["prev_hash"] or "").strip()
        stored_curr = (msg["current_hash"] or "").strip()
        recomputed_curr = compute_expected_message_hash(msg)

        chain_ok = (stored_prev == expected_prev_hash)
        digest_ok = (stored_curr == recomputed_curr)
        sender_compromised = (msg["account_status"] == "COMPROMISED")

        status = "VERIFIED"
        reasons = []

        if not chain_ok:
            status = "TAMPERED"
            reasons.append(f"Broken chain (expected prev_hash {expected_prev_hash[:12]}..., got {stored_prev[:12]}...)")
            issues.append(("CHAIN_BROKEN", "messages", str(msg_id), f"Message #{msg_id}: {reasons[-1]}"))

        if not digest_ok:
            status = "TAMPERED"
            reasons.append("Message content or metadata hash mismatch")
            issues.append(("HASH_MISMATCH", "messages", str(msg_id), f"Message #{msg_id} content altered after signing"))

        if sender_compromised:
            if status == "VERIFIED":
                status = "FLAGGED_COMPROMISED"
            reasons.append(f"Sent by COMPROMISED account ({msg['sender_name']})")
            issues.append(("COMPROMISED_SENDER", "messages", str(msg_id), f"Message #{msg_id} sent by compromised user {msg['sender_name']}"))

        message_results.append({
            "id": msg_id,
            "sender_name": msg["sender_name"],
            "channel_name": msg["channel_name"],
            "message_body": msg["message_body"],
            "created_at": str(msg["created_at"]),
            "prev_hash": stored_prev,
            "current_hash": stored_curr,
            "expected_hash": recomputed_curr,
            "status": status,
            "reasons": reasons,
        })

        # Advance expected hash for the next row in sequence
        expected_prev_hash = stored_curr

    for f in files:
        disk_hash = sha256_file(f["stored_path"])
        recorded_hash = (f["file_sha256"] or "").strip()

        if disk_hash is None:
            f_status = "MISSING_FILE"
            f_reason = f"File missing on disk at {f['stored_path']}"
            issues.append(("FILE_TAMPERED", "shared_files", str(f["id"]), f_reason))
        elif disk_hash != recorded_hash:
            f_status = "TAMPERED"
            f_reason = f"Digest mismatch (recorded {recorded_hash[:12]}..., actual {disk_hash[:12]}...)"
            issues.append(("FILE_TAMPERED", "shared_files", str(f["id"]), f"File '{f['filename']}' (#{f['id']}): {f_reason}"))
        else:
            f_status = "AUTHENTIC"
            f_reason = "SHA-256 digest matches original file"

        file_results.append({
            "id": f["id"],
            "filename": f["filename"],
            "uploader_name": f["uploader_name"],
            "recorded_sha256": recorded_hash,
            "actual_sha256": disk_hash or "MISSING",
            "status": f_status,
            "reason": f_reason,
        })

    if record_alerts and issues:
        # Clear previous auto-generated alerts before writing fresh audit findings
        cur.execute("DELETE FROM tamper_alerts")
        for alert_type, target_table, target_id, details in issues:
            cur.execute(
                """INSERT INTO tamper_alerts (alert_type, target_table, target_id, details)
                   VALUES (%s, %s, %s, %s)""",
                (alert_type, target_table, target_id, details),
            )
        conn.commit()
    elif record_alerts and not issues:
        cur.execute("DELETE FROM tamper_alerts")
        conn.commit()

    cur.execute("SELECT * FROM tamper_alerts ORDER BY id DESC")
    alerts = cur.fetchall()

    cur.close()
    conn.close()

    return {
        "overall_integrity": "COMPROMISED" if any(m["status"] != "VERIFIED" for m in message_results) or any(fl["status"] != "AUTHENTIC" for fl in file_results) else "INTACT",
        "messages": message_results,
        "files": file_results,
        "alerts": alerts,
    }


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/users", methods=["GET"])
def get_users():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users ORDER BY id ASC")
    users = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(users)


@app.route("/api/messages", methods=["POST"])
def create_message():
    data = request.get_json(force=True)
    sender_id = data.get("sender_id")
    channel_name = data.get("channel_name", "General-Ops")
    message_body = data.get("message_body", "").strip()
    file_sha256 = data.get("file_sha256")
    auth_context = data.get("auth_context", "NORMAL_SESSION")

    if not sender_id or not message_body:
        return jsonify({"error": "sender_id and message_body are required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO messages (sender_id, channel_name, message_body, file_sha256, prev_hash, current_hash, auth_context)
           VALUES (%s, %s, %s, %s, '', '', %s)
           RETURNING *""",
        (sender_id, channel_name, message_body, file_sha256, auth_context),
    )
    created = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(created), 201


@app.route("/api/files/upload", methods=["POST"])
def upload_shared_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    uploaded = request.files["file"]
    sender_id = request.form.get("sender_id", type=int)
    channel_name = request.form.get("channel_name", "Document-Room")
    note = request.form.get("note", f"Shared file: {uploaded.filename}")

    if not sender_id or uploaded.filename == "":
        return jsonify({"error": "sender_id and a valid file are required"}), 400

    raw_bytes = uploaded.read()
    digest = sha256_bytes(raw_bytes)
    safe_name = f"{int(datetime.now(timezone.utc).timestamp())}_{os.path.basename(uploaded.filename)}"
    save_path = os.path.join(UPLOAD_FOLDER, safe_name)

    with open(save_path, "wb") as f:
        f.write(raw_bytes)

    conn = get_db_connection()
    cur = conn.cursor()

    # Log the message with the file's SHA-256 digest sealed inside the hash chain
    cur.execute(
        """INSERT INTO messages (sender_id, channel_name, message_body, file_sha256, prev_hash, current_hash, auth_context)
           VALUES (%s, %s, %s, %s, '', '', 'FILE_UPLOAD')
           RETURNING *""",
        (sender_id, channel_name, note, digest),
    )
    msg = cur.fetchone()

    cur.execute(
        """INSERT INTO shared_files (message_id, uploaded_by, filename, stored_path, file_sha256)
           VALUES (%s, %s, %s, %s, %s)
           RETURNING *""",
        (msg["id"], sender_id, uploaded.filename, save_path, digest),
    )
    file_record = cur.fetchone()

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"message": msg, "file": file_record}), 201


@app.route("/api/verify", methods=["GET", "POST"])
def verify_ledger():
    report = run_verification(record_alerts=True)
    return jsonify(report)


if __name__ == "__main__":
    app.run(debug=True, port=5000)