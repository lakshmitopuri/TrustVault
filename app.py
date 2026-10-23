import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import (
    URLSafeTimedSerializer,
    BadSignature,
    SignatureExpired,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///" + str(BASE_DIR / "trustvault.db")
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

app.config["SECRET_KEY"] = os.environ.get(
    "TRUSTVAULT_SECRET_KEY",
    "development-only-change-this-key"
)

db = SQLAlchemy(app)
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

ALLOWED_EXTENSIONS = {
    ".pdf", ".txt", ".docx", ".png", ".jpg", ".jpeg"
}


# -------------------- DATABASE MODELS --------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), nullable=False, default="user")


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), unique=True, nullable=False)
    owner_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False
    )
    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(100), nullable=False)
    document_id = db.Column(db.Integer, nullable=True)
    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )


class DocumentPermission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(
        db.Integer,
        db.ForeignKey("document.id"),
        nullable=False
    )
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )
    permission = db.Column(
        db.String(20), nullable=False, default="view"
    )

    __table_args__ = (
        db.UniqueConstraint(
            "document_id",
            "user_id",
            name="unique_document_user_permission"
        ),
    )


# -------------------- HELPER FUNCTIONS --------------------

def create_audit_log(user_id, action, document_id=None):
    db.session.add(
        AuditLog(
            user_id=user_id,
            action=action,
            document_id=document_id
        )
    )


def get_current_user():
    header = request.headers.get("Authorization", "")

    if not header.startswith("Bearer "):
        return None

    token = header[7:]

    try:
        data = serializer.loads(token, max_age=3600)
        return db.session.get(User, data.get("user_id"))
    except (BadSignature, SignatureExpired):
        return None


def has_document_access(user, document, required_permission="view"):
    if document.owner_id == user.id:
        return True

    permission = DocumentPermission.query.filter_by(
        document_id=document.id,
        user_id=user.id
    ).first()

    if not permission:
        return False

    if required_permission == "edit":
        return permission.permission == "edit"

    return permission.permission in ("view", "edit")


def document_to_dict(document):
    return {
        "id": document.id,
        "filename": document.filename,
        "owner_id": document.owner_id,
        "created_at": document.created_at.isoformat()
    }


# -------------------- HOME AND HEALTH --------------------

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "app": "TrustVault",
        "message": "Backend is running"
    })


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "message": "TrustVault backend is running"
    })


# -------------------- AUTHENTICATION --------------------

@app.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")

    if not email or "@" not in email:
        return jsonify({"error": "Enter a valid email address"}), 400

    if not isinstance(password, str) or len(password) < 8:
        return jsonify({
            "error": "Password must contain at least 8 characters"
        }), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email is already registered"}), 409

    user = User(
        email=email,
        password_hash=generate_password_hash(password),
        role="user"
    )

    db.session.add(user)
    db.session.flush()

    create_audit_log(user.id, "USER_REGISTERED")
    db.session.commit()

    return jsonify({
        "message": "Registration successful",
        "user": {
            "id": user.id,
            "email": user.email,
            "role": user.role
        }
    }), 201


@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")

    user = User.query.filter_by(email=email).first()

    if (
        not user
        or not isinstance(password, str)
        or not check_password_hash(user.password_hash, password)
    ):
        return jsonify({"error": "Invalid email or password"}), 401

    token = serializer.dumps({"user_id": user.id})

    create_audit_log(user.id, "USER_LOGIN")
    db.session.commit()

    return jsonify({
        "message": "Login successful",
        "access_token": token,
        "token_type": "Bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "role": user.role
        }
    })


@app.route("/auth/me", methods=["GET"])
def me():
    user = get_current_user()

    if not user:
        return jsonify({"error": "Valid login token required"}), 401

    return jsonify({
        "id": user.id,
        "email": user.email,
        "role": user.role
    })


@app.route("/auth/admin", methods=["GET"])
def admin():
    user = get_current_user()

    if not user:
        return jsonify({"error": "Valid login token required"}), 401

    if user.role != "admin":
        return jsonify({"error": "Admin access required"}), 403

    return jsonify({"message": "Welcome, admin"})


# -------------------- DOCUMENT UPLOAD --------------------

@app.route("/documents/upload", methods=["POST"])
def upload_document():
    user = get_current_user()

    if not user:
        return jsonify({"error": "Valid login token required"}), 401

    if "file" not in request.files:
        return jsonify({"error": "Choose a file to upload"}), 400

    file = request.files["file"]

    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    safe_name = secure_filename(file.filename)

    if not safe_name:
        return jsonify({"error": "Invalid filename"}), 400

    extension = Path(safe_name).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        return jsonify({"error": "File type not allowed"}), 400

    stored_name = uuid.uuid4().hex + extension
    file_path = UPLOAD_DIR / stored_name

    try:
        file.save(file_path)

        document = Document(
            filename=safe_name,
            stored_name=stored_name,
            owner_id=user.id
        )

        db.session.add(document)
        db.session.flush()

        create_audit_log(
            user.id, "DOCUMENT_UPLOADED", document.id
        )
        db.session.commit()

    except Exception:
        db.session.rollback()

        if file_path.exists():
            file_path.unlink()

        app.logger.exception("Document upload failed")
        return jsonify({"error": "Document upload failed"}), 500

    return jsonify({
        "message": "Document uploaded successfully",
        "document": document_to_dict(document)
    }), 201


# -------------------- LIST DOCUMENTS --------------------

@app.route("/documents/", methods=["GET"])
def list_documents():
    user = get_current_user()

    if not user:
        return jsonify({"error": "Valid login token required"}), 401

    owned = Document.query.filter_by(owner_id=user.id).all()

    permissions = DocumentPermission.query.filter_by(
        user_id=user.id
    ).all()

    shared_ids = [p.document_id for p in permissions]

    shared = []
    if shared_ids:
        shared = Document.query.filter(
            Document.id.in_(shared_ids)
        ).all()

    documents = {doc.id: doc for doc in owned + shared}

    return jsonify([
        document_to_dict(doc)
        for doc in sorted(
            documents.values(),
            key=lambda item: item.id,
            reverse=True
        )
    ])


# -------------------- SHARE AND REVOKE PERMISSIONS --------------------

@app.route(
    "/documents/<int:document_id>/permissions",
    methods=["POST"]
)
def grant_document_permission(document_id):
    user = get_current_user()

    if not user:
        return jsonify({"error": "Valid login token required"}), 401

    document = db.session.get(Document, document_id)

    if not document:
        return jsonify({"error": "Document not found"}), 404

    if document.owner_id != user.id:
        return jsonify({
            "error": "Only the document owner can change permissions"
        }), 403

    data = request.get_json(silent=True) or {}
    target_email = str(data.get("email", "")).strip().lower()
    permission_type = data.get("permission", "view")

    if permission_type not in ("view", "edit"):
        return jsonify({
            "error": "Permission must be 'view' or 'edit'"
        }), 400

    target_user = User.query.filter_by(email=target_email).first()

    if not target_user:
        return jsonify({
            "error": "Recipient must register before sharing"
        }), 404

    if target_user.id == user.id:
        return jsonify({
            "error": "You already own this document"
        }), 400

    permission = DocumentPermission.query.filter_by(
        document_id=document.id,
        user_id=target_user.id
    ).first()

    try:
        if permission:
            permission.permission = permission_type
        else:
            permission = DocumentPermission(
                document_id=document.id,
                user_id=target_user.id,
                permission=permission_type
            )
            db.session.add(permission)

        create_audit_log(
            user.id,
            "DOCUMENT_SHARED_" + permission_type.upper(),
            document.id
        )
        db.session.commit()

    except Exception:
        db.session.rollback()
        app.logger.exception("Permission update failed")
        return jsonify({"error": "Could not update permission"}), 500

    return jsonify({
        "message": "Document shared successfully",
        "document_id": document.id,
        "recipient": target_user.email,
        "permission": permission_type
    })


@app.route(
    "/documents/<int:document_id>/permissions",
    methods=["DELETE"]
)
def revoke_document_permission(document_id):
    user = get_current_user()

    if not user:
        return jsonify({"error": "Valid login token required"}), 401

    document = db.session.get(Document, document_id)

    if not document:
        return jsonify({"error": "Document not found"}), 404

    if document.owner_id != user.id:
        return jsonify({
            "error": "Only the document owner can revoke permissions"
        }), 403

    data = request.get_json(silent=True) or {}
    target_email = str(data.get("email", "")).strip().lower()

    target_user = User.query.filter_by(email=target_email).first()

    if not target_user:
        return jsonify({"error": "Recipient not found"}), 404

    permission = DocumentPermission.query.filter_by(
        document_id=document.id,
        user_id=target_user.id
    ).first()

    if not permission:
        return jsonify({"error": "Permission does not exist"}), 404

    try:
        db.session.delete(permission)
        create_audit_log(
            user.id, "DOCUMENT_PERMISSION_REVOKED", document.id
        )
        db.session.commit()

    except Exception:
        db.session.rollback()
        app.logger.exception("Permission revocation failed")
        return jsonify({"error": "Could not revoke permission"}), 500

    return jsonify({
        "message": "Document access revoked successfully"
    })


# -------------------- SECURE DOCUMENT DOWNLOAD --------------------

@app.route(
    "/documents/<int:document_id>/download",
    methods=["GET"]
)
def download_document(document_id):
    user = get_current_user()

    if not user:
        return jsonify({"error": "Valid login token required"}), 401

    document = db.session.get(Document, document_id)

    if not document:
        return jsonify({"error": "Document not found"}), 404

    if not has_document_access(user, document, "view"):
        return jsonify({"error": "You do not have access to this document"}), 403

    file_path = UPLOAD_DIR / document.stored_name

    if not file_path.is_file():
        return jsonify({"error": "Stored file not found"}), 404

    create_audit_log(user.id, "DOCUMENT_DOWNLOADED", document.id)
    db.session.commit()

    return send_from_directory(
        str(UPLOAD_DIR),
        document.stored_name,
        as_attachment=True,
        download_name=document.filename
    )


# -------------------- ADMIN AUDIT LOG --------------------

@app.route("/audit", methods=["GET"])
def audit():
    user = get_current_user()

    if not user:
        return jsonify({"error": "Valid login token required"}), 401

    if user.role != "admin":
        return jsonify({"error": "Admin access required"}), 403

    logs = AuditLog.query.order_by(
        AuditLog.id.desc()
    ).limit(100).all()

    return jsonify([
        {
            "id": log.id,
            "user_id": log.user_id,
            "action": log.action,
            "document_id": log.document_id,
            "created_at": log.created_at.isoformat()
        }
        for log in logs
    ])


# -------------------- DATABASE AND SERVER --------------------

with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)