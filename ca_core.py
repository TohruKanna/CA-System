import os
import re
import json
import shutil
import sqlite3
import logging
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# ---- paths ----
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
ISSUED_DIR = os.path.join(DATA_DIR, "issued")
REVOKED_DIR = os.path.join(DATA_DIR, "revoked")
USERS_DIR = os.path.join(DATA_DIR, "users")
CA_CERT_PATH = os.path.join(DATA_DIR, "ca_cert.pem")
CA_KEY_PATH = os.path.join(DATA_DIR, "ca_key.pem")
INT_CA_CERT_PATH = os.path.join(DATA_DIR, "int_ca_cert.pem")
INT_CA_KEY_PATH = os.path.join(DATA_DIR, "int_ca_key.pem")
CRL_PATH = os.path.join(DATA_DIR, "crl.pem")
DB_PATH = os.path.join(DATA_DIR, "ca.db")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(ISSUED_DIR, exist_ok=True)
os.makedirs(REVOKED_DIR, exist_ok=True)
os.makedirs(USERS_DIR, exist_ok=True)

logger = logging.getLogger("ca_core")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    logger.addHandler(ch)


# ---------------- Safety helpers ----------------
def safe_basename(fname: str) -> str:
    """Return sanitized basename (strip directory, keep only safe characters)."""
    if not fname:
        return ""
    b = os.path.basename(fname)
    # allow letters, numbers, dots, hyphen, underscore, parentheses and spaces
    b = re.sub(r'[^A-Za-z0-9_.\-@() ]+', '_', b)
    return b


def safe_join(base_dir: str, filename: str) -> str:
    """Join and ensure the resulting path is inside base_dir (prevent path traversal)."""
    filename = safe_basename(filename)
    base = os.path.abspath(base_dir)
    path = os.path.abspath(os.path.join(base, filename))
    if not path.startswith(base):
        raise ValueError("Illegal path access attempt")
    return path


# ---------- Database ----------
def init_db():
    """Create sqlite DB and applications table if missing (compatible with original schema)."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
              CREATE TABLE IF NOT EXISTS applications
              (
                  id
                  INTEGER
                  PRIMARY
                  KEY
                  AUTOINCREMENT,
                  name
                  TEXT,
                  email
                  TEXT,
                  pubkey_path
                  TEXT,
                  docs_json
                  TEXT,
                  status
                  TEXT, -- pending / issued / revoked / rejected
                  cert_path
                  TEXT,
                  cert_serial
                  TEXT,
                  created_at
                  TEXT,
                  approved_at
                  TEXT,
                  revoked_at
                  TEXT,
                  revoke_reason
                  TEXT
              )
              """)
    conn.commit()
    conn.close()


# initialize DB on import
init_db()


# ---------- CA basic ----------
def init_ca(common_name: str = "My Root CA") -> str:
    """初始化根 CA：生成私钥与自签名证书（如果已存在则不覆盖）"""
    if os.path.exists(CA_KEY_PATH) and os.path.exists(CA_CERT_PATH):
        logger.info("CA already exists.")
        return "CA already exists."

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ExampleOrg"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(minutes=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    with open(CA_KEY_PATH, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(CA_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    logger.info("Initialized CA: %s", common_name)
    return "CA created successfully."


def _load_ca(use_intermediate: bool = True) -> Tuple[Any, x509.Certificate]:
    """
    Load CA key & cert. By default prefer intermediate CA if available (for signing).
    Return (private_key, cert_obj). If intermediate missing, use root.
    """
    if use_intermediate and os.path.exists(INT_CA_KEY_PATH) and os.path.exists(INT_CA_CERT_PATH):
        with open(INT_CA_KEY_PATH, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(INT_CA_CERT_PATH, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        return ca_key, ca_cert

    if not os.path.exists(CA_KEY_PATH) or not os.path.exists(CA_CERT_PATH):
        raise FileNotFoundError("CA key/cert not found. Initialize CA first.")
    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert


def create_intermediate_ca(common_name: str = "Intermediate CA") -> str:
    """
    Create an intermediate CA signed by root CA and store in DATA_DIR.
    Idempotent: if intermediate exists, do nothing.
    """
    if os.path.exists(INT_CA_KEY_PATH) and os.path.exists(INT_CA_CERT_PATH):
        return "Intermediate CA already exists."

    root_key, root_cert = _load_ca(use_intermediate=False)
    int_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ExampleOrg-Intermediate"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(int_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(minutes=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    )
    int_cert = cert_builder.sign(private_key=root_key, algorithm=hashes.SHA256())

    with open(INT_CA_KEY_PATH, "wb") as f:
        f.write(int_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(INT_CA_CERT_PATH, "wb") as f:
        f.write(int_cert.public_bytes(serialization.Encoding.PEM))

    logger.info("Created intermediate CA.")
    return "Intermediate CA created."


# ---------- Issue from provided public key (or CSR) ----------
def issue_cert_from_public_key(public_key_pem: bytes, common_name: str, valid_days: int = 365,
                               signer: str = "intermediate") -> Dict[str, str]:
    """
    使用客户提交的公钥（PEM bytes 或 CSR）签发证书
    signer: 'intermediate' or 'root'
    返回 dict {'cert_path': abs_path, 'serial': str(serial)}
    """
    use_intermediate = (signer != "root")
    ca_key, ca_cert = _load_ca(use_intermediate=use_intermediate)

    # try public key first, then CSR
    pubkey = None
    try:
        pubkey = serialization.load_pem_public_key(public_key_pem)
    except Exception:
        try:
            csr = x509.load_pem_x509_csr(public_key_pem)
            pubkey = csr.public_key()
            # try extract common name if not provided
            try:
                if not common_name:
                    common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            except Exception:
                pass
        except Exception:
            raise ValueError("Provided data is neither a public key PEM nor a CSR.")

    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
    cert_builder = cert_builder.issuer_name(ca_cert.subject)
    cert_builder = cert_builder.public_key(pubkey)
    serial_num = x509.random_serial_number()
    cert_builder = cert_builder.serial_number(serial_num)
    cert_builder = cert_builder.not_valid_before(datetime.utcnow() - timedelta(minutes=1))
    cert_builder = cert_builder.not_valid_after(datetime.utcnow() + timedelta(days=valid_days))
    cert_builder = cert_builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

    # add CRL distribution point (if exists)
    try:
        if os.path.exists(CRL_PATH):
            dp = x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier("file://" + CRL_PATH)],
                relative_name=None, reasons=None, crl_issuer=None
            )
            cert_builder = cert_builder.add_extension(x509.CRLDistributionPoints([dp]), critical=False)
    except Exception:
        pass

    cert = cert_builder.sign(ca_key, hashes.SHA256())

    # create safe filename and save
    cert_filename = safe_basename(f"{common_name}_{serial_num}.pem")
    cert_path = os.path.abspath(os.path.join(ISSUED_DIR, cert_filename))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    logger.info("Issued certificate for %s (serial=%s) -> %s", common_name, serial_num, cert_path)
    return {"cert_path": cert_path, "serial": str(serial_num)}


# ---------- Application workflow ----------
def submit_application(name: str, email: str, pubkey_src_path: str, docs_src_paths: List[str]) -> int:
    """
    用户提交申请：
    - 在 DB 插入 pending 记录，返回申请 id
    - 将公钥和扫描件复制到 data/users/<id>/ 下，使用安全 basename
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    created_at = datetime.utcnow().isoformat()
    c.execute(
        "INSERT INTO applications (name, email, pubkey_path, docs_json, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (name, email, "", "[]", "pending", created_at))
    app_id = c.lastrowid
    conn.commit()
    conn.close()

    user_folder = os.path.join(USERS_DIR, f"{app_id}")
    os.makedirs(user_folder, exist_ok=True)

    pub_dest = ""
    if pubkey_src_path and os.path.exists(pubkey_src_path):
        dest_name = safe_basename(os.path.basename(pubkey_src_path))
        pub_dest = os.path.abspath(os.path.join(user_folder, dest_name))
        shutil.copy(pubkey_src_path, pub_dest)

    docs_saved = []
    for p in docs_src_paths or []:
        if os.path.exists(p):
            dest_name = safe_basename(os.path.basename(p))
            dest = os.path.abspath(os.path.join(user_folder, dest_name))
            shutil.copy(p, dest)
            docs_saved.append(dest)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE applications SET pubkey_path=?, docs_json=? WHERE id=?",
              (pub_dest, json.dumps(docs_saved), app_id))
    conn.commit()
    conn.close()

    logger.info("Submitted application %s by %s", app_id, name)
    return app_id


def list_applications(status: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if status:
        c.execute("SELECT * FROM applications WHERE status=? ORDER BY id", (status,))
    else:
        c.execute("SELECT * FROM applications ORDER BY id")
    rows = c.fetchall()
    cols = [d[0] for d in c.description]
    conn.close()
    result = []
    for r in rows:
        rec = dict(zip(cols, r))
        try:
            rec['docs'] = json.loads(rec.get('docs_json') or "[]")
        except Exception:
            rec['docs'] = []
        result.append(rec)
    return result


def approve_application(app_id: int, valid_days: int = 365, signer: str = "intermediate") -> Dict[str, str]:
    """
    审批通过：读取申请里的 pubkey_path，签发证书，更新 DB（status->issued）
    返回证书路径与 serial
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, pubkey_path FROM applications WHERE id=?", (app_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise FileNotFoundError("Application not found")
    _, name, pubkey_path = row
    if not pubkey_path or not os.path.exists(pubkey_path):
        conn.close()
        raise FileNotFoundError("Public key file not found for this application")

    pub_pem = open(pubkey_path, "rb").read()
    res = issue_cert_from_public_key(pub_pem, name, valid_days=valid_days, signer=signer)
    cert_path = os.path.abspath(res["cert_path"])
    serial = res["serial"]
    approved_at = datetime.utcnow().isoformat()
    c.execute("UPDATE applications SET status=?, cert_path=?, cert_serial=?, approved_at=? WHERE id=?",
              ("issued", cert_path, serial, approved_at, app_id))
    conn.commit()
    conn.close()
    logger.info("Application %s approved -> cert %s", app_id, cert_path)
    return {"cert_path": cert_path, "serial": serial}


def reject_application(app_id: int, reason: str = ""):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE applications SET status=?, revoke_reason=? WHERE id=?", ("rejected", reason, app_id))
    conn.commit()
    conn.close()
    logger.info("Application %s rejected: %s", app_id, reason)
    return "rejected"


# ---------- Revoke & CRL ----------
def revoke_application(app_id: int, reason: str = "key compromised") -> str:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, cert_path, cert_serial FROM applications WHERE id=?", (app_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return "Application not found or no certificate"
    app_id, name, cert_path, cert_serial = row
    if not cert_path or not os.path.exists(cert_path):
        conn.close()
        return "Certificate file not found or already revoked"

    basename = os.path.basename(cert_path)
    dest = os.path.join(REVOKED_DIR, basename.replace(".pem", "_revoked.pem"))
    os.replace(cert_path, dest)
    revoked_at = datetime.utcnow().isoformat()

    # 修改这里：不要将 cert_path 设置为 NULL，而是保留原值
    c.execute("UPDATE applications SET status=?, revoked_at=?, revoke_reason=? WHERE id=?",
              ("revoked", revoked_at, reason, app_id))
    conn.commit()
    conn.close()

    try:
        generate_crl()
    except Exception as e:
        logger.error("CRL generation failed: %s", e)

    logger.info("Revoked application %s (serial=%s) reason=%s", app_id, cert_serial, reason)
    return f"Revoked: {basename}"


def generate_crl() -> str:
    """
    生成标准 X.509 CRL（覆盖写入 CRL_PATH）。
    CRL 从 DB 中读取所有已标记 revoked 的证书，添加到 CRL。
    """
    ca_key, ca_cert = _load_ca()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT cert_serial, revoked_at FROM applications WHERE status='revoked' AND cert_serial IS NOT NULL")
    rows = c.fetchall()
    conn.close()

    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    now = datetime.utcnow()
    builder = builder.last_update(now)
    builder = builder.next_update(now + timedelta(days=7))

    for serial, revoked_at in rows:
        try:
            serial_int = int(serial)
        except Exception:
            continue
        if revoked_at:
            revoked_dt = datetime.fromisoformat(revoked_at)
        else:
            revoked_dt = now
        revoked_cert_b = x509.RevokedCertificateBuilder().serial_number(serial_int).revocation_date(revoked_dt)
        revoked_cert = revoked_cert_b.build()
        builder = builder.add_revoked_certificate(revoked_cert)

    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    with open(CRL_PATH, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))

    logger.info("CRL generated at %s", CRL_PATH)
    return CRL_PATH


# ---------- Helper: list issued certs and get details ----------
def list_issued_certs() -> List[Dict[str, str]]:
    items = []
    for fn in os.listdir(ISSUED_DIR):
        if not fn.endswith(".pem") or fn.endswith("_key.pem"):
            continue
        path = os.path.abspath(os.path.join(ISSUED_DIR, fn))
        try:
            cert = x509.load_pem_x509_certificate(open(path, "rb").read())
            cn = ""
            try:
                cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            except Exception:
                pass
            items.append({
                "path": path,
                "filename": fn,
                "common_name": cn,
                "serial": str(cert.serial_number),
                "not_before": cert.not_valid_before.isoformat(),
                "not_after": cert.not_valid_after.isoformat(),
            })
        except Exception as e:
            logger.error("Failed to parse cert %s: %s", fn, e)
            items.append({"path": path, "filename": fn})
    items.sort(key=lambda x: x["filename"])
    return items


def get_cert_details(cert_path: str) -> Dict[str, Optional[str]]:
    """
    解析证书并从DB查找对应的申请ID（若存在），返回详细信息字典（包含 application_id）
    cert_path 应当为绝对路径（approve_application 存储时已使用绝对路径）
    """
    if not os.path.exists(cert_path):
        raise FileNotFoundError("cert not found")

    pem = open(cert_path, "rb").read()
    cert = x509.load_pem_x509_certificate(pem)

    details = {
        "filename": os.path.basename(cert_path),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": str(cert.serial_number),
        "not_valid_before": cert.not_valid_before.isoformat(),
        "not_valid_after": cert.not_valid_after.isoformat(),
        "extensions": [],
        "application_id": None,
    }

    # 从数据库获取申请ID（以绝对路径匹配）
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    abs_path = os.path.abspath(cert_path)
    c.execute("SELECT id FROM applications WHERE cert_path=?", (abs_path,))
    row = c.fetchone()
    if not row:
        # fallback: try matching by filename suffix
        fname = os.path.basename(cert_path)
        c.execute("SELECT id, cert_path FROM applications WHERE cert_path LIKE ? LIMIT 1", (f"%{fname}",))
        row = c.fetchone()
    if row:
        details["application_id"] = str(row[0])
    conn.close()

    for ext in cert.extensions:
        try:
            name = getattr(ext.oid, "_name", str(ext.oid))
            details["extensions"].append(f"{name}: critical={ext.critical}")
        except Exception:
            details["extensions"].append(str(ext.oid))

    return details


# ---------- Revoked certificates management ----------
def list_revoked_certs() -> List[Dict[str, Any]]:
    """
    获取所有已撤销证书的详细信息
    返回包含申请信息和撤销信息的列表
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
              SELECT id, name, email, cert_path, cert_serial, revoked_at, revoke_reason
              FROM applications
              WHERE status = 'revoked'
              ORDER BY revoked_at DESC
              """)
    rows = c.fetchall()
    cols = [d[0] for d in c.description]
    conn.close()

    result = []
    for r in rows:
        rec = dict(zip(cols, r))
        # 获取文件名 - 现在 cert_path 不为 NULL
        if rec.get('cert_path'):
            rec['filename'] = os.path.basename(rec['cert_path'])
        else:
            rec['filename'] = "未知文件"
        # 确保 application_id 字段存在
        rec['application_id'] = rec.get('id', '未知')
        result.append(rec)

    return result


def get_revoked_cert_details(app_id: int) -> Optional[Dict[str, Any]]:
    """
    获取特定撤销证书的详细信息，包括原始证书信息
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
              SELECT id, name, cert_path, cert_serial, revoked_at, revoke_reason
              FROM applications
              WHERE id = ?
                AND status = 'revoked'
              """, (app_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        return None

    app_id, name, cert_path, cert_serial, revoked_at, revoke_reason = row

    details = {
        'application_id': app_id,
        'name': name,
        'revoked_at': revoked_at,
        'revoke_reason': revoke_reason,
        'serial_number': cert_serial,
        'filename': os.path.basename(cert_path) if cert_path else "未知文件",
    }

    # 尝试从撤销目录中查找证书文件
    revoked_cert_path = None
    if cert_path:
        # 原路径可能已不存在，在撤销目录中查找
        basename = os.path.basename(cert_path)
        revoked_cert_path = os.path.join(REVOKED_DIR, basename.replace(".pem", "_revoked.pem"))
        if not os.path.exists(revoked_cert_path):
            # 尝试查找续签撤销的证书
            revoked_cert_path = os.path.join(REVOKED_DIR, basename.replace(".pem", "_renewed.pem"))

    # 如果找到证书文件，解析证书信息
    if revoked_cert_path and os.path.exists(revoked_cert_path):
        try:
            with open(revoked_cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())

            details.update({
                'subject': cert.subject.rfc4514_string(),
                'issuer': cert.issuer.rfc4514_string(),
                'not_valid_before': cert.not_valid_before.isoformat(),
                'not_valid_after': cert.not_valid_after.isoformat(),
                'cert_path': revoked_cert_path,
            })

            # 尝试获取 Common Name
            try:
                cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                details['common_name'] = cn
            except Exception:
                details['common_name'] = "未知"

        except Exception as e:
            logger.error(f"解析撤销证书失败: {e}")
            details['parse_error'] = str(e)

    return details


# ---------- Renewal / Expiry Checking  ----------

def renew_certificate(app_id: int, valid_days: int = 365, signer: str = "intermediate") -> Dict[str, str]:
    """
    为已存在申请续签一个新的证书（使用相同的公钥与 subject），更新该应用记录的 cert_path/cert_serial/approved_at。
    在颁发新证书后自动撤销旧证书。
    返回新的 cert_path & serial。
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, pubkey_path, cert_path, cert_serial FROM applications WHERE id=?", (app_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise FileNotFoundError("Application not found for renewal")
    _, name, pubkey_path, old_cert_path, old_serial = row

    if not pubkey_path or not os.path.exists(pubkey_path):
        conn.close()
        raise FileNotFoundError("Public key not found for renewal")

    # 安全路径校验
    abs_pubkey_path = os.path.realpath(pubkey_path)
    if not abs_pubkey_path.startswith(os.path.realpath(BASE_DIR)):
        raise PermissionError("Unsafe pubkey path detected!")

    # 颁发新证书
    with open(abs_pubkey_path, "rb") as f:
        pub_pem = f.read()

    res = issue_cert_from_public_key(pub_pem, name, valid_days=valid_days, signer=signer)
    cert_path = os.path.abspath(res["cert_path"])
    serial = res["serial"]
    approved_at = datetime.utcnow().isoformat()

    # 更新数据库记录
    c.execute("UPDATE applications SET cert_path=?, cert_serial=?, approved_at=?, status=? WHERE id=?",
              (cert_path, serial, approved_at, "issued", app_id))
    conn.commit()

    # 吊销旧证书
    if old_cert_path and os.path.exists(old_cert_path):
        logger.info(f"自动撤销旧证书: {old_cert_path} (serial={old_serial})")

        basename = os.path.basename(old_cert_path)
        revoked_target = os.path.join(REVOKED_DIR, basename.replace(".pem", "_renewed.pem"))
        os.replace(old_cert_path, revoked_target)

        revoked_at = datetime.utcnow().isoformat()
        c.execute("UPDATE applications SET revoked_at=?, revoke_reason=? WHERE id=?",
                  (revoked_at, "renewed", app_id))
        conn.commit()

        try:
            generate_crl()
        except Exception as e:
            logger.warning("CRL generation failed during renewal: %s", e)

    conn.close()
    logger.info(f"[Renew] app {app_id} -> new serial={serial}")
    return {"cert_path": cert_path, "serial": serial}


def auto_renew_all(days_before_expire: int = 30) -> str:
    """
    自动扫描并续签即将到期的证书。
    若证书将在 days_before_expire 天内到期，则自动续签。
    """
    cert_dir = os.path.join(BASE_DIR, "data", "certs")
    if not os.path.exists(cert_dir):
        return "未发现证书目录，无需续签。"

    renewed = []
    now = datetime.utcnow()

    for fname in os.listdir(cert_dir):
        if not fname.endswith(".pem"):
            continue
        fpath = os.path.join(cert_dir, fname)
        try:
            with open(fpath, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            expire_time = cert.not_valid_after
            if expire_time - now >= timedelta(days=days_before_expire):
                continue

            serial = cert.serial_number
            with sqlite3.connect(DB_PATH) as conn:
                cur = conn.cursor()
                cur.execute("SELECT id, name, email, pubkey_path FROM applications WHERE cert_serial=?", (serial,))
                row = cur.fetchone()
                if not row:
                    continue
                app_id, name, email, pubkey_path = row

            renew_certificate(app_id)
            renewed.append(fname)
            logger.info(f"[AUTO-RENEW] {fname} renewed for app {app_id}")

        except Exception as e:
            logger.warning(f"[AUTO-RENEW] 无法处理 {fname}: {e}")

    return f"已自动续签 {len(renewed)} 个证书。" if renewed else "没有证书需要续签。"


def check_expiry_and_warn(days_before: int = 30) -> List[Dict[str, str]]:
    """
    扫描已颁发证书，找出将在 days_before 天内到期的证书。
    返回列表，每项包含 application_id, filename, common_name, not_after。
    """
    warn_list = []
    certs = list_issued_certs()
    now = datetime.utcnow()
    threshold = now + timedelta(days=days_before)

    for cinfo in certs:
        try:
            expire_date = datetime.fromisoformat(cinfo["not_after"])
        except Exception:
            try:
                expire_date = datetime.strptime(cinfo["not_after"], "%Y-%m-%dT%H:%M:%S")
            except Exception:
                continue
        if expire_date > threshold:
            continue

        try:
            details = get_cert_details(cinfo["path"])
            app_id = details.get("application_id", None)
        except Exception:
            app_id = None

        warn_list.append({
            "application_id": app_id,
            "filename": cinfo["filename"],
            "common_name": cinfo.get("common_name"),
            "not_after": cinfo.get("not_after"),
            "path": cinfo.get("path"),
        })

    return warn_list
