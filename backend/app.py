from flask import Flask, render_template, request, redirect, url_for, session, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
import pytesseract
from PIL import Image
import pdfplumber

# ================= APP CONFIG =================
app = Flask(__name__)
app.secret_key = "lendnova8_secure_key"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_ROOT = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_ROOT, exist_ok=True)

pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# ================= DATABASE =================
DB_NAME = os.path.join(BASE_DIR, "lendnova8.db")

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            doc_type TEXT,
            file_path TEXT,
            is_valid INTEGER,
            ocr_text TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            fraud_score INTEGER,
            credit_score INTEGER,
            risk_level TEXT,
            eligible_amount INTEGER,
            insights TEXT
        )
    """)

    conn.commit()
    conn.close()

init_db()

# ================= CONFIG =================

ALLOWED_DOCS = {
    "rent_receipt","electricity_bill","water_bill","gas_bill",
    "mobile_bill","bank_statement","income_proof",
    "upi_transactions","mobile_recharge","internet_bill"
}

ALLOWED_EXTENSIONS = {"pdf","jpg","jpeg","png"}

DOC_KEYWORDS = {

    "rent_receipt": [
        "rent","tenant","landlord","lease",
        "rent paid","agreement","property address"
    ],

    "electricity_bill": [
        "electricity","kwh","power","consumer","total Due",
        "billing period","units consumed","meter reading"
    ],

    "water_bill": [
        "water supply","meter","municipal",
        "usage","billing cycle","consumer id","TOTAL DEMAND","TOT.REBATE"
    ],

    "gas_bill": [
        "gas bill","lpg","png","gas connection",
        "consumer number","invoice number","bill number",
        "billing period","due date","amount payable",
        "gst","delivery date","refill","cylinder",
        "indane","bharat gas","hp gas","bpcl","ioc"
    ],

    "mobile_bill": [
        "mobile services","telecom","postpaid",
        "bill number","plan","Total Amount"
    ],

    "bank_statement": [
        "account statement","bank","account number",
        "debit","credit","balance",
        "closing balance","ifsc"
    ],

    "income_proof": [
        "salary","income","ctc",
        "gross pay","net pay","payslip"
    ],

    "upi_transactions": [
        "upi","transaction id","txn id",
        "reference number","payment"
    ],

    "mobile_recharge": [
        "recharge","validity",
        "plan","top up"
    ],

    "internet_bill": [
        "internet","broadband","wifi",
        "invoice","service provider"
    ]
}

MIN_REQUIRED_DOCS = 5

# ================= HELPERS =================

def allowed_file(filename):
    return "." in filename and filename.rsplit(".",1)[1].lower() in ALLOWED_EXTENSIONS

def perform_ocr(path):
    text = ""
    try:
        if path.endswith(".pdf"):
            with pdfplumber.open(path) as pdf:
                for page in pdf.pages:
                    t = page.extract_text()
                    if t:
                        text += t + " "
        else:
            text = pytesseract.image_to_string(Image.open(path))
    except:
        pass
    return text.lower()

def detect_fraud(documents):
    fraud_score = 0
    flags = []

    for doc in documents:
        text = doc["ocr_text"]

        if len(text) < 200:
            fraud_score += 20
            flags.append(f"{doc['doc_type']} has insufficient data")

        if text.count("sample") > 2 or text.count("xxxx") > 3:
            fraud_score += 25
            flags.append(f"{doc['doc_type']} appears templated")

    return min(fraud_score,100), flags

def generate_credit_score(valid_count, fraud_score):
    score = 300 + (valid_count * 90)
    score -= int(fraud_score * 1.5)
    score = max(300, min(score, 900))

    if score >= 750:
        risk = "LOW"
    elif score >= 600:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    return score, risk

def calculate_loan(score):
    if score >= 750:
        return 500000
    elif score >= 650:
        return 250000
    elif score >= 550:
        return 100000
    else:
        return 0

# ================= ROUTES =================

@app.route("/")
def index():
    return render_template("index.html")

# -------- REGISTER --------
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO users (name,email,password) VALUES (?,?,?)",
                (
                    request.form["name"],
                    request.form["email"],
                    generate_password_hash(request.form["password"])
                )
            )
            conn.commit()
            conn.close()
            return redirect(url_for("login"))
        except:
            return "Email already registered"
    return render_template("register.html")

# -------- LOGIN --------
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE email=?",
            (request.form["email"],)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], request.form["password"]):
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["consent_given"] = False
            return redirect(url_for("consent"))

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")

# -------- CONSENT --------
@app.route("/consent", methods=["GET","POST"])
def consent():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        session["consent_given"] = True
        return redirect(url_for("dashboard"))

    return render_template("consent.html")

# -------- LOGOUT --------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# -------- DASHBOARD --------
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not session.get("consent_given"):
        return redirect(url_for("consent"))

    conn = get_db()

    valid_docs = conn.execute(
        "SELECT COUNT(*) as c FROM documents WHERE user_id=? AND is_valid=1",
        (session["user_id"],)
    ).fetchone()["c"]

    invalid_docs = conn.execute(
        "SELECT COUNT(*) as c FROM documents WHERE user_id=? AND is_valid=0",
        (session["user_id"],)
    ).fetchone()["c"]

    assessment = conn.execute("""
        SELECT fraud_score,credit_score,risk_level,eligible_amount,insights
        FROM assessments
        WHERE user_id=?
        ORDER BY id DESC LIMIT 1
    """,(session["user_id"],)).fetchone()

    conn.close()

    return render_template(
        "borrower-dashboard.html",
        valid_docs=valid_docs,
        invalid_docs=invalid_docs,
        assessment=assessment
    )

# -------- UPLOAD DOCUMENTS --------
@app.route("/upload-documents", methods=["POST"])
def upload_documents():
    if "user_id" not in session:
        abort(403)

    user_id = session["user_id"]
    user_folder = os.path.join(UPLOAD_ROOT, str(user_id))
    os.makedirs(user_folder, exist_ok=True)

    conn = get_db()
    valid_count = 0
    invalid_found = False

    for doc_type in ALLOWED_DOCS:
        if doc_type in request.files:
            file = request.files[doc_type]

            if file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                path = os.path.join(user_folder, filename)
                file.save(path)

                text = perform_ocr(path)

                # VALIDATION
                if any(k in text for k in DOC_KEYWORDS[doc_type]):
                    conn.execute(
                        "INSERT INTO documents (user_id,doc_type,file_path,is_valid,ocr_text) VALUES (?,?,?,?,?)",
                        (user_id,doc_type,path,1,text)
                    )
                    valid_count += 1
                else:
                    if os.path.exists(path):
                        os.remove(path)
                    conn.execute(
                        "INSERT INTO documents (user_id,doc_type,file_path,is_valid,ocr_text) VALUES (?,?,?,?,?)",
                        (user_id,doc_type,"",0,"")
                    )
                    invalid_found = True

    conn.commit()
    conn.close()

    if invalid_found:
        return redirect(url_for("dashboard"))

    return redirect(url_for("dashboard"))

# -------- RUN ASSESSMENT --------
@app.route("/run-assessment")
def run_assessment():
    if "user_id" not in session:
        abort(403)

    conn = get_db()

    documents = conn.execute(
        "SELECT doc_type,ocr_text FROM documents WHERE user_id=? AND is_valid=1",
        (session["user_id"],)
    ).fetchall()

    if len(documents) < MIN_REQUIRED_DOCS:
        conn.close()
        return redirect(url_for("dashboard"))

    fraud_score, flags = detect_fraud(documents)
    credit_score, risk = generate_credit_score(len(documents), fraud_score)
    eligible = calculate_loan(credit_score)

    insights = "; ".join(flags) if flags else "Healthy financial behaviour detected"

    conn.execute("""
        INSERT INTO assessments
        (user_id,fraud_score,credit_score,risk_level,eligible_amount,insights)
        VALUES (?,?,?,?,?,?)
    """,(session["user_id"],fraud_score,credit_score,risk,eligible,insights))

    conn.commit()
    conn.close()

    return redirect(url_for("dashboard"))

# ================= RUN =================
if __name__ == "__main__":
    app.run(debug=True)