from flask import Flask, redirect, url_for, render_template, request, session, flash
from datetime import timedelta
import sqlite3, hashlib, secrets, datetime, os
from functools import wraps
from dotenv import load_dotenv

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

load_dotenv()  # loads variables from a local .env file, if present (no effect on Render)

GMAIL_SENDER = os.environ.get("GMAIL_SENDER", "")
GMAIL_PASSWORD = os.environ.get("GMAIL_PASSWORD", "")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(16))
app.permanent_session_lifetime = timedelta(minutes=30)

DB = "users.db"

# ── DATABASE ──────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn
def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT    NOT NULL UNIQUE,
            email      TEXT    NOT NULL UNIQUE,
            password   TEXT    NOT NULL,
            created_at TEXT    DEFAULT (datetime('now'))
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            token      TEXT    NOT NULL UNIQUE,
            expires_at TEXT    NOT NULL,
            used       INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS expenses (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            description TEXT    NOT NULL,
            category    TEXT    DEFAULT 'others',
            amount      REAL    NOT NULL,
            date        TEXT    DEFAULT (date('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS budget (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            month       TEXT    NOT NULL,
            budget      REAL    NOT NULL,
            alert_pct   INTEGER DEFAULT 70,
            UNIQUE(user_id, month),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS savings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            goal_name   TEXT    NOT NULL,
            target      REAL    NOT NULL,
            saved       REAL    DEFAULT 0,
            target_date TEXT,
            created_at  TEXT    DEFAULT (date('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS income (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            description TEXT    NOT NULL,
            amount      REAL    NOT NULL,
            type        TEXT    DEFAULT 'salary',
            date        TEXT    DEFAULT (date('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    db.commit()
    db.close()

def hash_pw(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access that page.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def sv():
    return {"username": session.get("username",""), "email": session.get("email","")}

# ── ROUTES ────────────────────────────────────────────────────────────────

import requests

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")

def send_reset_email(to_email, reset_url):
    """Send password reset email via Resend API."""
    try:
        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:32px;background:#FEFAF2;border-radius:16px;">
          <h2 style="color:#C47B0E;">🐝 Budget Bee</h2>
          <p style="color:#1C1410;">You requested a password reset. Click the button below:</p>
          <a href="{reset_url}"
             style="display:inline-block;padding:12px 24px;background:#C47B0E;color:#fff;border-radius:10px;text-decoration:none;font-weight:bold;margin:16px 0;">
             Reset My Password
          </a>
          <p style="color:#9A8878;font-size:12px;">
            This link expires in 1 hour.<br>
            If you didn't request this, ignore this email.
          </p>
        </div>"""

        response = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
            json={
                "from": "Budget Bee <onboarding@resend.dev>",
                "to": [to_email],
                "subject": "Budget Bee — Reset Your Password",
                "html": html
            },
            timeout=10
        )
        if response.status_code == 200:
            return True
        else:
            print(f"[Email Error] Resend API returned {response.status_code}: {response.text}")
            return False
    except Exception as e:
        print(f"[Email Error] {e}")
        return False

@app.route("/")
def home():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))


# ── AUTH ──────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        if not email or not password:
            flash("Please fill in all fields.", "error")
        else:
            db   = get_db()
            user = db.execute(
                "SELECT * FROM users WHERE email=? AND password=?",
                (email, hash_pw(password))
            ).fetchone()
            db.close()
            if user:
                session.permanent   = True
                session["user_id"]  = user["id"]
                session["username"] = user["username"]
                session["email"]    = user["email"]
                flash(f"Welcome back, {user['username']}! 👋", "success")
                return redirect(url_for("dashboard"))
            flash("Invalid email or password.", "error")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")
        if not all([username, email, password, confirm]):
            flash("Please fill in all fields.", "error")
        elif len(username) < 3:
            flash("Username must be at least 3 characters.", "error")
        elif "@" not in email:
            flash("Please enter a valid email.", "error")
        elif len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        else:
            db = get_db()
            try:
                cur = db.execute(
                    "INSERT INTO users (username, email, password) VALUES (?,?,?)",
                    (username, email, hash_pw(password))
                )
                db.commit()
                new_id = cur.lastrowid
                db.close()
                session.permanent   = True
                session["user_id"]  = new_id
                session["username"] = username
                session["email"]    = email
                flash(f"Account created! Welcome, {username}! 🎉", "success")
                return redirect(url_for("dashboard"))
            except sqlite3.IntegrityError:
                db.close()
                flash("Username or email already registered.", "error")
    return render_template("register.html")


@app.route("/logout")
def logout():
    name = session.get("username", "")
    session.clear()
    flash(f"You've been signed out. See you soon, {name}!", "success")
    return redirect(url_for("login"))


# ── MAIN PAGES ────────────────────────────────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    uid   = session["user_id"]
    db    = get_db()
    month = datetime.date.today().strftime("%Y-%m")

    total = db.execute(
        "SELECT COALESCE(SUM(amount),0) AS t FROM expenses WHERE user_id=? AND date LIKE ?",
        (uid, f"{month}%")
    ).fetchone()["t"]

    income_total = db.execute(
        "SELECT COALESCE(SUM(amount),0) AS t FROM income WHERE user_id=? AND date LIKE ?",
        (uid, f"{month}%")
    ).fetchone()["t"]

    bud = db.execute(
        "SELECT budget FROM budget WHERE user_id=? AND month=?", (uid, month)
    ).fetchone()

    recent  = db.execute(
        "SELECT * FROM expenses WHERE user_id=? ORDER BY date DESC LIMIT 5", (uid,)
    ).fetchall()

    savings = db.execute(
        "SELECT * FROM savings WHERE user_id=?", (uid,)
    ).fetchall()

    db.close()
    return render_template("dashboard.html", **sv(),
                           total_spent=total,
                           income_total=income_total,
                           budget=bud["budget"] if bud else None,
                           recent=recent,
                           savings=savings)


@app.route("/expenses", methods=["GET", "POST"])
@login_required
def expenses():
    uid = session["user_id"]
    db  = get_db()

    if request.method == "POST":
        desc     = request.form.get("description", "").strip()
        category = request.form.get("category", "others")
        amount   = request.form.get("amount", "")
        date     = request.form.get("date", datetime.date.today().isoformat())
        if not desc or not amount:
            flash("Description and amount are required.", "error")
        else:
            db.execute(
                "INSERT INTO expenses (user_id,description,category,amount,date) VALUES (?,?,?,?,?)",
                (uid, desc, category, float(amount), date)
            )
            db.commit()
            flash(f"Expense '{desc}' added successfully! 💸", "success")

    month = request.args.get("month", datetime.date.today().strftime("%Y-%m"))
    rows  = db.execute(
        "SELECT * FROM expenses WHERE user_id=? AND date LIKE ? ORDER BY date DESC",
        (uid, f"{month}%")
    ).fetchall()
    total = sum(r["amount"] for r in rows)
    db.close()

    return render_template("expenses.html", **sv(),
                           expenses=rows, total=total, month=month)


@app.route("/budget", methods=["GET", "POST"])
@login_required
def budget():
    uid = session["user_id"]
    db  = get_db()

    if request.method == "POST":
        amount    = request.form.get("budget", "")
        month     = request.form.get("month", "")
        alert_pct = request.form.get("alert_pct", 70)
        if not amount or not month:
            flash("Budget amount and month are required.", "error")
        else:
            db.execute(
                """INSERT INTO budget (user_id,month,budget,alert_pct) VALUES (?,?,?,?)
                   ON CONFLICT(user_id,month) DO UPDATE SET
                   budget=excluded.budget, alert_pct=excluded.alert_pct""",
                (uid, month, float(amount), int(alert_pct))
            )
            db.commit()
            flash(f"Budget of RM {float(amount):.2f} set for {month}! 🎯", "success")

    budgets  = db.execute(
        "SELECT * FROM budget WHERE user_id=? ORDER BY month DESC", (uid,)
    ).fetchall()
    spending = db.execute(
        "SELECT strftime('%Y-%m',date) AS month, SUM(amount) AS total FROM expenses WHERE user_id=? GROUP BY month",
        (uid,)
    ).fetchall()
    spending_map = {r["month"]: r["total"] for r in spending}
    db.close()

    return render_template("budget.html", **sv(),
                           budgets=budgets, spending=spending_map,
                           current_month=datetime.date.today().strftime("%Y-%m"))


@app.route("/savings", methods=["GET", "POST"])
@login_required
def savings():
    uid = session["user_id"]
    db  = get_db()

    if request.method == "POST":
        goal_name   = request.form.get("goal_name", "").strip()
        target      = request.form.get("target", "")
        target_date = request.form.get("target_date") or None
        if not goal_name or not target:
            flash("Goal name and target amount are required.", "error")
        else:
            db.execute(
                "INSERT INTO savings (user_id,goal_name,target,target_date) VALUES (?,?,?,?)",
                (uid, goal_name, float(target), target_date)
            )
            db.commit()
            flash(f"Savings goal '{goal_name}' created! 🐷", "success")

    goals = db.execute(
        "SELECT * FROM savings WHERE user_id=? ORDER BY created_at DESC", (uid,)
    ).fetchall()
    db.close()

    return render_template("savings.html", **sv(), goals=goals)


# ── PROFILE ───────────────────────────────────────────────────────────────

@app.route("/profile")
@login_required
def profile():
    uid = session["user_id"]
    db  = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    db.close()
    return render_template("profile.html", **sv(), user=user)


@app.route("/profile/update", methods=["POST"])
@login_required
def profile_update():
    uid      = session["user_id"]
    username = request.form.get("username", "").strip()
    email    = request.form.get("email", "").strip()

    if not username or not email:
        flash("Username and email cannot be empty.", "error")
        return redirect(url_for("profile"))
    if len(username) < 3:
        flash("Username must be at least 3 characters.", "error")
        return redirect(url_for("profile"))
    if "@" not in email:
        flash("Please enter a valid email.", "error")
        return redirect(url_for("profile"))

    db = get_db()
    try:
        db.execute(
            "UPDATE users SET username=?, email=? WHERE id=?",
            (username, email, uid)
        )
        db.commit()
        # Update session so nav shows the new name immediately
        session["username"] = username
        session["email"]    = email
        flash("Profile updated successfully! ✅", "success")
    except sqlite3.IntegrityError:
        flash("That username or email is already taken.", "error")
    finally:
        db.close()

    return redirect(url_for("profile"))


@app.route("/profile/password", methods=["POST"])
@login_required
def profile_password():
    uid              = session["user_id"]
    current_password = request.form.get("current_password", "")
    new_password     = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

    if user["password"] != hash_pw(current_password):
        db.close()
        flash("Current password is incorrect.", "error")
        return redirect(url_for("profile"))
    if len(new_password) < 6:
        db.close()
        flash("New password must be at least 6 characters.", "error")
        return redirect(url_for("profile"))
    if new_password != confirm_password:
        db.close()
        flash("New passwords do not match.", "error")
        return redirect(url_for("profile"))

    db.execute("UPDATE users SET password=? WHERE id=?", (hash_pw(new_password), uid))
    db.commit()
    db.close()
    flash("Password changed successfully! 🔒", "success")
    return redirect(url_for("profile"))


@app.route("/profile/delete", methods=["POST"])
@login_required
def profile_delete():
    uid = session["user_id"]
    db  = get_db()
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    db.commit()
    db.close()
    session.clear()
    flash("Your account has been permanently deleted.", "success")
    return redirect(url_for("login"))


# ── PASSWORD RESET ────────────────────────────────────────────────────────

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        if not email or "@" not in email:
            flash("Please enter a valid email address.", "error")
        else:
            db   = get_db()
            user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if user:
                token   = secrets.token_urlsafe(32)
                expires = (datetime.datetime.now() + datetime.timedelta(hours=1)).isoformat()
                db.execute(
                    "INSERT INTO password_resets (user_id,token,expires_at) VALUES (?,?,?)",
                    (user["id"], token, expires)
                )
                db.commit()
                reset_url = url_for("reset_password", token=token, _external=True)
                db.close()

                if send_reset_email(user["email"], reset_url):
                    return render_template("forgot_password.html", sent=reset_url)
                else:
                    flash("Unable to send email.", "error")
                    return render_template("forgot_password.html", sent=reset_url)
            db.close()
            # Don't reveal if email exists — always show success
            return render_template("forgot_password.html", sent="not_found")
    return render_template("forgot_password.html", sent=None)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    db    = get_db()
    reset = db.execute(
        "SELECT * FROM password_resets WHERE token=? AND used=0", (token,)
    ).fetchone()
    invalid = not reset or datetime.datetime.fromisoformat(reset["expires_at"]) < datetime.datetime.now()

    if not invalid and request.method == "POST":
        pw = request.form.get("password", "")
        cf = request.form.get("confirm", "")
        if len(pw) < 6:
            flash("Password must be at least 6 characters.", "error")
        elif pw != cf:
            flash("Passwords do not match.", "error")
        else:
            db.execute("UPDATE users SET password=? WHERE id=?", (hash_pw(pw), reset["user_id"]))
            db.execute("UPDATE password_resets SET used=1 WHERE token=?", (token,))
            db.commit()
            db.close()
            flash("Password reset successful! You can now sign in. ✅", "success")
            return redirect(url_for("login"))

    db.close()
    return render_template("reset_password.html", invalid=invalid, token=token)


# ── STATIC PAGES ──────────────────────────────────────────────────────────

@app.route("/terms")
def terms():
    return render_template("terms.html")

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route("/income", methods=["GET", "POST"])
@login_required
def income():
    uid = session["user_id"]
    db  = get_db()

    if request.method == "POST":
        desc        = request.form.get("description", "").strip()
        amount      = request.form.get("amount", "")
        income_type = request.form.get("type", "salary")
        date        = request.form.get("date", datetime.date.today().isoformat())
        if not desc or not amount:
            flash("Description and amount are required.", "error")
        else:
            db.execute(
                "INSERT INTO income (user_id,description,amount,type,date) VALUES (?,?,?,?,?)",
                (uid, desc, float(amount), income_type, date)
            )
            db.commit()
            flash(f"Income '{desc}' added successfully! 💰", "success")

    month = request.args.get("month", datetime.date.today().strftime("%Y-%m"))
    rows  = db.execute(
        "SELECT * FROM income WHERE user_id=? AND date LIKE ? ORDER BY date DESC",
        (uid, f"{month}%")
    ).fetchall()
    total = sum(r["amount"] for r in rows)
    db.close()

    return render_template("income.html", **sv(),
                           income_list=rows, total=total, month=month)



# ══════════════════════════════════════════════════════════════════════════
# API ROUTES — called by fetch() in templates
# ══════════════════════════════════════════════════════════════════════════

# ── EXPENSES API ─────────────────────────────────────────────────────────

@app.route("/api/expenses")
@login_required
def api_expenses_get():
    uid      = session["user_id"]
    all_time = request.args.get("all", "false").lower() == "true"
    db       = get_db()
    if all_time:
        rows = db.execute(
            "SELECT * FROM expenses WHERE user_id=? ORDER BY date DESC",
            (uid,)
        ).fetchall()
    else:
        month = request.args.get("month", datetime.date.today().strftime("%m")).zfill(2)
        year  = request.args.get("year",  datetime.date.today().strftime("%Y"))
        rows  = db.execute(
            """SELECT * FROM expenses
               WHERE user_id=?
                 AND strftime('%m',date)=?
                 AND strftime('%Y',date)=?
               ORDER BY date DESC""",
            (uid, month, year)
        ).fetchall()
    total = sum(r["amount"] for r in rows)
    db.close()
    return {"expenses": [dict(r) for r in rows], "total": round(total, 2)}


@app.route("/api/expenses/add", methods=["POST"])
@login_required
def api_expenses_add():
    uid  = session["user_id"]
    data = request.get_json()
    desc     = data.get("description", "").strip()
    amount   = data.get("amount", 0)
    category = data.get("category", "Other")
    date     = data.get("date", datetime.date.today().isoformat())
    if not desc or not amount:
        return {"error": "Description and amount are required"}, 400
    db  = get_db()
    cur = db.execute(
        "INSERT INTO expenses (user_id,description,category,amount,date) VALUES (?,?,?,?,?)",
        (uid, desc, category, float(amount), date)
    )
    db.commit()
    new_id = cur.lastrowid
    db.close()
    return {"id": new_id, "description": desc, "category": category,
            "amount": float(amount), "date": date}, 201


@app.route("/api/expenses/delete/<int:eid>", methods=["DELETE"])
@login_required
def api_expenses_delete(eid):
    uid = session["user_id"]
    db  = get_db()
    db.execute("DELETE FROM expenses WHERE id=? AND user_id=?", (eid, uid))
    db.commit()
    db.close()
    return {"deleted": eid}


@app.route("/api/expenses/edit/<int:eid>", methods=["PUT"])
@login_required
def api_expenses_edit(eid):
    uid  = session["user_id"]
    data = request.get_json()
    desc     = data.get("description", "").strip()
    amount   = data.get("amount", 0)
    category = data.get("category", "Other")
    date     = data.get("date", datetime.date.today().isoformat())
    if not desc or not amount:
        return {"error": "Description and amount are required"}, 400
    db = get_db()
    db.execute(
        "UPDATE expenses SET description=?, amount=?, category=?, date=? WHERE id=? AND user_id=?",
        (desc, float(amount), category, date, eid, uid)
    )
    db.commit()
    db.close()
    return {"id": eid, "description": desc, "amount": float(amount),
            "category": category, "date": date}


# ── INCOME API ────────────────────────────────────────────────────────────

@app.route("/api/income")
@login_required
def api_income_get():
    uid      = session["user_id"]
    all_time = request.args.get("all", "false").lower() == "true"
    db       = get_db()
    if all_time:
        rows = db.execute(
            "SELECT * FROM income WHERE user_id=? ORDER BY date DESC",
            (uid,)
        ).fetchall()
    else:
        month = request.args.get("month", datetime.date.today().strftime("%m")).zfill(2)
        year  = request.args.get("year",  datetime.date.today().strftime("%Y"))
        rows  = db.execute(
            """SELECT * FROM income
               WHERE user_id=?
                 AND strftime('%m',date)=?
                 AND strftime('%Y',date)=?
               ORDER BY date DESC""",
            (uid, month, year)
        ).fetchall()
    total = sum(r["amount"] for r in rows)
    db.close()
    return {"income": [dict(r) for r in rows], "total": round(total, 2)}


@app.route("/api/income/add", methods=["POST"])
@login_required
def api_income_add():
    uid  = session["user_id"]
    data = request.get_json()
    desc        = data.get("description", "").strip()
    amount      = data.get("amount", 0)
    income_type = data.get("income_type", "Salary")
    date        = data.get("date", datetime.date.today().isoformat())
    if not desc or not amount:
        return {"error": "Description and amount are required"}, 400
    db  = get_db()
    cur = db.execute(
        "INSERT INTO income (user_id,description,amount,type,date) VALUES (?,?,?,?,?)",
        (uid, desc, float(amount), income_type, date)
    )
    db.commit()
    new_id = cur.lastrowid
    db.close()
    return {"id": new_id, "description": desc, "amount": float(amount),
            "type": income_type, "date": date}, 201


@app.route("/api/income/delete/<int:iid>", methods=["DELETE"])
@login_required
def api_income_delete(iid):
    uid = session["user_id"]
    db  = get_db()
    db.execute("DELETE FROM income WHERE id=? AND user_id=?", (iid, uid))
    db.commit()
    db.close()
    return {"deleted": iid}


@app.route("/api/income/edit/<int:iid>", methods=["PUT"])
@login_required
def api_income_edit(iid):
    uid  = session["user_id"]
    data = request.get_json()
    desc        = data.get("description", "").strip()
    amount      = data.get("amount", 0)
    income_type = data.get("income_type", "Other")
    date        = data.get("date", datetime.date.today().isoformat())
    if not desc or not amount:
        return {"error": "Description and amount are required"}, 400
    db = get_db()
    db.execute(
        "UPDATE income SET description=?, amount=?, type=?, date=? WHERE id=? AND user_id=?",
        (desc, float(amount), income_type, date, iid, uid)
    )
    db.commit()
    db.close()
    return {"id": iid, "description": desc, "amount": float(amount),
            "type": income_type, "date": date}


# ── BUDGET API ────────────────────────────────────────────────────────────

@app.route("/api/budget")
@login_required
def api_budget_get():
    uid   = session["user_id"]
    month = request.args.get("month", datetime.date.today().strftime("%m")).zfill(2)
    year  = request.args.get("year",  datetime.date.today().strftime("%Y"))
    month_str = f"{year}-{month}"
    db  = get_db()
    bud = db.execute(
        "SELECT budget, alert_pct FROM budget WHERE user_id=? AND month=?",
        (uid, month_str)
    ).fetchone()
    db.close()
    if bud:
        return {"budget": bud["budget"], "alert_pct": bud["alert_pct"], "month": month_str}
    return {"budget": 0, "alert_pct": 70, "month": month_str}


@app.route("/api/budget/delete/<int:bid>", methods=["DELETE"])
@login_required
def api_budget_delete(bid):
    uid = session["user_id"]
    db  = get_db()
    db.execute("DELETE FROM budget WHERE id=? AND user_id=?", (bid, uid))
    db.commit()
    db.close()
    return {"deleted": bid}


@app.route("/api/budget/edit/<int:bid>", methods=["PUT"])
@login_required
def api_budget_edit(bid):
    uid  = session["user_id"]
    data = request.get_json()
    month     = data.get("month", "").strip()
    amount    = data.get("budget", 0)
    alert_pct = data.get("alert_pct", 70)
    if not month or not amount:
        return {"error": "Month and budget amount are required"}, 400
    db = get_db()
    try:
        db.execute(
            "UPDATE budget SET month=?, budget=?, alert_pct=? WHERE id=? AND user_id=?",
            (month, float(amount), int(alert_pct), bid, uid)
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.close()
        return {"error": f"A budget for {month} already exists"}, 409
    db.close()
    return {"id": bid, "month": month, "budget": float(amount), "alert_pct": int(alert_pct)}


# ── SAVINGS API ───────────────────────────────────────────────────────────

@app.route("/api/savings")
@login_required
def api_savings_get():
    uid  = session["user_id"]
    db   = get_db()
    rows = db.execute(
        "SELECT * FROM savings WHERE user_id=? ORDER BY created_at DESC", (uid,)
    ).fetchall()
    db.close()
    goals = []
    for r in rows:
        g = dict(r)
        g["progress_pct"] = round((g["saved"] / g["target"]) * 100, 1) if g["target"] > 0 else 0
        g["remaining"]    = round(g["target"] - g["saved"], 2)
        goals.append(g)
    return {"goals": goals}


@app.route("/api/savings/add", methods=["POST"])
@login_required
def api_savings_add():
    uid  = session["user_id"]
    data = request.get_json()
    name          = data.get("name", "").strip()
    target_amount = data.get("target_amount", 0)
    deadline      = data.get("deadline") or None
    if not name or not target_amount:
        return {"error": "Goal name and target amount are required"}, 400
    db  = get_db()
    cur = db.execute(
        "INSERT INTO savings (user_id,goal_name,target,target_date) VALUES (?,?,?,?)",
        (uid, name, float(target_amount), deadline)
    )
    db.commit()
    new_id = cur.lastrowid
    db.close()
    return {"id": new_id, "name": name, "target_amount": float(target_amount),
            "saved": 0, "progress_pct": 0, "deadline": deadline}, 201


@app.route("/api/savings/topup/<int:gid>", methods=["POST"])
@login_required
def api_savings_topup(gid):
    uid  = session["user_id"]
    data = request.get_json()
    amount = float(data.get("amount", 0))
    if amount <= 0:
        return {"error": "Amount must be greater than 0"}, 400
    db   = get_db()
    goal = db.execute(
        "SELECT * FROM savings WHERE id=? AND user_id=?", (gid, uid)
    ).fetchone()
    if not goal:
        db.close()
        return {"error": "Goal not found"}, 404
    new_saved = min(goal["saved"] + amount, goal["target"])
    db.execute("UPDATE savings SET saved=? WHERE id=?", (new_saved, gid))
    db.commit()
    db.close()
    return {"id": gid, "saved": new_saved, "completed": new_saved >= goal["target"]}


@app.route("/api/savings/delete/<int:gid>", methods=["DELETE"])
@login_required
def api_savings_delete(gid):
    uid = session["user_id"]
    db  = get_db()
    db.execute("DELETE FROM savings WHERE id=? AND user_id=?", (gid, uid))
    db.commit()
    db.close()
    return {"deleted": gid}

# ── INIT ──────────────────────────────────────────────────────────────────
init_db()

if __name__ == "__main__":
    app.run(debug=True)