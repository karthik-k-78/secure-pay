from flask import Flask, render_template, request, redirect, session
import sqlite3
import uuid
import datetime
import bcrypt

app = Flask(__name__)
app.secret_key = "supersecret"

# ---------- DATABASE SETUP ----------
def init_db():
    conn = sqlite3.connect("database.db")
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    email TEXT UNIQUE,
                    password BLOB,
                    balance INTEGER DEFAULT 1000)''')

    conn.execute('''CREATE TABLE IF NOT EXISTS tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id INTEGER,
                    token TEXT,
                    amount INTEGER,
                    expiry TEXT,
                    used INTEGER DEFAULT 0)''')

    conn.execute('''CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id INTEGER,
                    receiver_id INTEGER,
                    amount INTEGER,
                    time TEXT)''')
    conn.commit()
    conn.close()

init_db()

# ---------- ROUTES ----------

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["POST"])
def register():
    name = request.form["name"]
    email = request.form["email"]
    password = bcrypt.hashpw(request.form["password"].encode(), bcrypt.gensalt())

    conn = sqlite3.connect("database.db")
    conn.execute("INSERT INTO users (name,email,password) VALUES (?,?,?)",
                 (name,email,password))
    conn.commit()
    conn.close()
    return redirect("/")

@app.route("/login", methods=["POST"])
def login():
    email = request.form["email"]
    password = request.form["password"]

    conn = sqlite3.connect("database.db")
    cur = conn.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cur.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode(), user[3]):
        session["user_id"] = user[0]
        return redirect("/dashboard")
    return "Invalid Credentials"

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/")

    conn = sqlite3.connect("database.db")
    cur = conn.execute("SELECT balance FROM users WHERE id=?", (session["user_id"],))
    balance = cur.fetchone()[0]

    tx = conn.execute("SELECT * FROM transactions WHERE sender_id=? OR receiver_id=?",
                      (session["user_id"], session["user_id"])).fetchall()
    conn.close()

    return render_template("dashboard.html", balance=balance, transactions=tx)

@app.route("/generate_token", methods=["POST"])
def generate_token():
    amount = int(request.form["amount"])
    token = str(uuid.uuid4())[:8]
    expiry = (datetime.datetime.now() + datetime.timedelta(seconds=120)).isoformat()

    conn = sqlite3.connect("database.db")
    conn.execute("INSERT INTO tokens (sender_id, token, amount, expiry) VALUES (?,?,?,?)",
                 (session["user_id"], token, amount, expiry))
    conn.commit()
    conn.close()

    return render_template("token.html", token=token)

@app.route("/verify", methods=["POST"])
def verify():
    token_input = request.form["token"]

    conn = sqlite3.connect("database.db")
    cur = conn.execute("SELECT * FROM tokens WHERE token=? AND used=0", (token_input,))
    token = cur.fetchone()

    if not token:
        conn.close()
        return "Invalid or Expired Token"

    sender_id = token[1]
    amount = token[3]
    expiry = datetime.datetime.fromisoformat(token[4])

    if datetime.datetime.now() > expiry:
        conn.close()
        return "Token Expired"

    receiver_id = session["user_id"]

    # Transfer money
    conn.execute("UPDATE users SET balance = balance - ? WHERE id=?", (amount, sender_id))
    conn.execute("UPDATE users SET balance = balance + ? WHERE id=?", (amount, receiver_id))

    conn.execute("INSERT INTO transactions (sender_id,receiver_id,amount,time) VALUES (?,?,?,?)",
                 (sender_id, receiver_id, amount, datetime.datetime.now().isoformat()))

    conn.execute("UPDATE tokens SET used=1 WHERE token=?", (token_input,))
    conn.commit()
    conn.close()

    return redirect("/dashboard")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)