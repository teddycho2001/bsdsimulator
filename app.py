import os
import sqlite3

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Connect to SQLite database
    with sqlite3.connect("finance.db") as conn:
        conn.row_factory = dict_factory
        c = conn.cursor()

        # Query the user's current cash balance
        c.execute("SELECT * FROM users WHERE id = (?)", (session["user_id"],))
        rows = c.fetchall()
        cash = rows[0]["cash"]

        # Query the user's current stock portfolio
        c.execute(
            "SELECT SUM(shares) AS shares, symbol, name FROM transactions WHERE user_id = (?) GROUP BY symbol HAVING SUM(shares) > 0 ORDER BY symbol",
            (session["user_id"],))
        rows = c.fetchall()

        # Lookup current price of each stock in portfolio
        for stock in rows:
            stock["price"] = lookup(stock["symbol"])["price"]

        # Calculate total portfolio value
        value = cash
        for stock in rows:
            value += stock["price"] * stock["shares"]

        return render_template("index.html", cash=cash, rows=rows, value=value)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Connect to SQLite database
    with sqlite3.connect("finance.db") as conn:
        conn.row_factory = dict_factory
        c = conn.cursor()

        # Forget any user_id
        session.clear()

        # User reached route via POST (as by submitting a form via POST)
        if request.method == "POST":

            # Ensure username was submitted
            if not request.form.get("username"):
                flash("Must provide username.")
                return render_template("register.html")

            # Ensure password was submitted
            if not request.form.get("password"):
                flash("Must provide password.")
                return render_template("register.html")

            # Ensure password meets length requirement
            if len(request.form.get("password")) < 6:
                flash("Password does not meet length requirement.")
                return render_template("register.html")

            # Ensure password fields match
            if request.form.get("password") != request.form.get("confirmation"):
                flash("Passwords do not match.")
                return render_template("register.html")

            # Query database for username
            c.execute("SELECT * FROM users WHERE username = (?)", (request.form.get("username"),))
            rows = c.fetchall()

            # Ensure username doesn't already exist
            if len(rows) != 0:
                flash("Username is not available.")
                return render_template("register.html")

            # Insert user credentials into database
            c.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                      (request.form.get("username"), generate_password_hash(request.form.get("password")),))
            id = c.lastrowid
            conn.commit()

            # Remember which user has registered
            session["user_id"] = id

            # Redirect user to home page
            flash("Registered!")
            return redirect("/")

        # User reached route via GET (as by clicking a link or via redirect)
        else:
            return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Connect to SQLite database
    with sqlite3.connect("finance.db") as conn:
        conn.row_factory = dict_factory
        c = conn.cursor()

        # Forget any user_id
        session.clear()

        # User reached route via POST (as by submitting a form via POST)
        if request.method == "POST":

            # Ensure username was submitted
            if not request.form.get("username"):
                flash("Must provide username.")
                return render_template("login.html")

            # Ensure password was submitted
            if not request.form.get("password"):
                flash("Must provide password.")
                return render_template("login.html")

            # Query database for username
            c.execute("SELECT * FROM users WHERE username = (?)", (request.form.get("username"),))
            rows = c.fetchall()

            # Ensure username exists and password is correct
            if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
                flash("Invalid username and/or password.")
                return render_template("login.html")

            # Remember which user has logged in
            session["user_id"] = rows[0]["id"]

            # Redirect user to home page
            flash("Logged in!")
            return redirect("/")

        # User reached route via GET (as by clicking a link or via redirect)
        else:
            return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            flash("Missing symbol.")
            return render_template("quote.html")

        # Lookup the stock symbol
        quote = lookup(request.form.get("symbol"))

        # Ensure symbol is valid
        if quote is None:
            flash("Invalid symbol.")
            return render_template("quote.html")

        return render_template("quoted.html", quote=quote)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # Connect to SQLite database
    with sqlite3.connect("finance.db") as conn:
        conn.row_factory = dict_factory
        c = conn.cursor()

        # User reached route via POST (as by submitting a form via POST)
        if request.method == "POST":

            # Ensure symbol was submitted
            if not request.form.get("symbol"):
                flash("Missing symbol.")
                return render_template("buy.html")

            # Ensure shares was submitted
            if not request.form.get("shares"):
                flash("Missing shares.")
                return render_template("buy.html")

            # Lookup the stock symbol
            quote = lookup(request.form.get("symbol"))

            # Ensure symbol is valid
            if quote is None:
                flash("Invalid symbol.")
                return render_template("buy.html")

            # Query how much cash the user currently has
            c.execute("SELECT * FROM users WHERE id = (?)", (session["user_id"],))
            rows = c.fetchall()
            cash = rows[0]["cash"]

            # Ensure user can afford the stock
            if cash < int(request.form.get("shares")) * quote["price"]:
                flash("Cannot afford stock.")
                return render_template("buy.html")

            # Buy stock
            cash -= int(request.form.get("shares")) * quote["price"]
            bought = int(request.form.get("shares"))
            c.execute("INSERT INTO transactions (user_id, name, symbol, shares, price) VALUES (?, ?, ?, ?, ?)",
                      (session["user_id"], quote["name"], quote["symbol"], bought, quote["price"],))
            c.execute("UPDATE users SET cash = (?) WHERE id = (?)", (cash, session["user_id"],))
            conn.commit()

            # Redirect user to home page
            flash("Bought!")
            return redirect("/")

        # User reached route via GET (as by clicking a link or via redirect)
        else:
            return render_template("buy.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # Connect to SQLite database
    with sqlite3.connect("finance.db") as conn:
        conn.row_factory = dict_factory
        c = conn.cursor()

        # User reached route via POST (as by submitting a form via POST)
        if request.method == "POST":

            # Ensure symbol was submitted
            if not request.form.get("symbol"):
                flash("Missing symbol.")
                c.execute(
                    "SELECT symbol FROM transactions WHERE user_id = (?) GROUP BY symbol HAVING SUM(shares) > 0 ORDER BY symbol",
                    (session["user_id"],))
                rows = c.fetchall()
                return render_template("sell.html", rows=rows)

            # Ensure shares was submitted
            if not request.form.get("shares"):
                flash("Missing shares.")
                c.execute(
                    "SELECT symbol FROM transactions WHERE user_id = (?) GROUP BY symbol HAVING SUM(shares) > 0 ORDER BY symbol",
                    (session["user_id"],))
                rows = c.fetchall()
                return render_template("sell.html", rows=rows)

            # Query how many shares of the stock the user has
            c.execute("SELECT SUM(shares) AS shares FROM transactions WHERE user_id = (?) AND symbol = (?)",
                      (session["user_id"], request.form.get("symbol"),))
            rows = c.fetchall()

            # Ensure user actually owns shares of the stock
            if rows[0]["shares"] < 1:
                flash("You do not own any shares.")
                c.execute(
                    "SELECT symbol FROM transactions WHERE user_id = (?) GROUP BY symbol HAVING SUM(shares) > 0 ORDER BY symbol",
                    (session["user_id"],))
                rows = c.fetchall()
                return render_template("sell.html", rows=rows)

            # Ensure user owns enough shares of the stock
            if rows[0]["shares"] < int(request.form.get("shares")):
                flash("You do not own enough shares.")
                c.execute(
                    "SELECT symbol FROM transactions WHERE user_id = (?) GROUP BY symbol HAVING SUM(shares) > 0 ORDER BY symbol",
                    (session["user_id"],))
                rows = c.fetchall()
                return render_template("sell.html", rows=rows)

            # Query stock price
            quote = lookup(request.form.get("symbol"))

            # Query current cash balance
            c.execute("SELECT * FROM users WHERE id = (?)", (session["user_id"],))
            rows = c.fetchall()
            cash = rows[0]["cash"]

            # Sell stock
            cash += int(request.form.get("shares")) * quote["price"]
            sold = -(int(request.form.get("shares")))
            c.execute("INSERT INTO transactions (user_id, name, symbol, shares, price) VALUES (?, ?, ?, ?, ?)",
                      (session["user_id"], quote["name"], quote["symbol"], sold, quote["price"],))
            c.execute("UPDATE users SET cash = (?) WHERE id = (?)", (cash, session["user_id"],))
            conn.commit()

            # Redirect user to home page
            flash("Sold!")
            return redirect("/")

        # User reached route via GET (as by clicking a link or via redirect)
        else:

            # Query the user's current stock portfolio
            c.execute(
                "SELECT symbol FROM transactions WHERE user_id = (?) GROUP BY symbol HAVING SUM(shares) > 0 ORDER BY symbol",
                (session["user_id"],))
            rows = c.fetchall()
            return render_template("sell.html", rows=rows)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Connect to SQLite database
    with sqlite3.connect("finance.db") as conn:
        conn.row_factory = dict_factory
        c = conn.cursor()

        # Query the user's transaction history
        c.execute("SELECT * FROM transactions WHERE user_id = (?)", (session["user_id"],))
        rows = c.fetchall()
        return render_template("history.html", rows=rows)


@app.route("/leaderboard")
@login_required
def leaderboard():
    """Show leaderboard"""

    # Connect to SQLite database
    with sqlite3.connect("finance.db") as conn:
        conn.row_factory = dict_factory
        c = conn.cursor()

        c.execute("SELECT * FROM users")
        users = c.fetchall()

        # Calculate and assign every user's net worth
        for user in users:

            # Initialize the user's net worth to user's cash holdings
            user["networth"] = user["cash"]

            # Query the the user's current stock portfolio
            c.execute(
                "SELECT SUM(shares) AS shares, symbol FROM transactions WHERE user_id = (?) GROUP BY symbol HAVING SUM(shares) > 0",
                (user["id"],))
            stocks = c.fetchall()

            # Calculate the user's net worth with user's stock holdings
            for stock in stocks:
                # Lookup current price of each stock in portfolio
                stock["price"] = lookup(stock["symbol"])["price"]

                # Update the user's net worth
                user["networth"] += stock["price"] * stock["shares"]

        # Sort list by user net worth
        ranking = sorted(users, key=lambda item: item["networth"], reverse=True)

        # Calculate and assign every user's rank
        rank = 1
        for user in ranking:
            user["rank"] = rank
            rank += 1

        return render_template("leaderboard.html", ranking=ranking)


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    """Change user's password"""

    # Connect to SQLite database
    with sqlite3.connect("finance.db") as conn:
        conn.row_factory = dict_factory
        c = conn.cursor()

        # User reached route via POST (as by submitting a form via POST)
        if request.method == "POST":

            # Ensure old password was submitted
            if not request.form.get("old_password"):
                flash("Must provide current password.")
                return render_template("account.html")

            # Ensure new password was submitted
            if not request.form.get("new_password"):
                flash("Must provide new password.")
                return render_template("account.html")

            # Ensure new password meets length requirement
            if len(request.form.get("new_password")) < 6:
                flash("New password does not meet length requirement.")
                return render_template("account.html")

            # Ensure password fields match
            if request.form.get("new_password") != request.form.get("confirmation"):
                flash("Passwords do not match.")
                return render_template("account.html")

            # Query database for password
            c.execute("SELECT * FROM users WHERE id = (?)", (session["user_id"],))
            rows = c.fetchall()

            # Ensure old password is correct
            if not check_password_hash(rows[0]["hash"], request.form.get("old_password")):
                flash("Invalid current password.")
                return render_template("account.html")

            # Update the database with the new password
            c.execute("UPDATE users SET hash = (?) WHERE id = (?)",
                      (generate_password_hash(request.form.get("new_password")), session["user_id"],))
            conn.commit()

            # Redirect user to home page
            flash("Password changed!")
            return redirect("/")

        # User reached route via GET (as by clicking a link or via redirect)
        else:
            return render_template("account.html")


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
