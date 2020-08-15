import os

from datetime import datetime
from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Load environment variables from .env
load_dotenv()

# Configure application
app = Flask(__name__)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
db = SQLAlchemy(app)


# Declare User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    hash = db.Column(db.String(256), nullable=False)
    cash = db.Column(db.Numeric, nullable=False, default=10000.00)
    transactions = db.relationship("Transaction", backref="user", lazy=True)

    def __init__(self, username, hash):
        self.username = username
        self.hash = hash


# Declare Transaction model
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name = db.Column(db.String(64), nullable=False)
    symbol = db.Column(db.String(16), nullable=False)
    shares = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Numeric, nullable=False)
    transacted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __init__(self, user_id, name, symbol, shares, price):
        self.user_id = user_id
        self.name = name
        self.symbol = symbol
        self.shares = shares
        self.price = price


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

    # Query the user's current cash balance
    user = User.query.get(session["user_id"])
    cash = float(user.cash)
    networth = cash

    # Query the user's current stock portfolio
    stocks = db.session.query(db.func.sum(Transaction.shares).label("shares"), Transaction.symbol).filter_by(
        user_id=session["user_id"]).group_by(Transaction.symbol).having(db.func.sum(Transaction.shares) > 0).order_by(
        Transaction.symbol).all()

    portfolio = []

    # Generate user portfolio and compute net worth
    for stock in stocks:
        tmpstock = {"shares": stock.shares, "symbol": stock.symbol}
        tmpprice = lookup(stock.symbol)["price"]
        tmpname = lookup(stock.symbol)["name"]
        tmpstock["price"] = tmpprice
        tmpstock["name"] = tmpname
        networth += tmpprice * stock.shares
        portfolio.append(tmpstock)

    return render_template("index.html", portfolio=portfolio, cash=cash, networth=networth)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

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
        user = User.query.filter_by(username=request.form.get("username")).first()

        # Ensure username doesn't already exist
        if user is not None:
            flash("Username is not available.")
            return render_template("register.html")

        # Insert user credentials into database
        user = User(request.form.get("username"), generate_password_hash(request.form.get("password")))
        db.session.add(user)
        db.session.commit()

        # Remember which user has registered
        session["user_id"] = user.id

        # Redirect user to home page
        flash("Registered!")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

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
        user = User.query.filter_by(username=request.form.get("username")).first()

        # Ensure username exists and password is correct
        if user is None or not check_password_hash(user.hash, request.form.get("password")):
            flash("Invalid username and/or password.")
            return render_template("login.html")

        # Remember which user has logged in
        session["user_id"] = user.id

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
        stock = lookup(request.form.get("symbol"))

        # Ensure symbol is valid
        if stock is None:
            flash("Invalid symbol.")
            return render_template("quote.html")

        return render_template("quoted.html", stock=stock)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

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
        stock = lookup(request.form.get("symbol"))

        # Ensure symbol is valid
        if stock is None:
            flash("Invalid symbol.")
            return render_template("buy.html")

        # Query how much cash the user currently has
        user = User.query.get(session["user_id"])
        cash = float(user.cash)

        # Ensure user can afford the stock
        if cash < int(request.form.get("shares")) * stock["price"]:
            flash("Cannot afford stock.")
            return render_template("buy.html")

        # Calculate cash upon purchase and update database
        cash -= int(request.form.get("shares")) * stock["price"]
        user.cash = cash

        # Insert buy transaction into database
        quantity = int(request.form.get("shares"))
        transaction = Transaction(session["user_id"], stock["name"], stock["symbol"], quantity, stock["price"])
        db.session.add(transaction)
        db.session.commit()

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

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            flash("Missing symbol.")
            stocks = db.session.query(Transaction.symbol).filter_by(user_id=session["user_id"]).group_by(
                Transaction.symbol).having(db.func.sum(Transaction.shares) > 0).order_by(
                Transaction.symbol).all()
            return render_template("sell.html", stocks=stocks)

        # Ensure shares was submitted
        if not request.form.get("shares"):
            flash("Missing shares.")
            stocks = db.session.query(Transaction.symbol).filter_by(user_id=session["user_id"]).group_by(
                Transaction.symbol).having(db.func.sum(Transaction.shares) > 0).order_by(
                Transaction.symbol).all()
            return render_template("sell.html", stocks=stocks)

        # Query how many shares of the stock the user has
        transactions = Transaction.query.filter_by(user_id=session["user_id"], symbol=request.form.get("symbol")).all()

        quantity = 0
        for transaction in transactions:
            quantity += transaction.shares

        # Ensure user actually owns shares of the stock
        if quantity < 1:
            flash("You do not own any shares.")
            stocks = db.session.query(Transaction.symbol).filter_by(user_id=session["user_id"]).group_by(
                Transaction.symbol).having(db.func.sum(Transaction.shares) > 0).order_by(
                Transaction.symbol).all()
            return render_template("sell.html", stocks=stocks)

        # Ensure user owns enough shares of the stock
        if quantity < int(request.form.get("shares")):
            flash("You do not own enough shares.")
            stocks = db.session.query(Transaction.symbol).filter_by(user_id=session["user_id"]).group_by(
                Transaction.symbol).having(db.func.sum(Transaction.shares) > 0).order_by(
                Transaction.symbol).all()
            return render_template("sell.html", stocks=stocks)

        # Query stock price
        stock = lookup(request.form.get("symbol"))

        # Query current cash balance
        user = User.query.get(session["user_id"])
        cash = float(user.cash)

        # Calculate cash upon sale and update database
        cash += int(request.form.get("shares")) * stock["price"]
        user.cash = cash

        # Insert sell transaction into database
        quantity = -(int(request.form.get("shares")))
        transaction = Transaction(session["user_id"], stock["name"], stock["symbol"], quantity, stock["price"])
        db.session.add(transaction)
        db.session.commit()

        # Redirect user to home page
        flash("Sold!")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:

        # Query the user's current stock portfolio
        stocks = db.session.query(Transaction.symbol).filter_by(user_id=session["user_id"]).group_by(
            Transaction.symbol).having(db.func.sum(Transaction.shares) > 0).order_by(
            Transaction.symbol).all()
        return render_template("sell.html", stocks=stocks)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Query the user's transaction history
    transactions = Transaction.query.filter_by(user_id=session["user_id"]).all()
    return render_template("history.html", transactions=transactions)


@app.route("/leaderboard")
@login_required
def leaderboard():
    """Show leaderboard"""

    users = User.query.all()

    ranking = []

    # Compute every user's net worth
    for user in users:
        tmpuser = {"username": user.username, "networth": float(user.cash)}

        # Query the the user's current stock portfolio
        stocks = db.session.query(db.func.sum(Transaction.shares).label("shares"), Transaction.symbol).filter_by(
            user_id=user.id).group_by(Transaction.symbol).having(db.func.sum(Transaction.shares) > 0).all()

        # Calculate the user's net worth with user's stock holdings
        for stock in stocks:
            tmpprice = lookup(stock.symbol)["price"]
            tmpuser["networth"] += tmpprice * stock.shares

        ranking.append(tmpuser)

    # Sort list by user net worth
    leaderboard = sorted(ranking, key=lambda item: item["networth"], reverse=True)

    # Assign a rank to every user in leaderboard
    rank = 1
    for user in leaderboard:
        user["rank"] = rank
        rank += 1

    return render_template("leaderboard.html", leaderboard=leaderboard)


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    """Change user's password"""

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
        user = User.query.get(session["user_id"])

        # Ensure old password is correct
        if not check_password_hash(user.hash, request.form.get("old_password")):
            flash("Invalid current password.")
            return render_template("account.html")

        # Update the database with the new password
        user.hash = generate_password_hash(request.form.get("new_password"))
        db.session.commit()

        # Redirect user to home page
        flash("Password changed!")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("account.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
