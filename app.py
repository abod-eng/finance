import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Get user stocks and shares
    stocks = db.execute("SELECT symbol, SUM(shares) as total_shares FROM transactions WHERE user_id = :user_id GROUP BY symbol HAVING total_shares > 0",
                        user_id=session["user_id"])
    # Get user cash balance
    cash = db.execute("SELECT cash FROM users WHERE id = :user_id",
                      user_id=session["user_id"])[0]["cash"]
    # variables for total values
    total_value = cash
    grand_total = cash

    for stock in stocks:
        quote = lookup(stock["symbol"])
        stock["name"] = quote["name"]
        stock["price"] = quote["price"]
        stock["value"] = stock["price"] * stock["total_shares"]
        total_value += stock["value"]
        grand_total += stock["value"]

    return render_template("index.html", stocks=stocks, cash=cash, total_value=usd(total_value), grand_total=usd(grand_total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # Get form inputs
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")

        # Validate symbol and shares
        if not symbol:
            return apology("Must provide symbol", 400)
        elif not shares or not shares.isdigit() or int(shares) <= 0:
            return apology("Must provide valid number of shares", 400)

        # Lookup stock
        quote = lookup(symbol)
        if quote is None:
            return apology("Symbol not found", 400)

        # Calculate price and total cost
        price = quote["price"]
        total_cost = int(shares) * price

        # Get user's cash
        cash = db.execute("SELECT cash FROM users WHERE id = :user_id",
                          user_id=session["user_id"])[0]["cash"]

        # Check if user has enough cash
        if cash < total_cost:
            return apology("Not enough cash", 400)

        # Update user's cash
        db.execute("UPDATE users SET cash = cash - :total_cost WHERE id = :user_id",
                   total_cost=total_cost, user_id=session["user_id"])

        # Insert transaction into 'transactions' table
        db.execute(
            "INSERT INTO transactions (user_id, symbol, price, shares, type) VALUES(:user_id, :symbol, :price, :shares, :type)",
            user_id=session["user_id"], symbol=symbol, price=usd(price), shares=int(shares), type="BUY"
        )

        # Flash success message
        flash(f"Bought {shares} shares of {symbol} for {usd(total_cost)}")
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute(
        "SELECT * FROM transactions WHERE user_id = :user_id ORDER BY timestamp DESC", user_id=session["user_id"])
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
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
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        quote = lookup(symbol)
        if not quote:
            return apology("Invalid symbol", 400)
        return render_template("quote.html", quote=quote)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    session.clear()
    # Ensure user reached route via POST
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure password confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide password confirmation", 400)

        # Ensure password and password confirmation match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords must match", 400)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username does not already exist
        if len(rows) != 0:
            return apology("username already exists", 400)

        # Insert new user into database
        db.execute(
            "INSERT INTO users (username, hash) VALUES(?, ?)",
            request.form.get("username"),
            generate_password_hash(request.form.get("password")),
        )

        # Query database for newly created user
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")
    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # Get user stocks
    stocks = db.execute("SELECT symbol, SUM(shares) as total_shares FROM transactions WHERE user_id = :user_id GROUP BY symbol HAVING total_shares > 0",
                        user_id=session["user_id"])
    # Render sell form if the user submits the form
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")
        if not symbol:
            return apology("Must provide symbol")
        elif not shares or not shares.isdigit() or int(shares) <= 0:
            return apology("Must provide valid number of shares")
        else:
            shares = int(shares)

        # Check if the user has enough shares
        for stock in stocks:
            if stock["symbol"] == symbol:
                if stock["total_shares"] < shares:
                    return apology("Not enough shares")
                else:
                    quote = lookup(symbol)
                    if quote is None:
                        return apology("Symbol not found")
                    price = quote["price"]
                    total_sale = price * shares
                    # Update users cash
                    db.execute("UPDATE users SET cash = cash + :total_sale WHERE id = :user_id",
                               total_sale=total_sale, user_id=session["user_id"])
                    # Insert transaction
                    db.execute("INSERT INTO transactions (user_id, symbol, price, shares, type) VALUES(:user_id, :symbol, :price, :shares, :type)",
                               user_id=session["user_id"], symbol=symbol, price=usd(price), shares=-shares, type="SELL")
                    flash(f"Sold {shares} shares of {symbol} for {usd(total_sale)}")
                    return redirect("/")
        return apology("Symbol not found")
    else:
        return render_template("sell.html", stocks=stocks)


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change user password"""
    if request.method == "POST":
        # Get form inputs
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        # Ensure current password is provided
        if not current_password:
            return apology("Must provide current password", 400)

        # Ensure new password is provided
        if not new_password:
            return apology("Must provide new password", 400)

        # Ensure new password matches confirmation
        if new_password != confirmation:
            return apology("New passwords must match", 400)

        # Query database for user
        user = db.execute("SELECT * FROM users WHERE id = :user_id", user_id=session["user_id"])

        # Check if the current password is correct
        if len(user) != 1 or not check_password_hash(user[0]["hash"], current_password):
            return apology("Incorrect current password", 400)

        # Hash the new password
        new_hash = generate_password_hash(new_password)

        # Update the password in the database
        db.execute("UPDATE users SET hash = :new_hash WHERE id = :user_id",
                   new_hash=new_hash, user_id=session["user_id"])

        flash("Password changed successfully")
        return redirect("/")

    else:
        return render_template("change_password.html")


@app.route("/add_cash", methods=["GET", "POST"])
def add_cash():
    # Ensure the user is logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    # If the form is submitted
    if request.method == "POST":
        # Get the amount to add from the form
        amount = request.form.get("amount")

        # Validate the input
        if not amount or not amount.isdigit() or float(amount) <= 0:
            flash("Invalid amount. Please enter a valid number.")
            return redirect(url_for("add_cash"))

        # Convert the amount to a float
        amount = float(amount)

        # Update the user's cash in the database
        user_id = session["user_id"]
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", amount, user_id)

        # Flash a success message
        flash(f"Successfully added ${amount:.2f} to your account.")

        return redirect("/")

    # Render the add_cash form
    return render_template("add_cash.html")
