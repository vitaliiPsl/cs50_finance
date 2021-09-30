from collections import UserDict, UserString
import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import RequestHeaderFieldsTooLarge, default_exceptions, HTTPException, InternalServerError
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

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    user_id = session["user_id"]

    # select user's cash
    cash_select = "SELECT cash FROM users WHERE id = ?"
    cash = db.execute(cash_select, user_id)[0]["cash"]

    # select quotes user own
    wallet_select = "SELECT symbol, shares FROM wallet WHERE user_id = ?"
    rows = db.execute(wallet_select, user_id)

    user_quotes = []
    grand_total = cash

    for row in rows:
        lookup_result = lookup(row["symbol"])
        total = lookup_result["price"] * row["shares"]
        grand_total += total

        user_quotes.append([row["symbol"], lookup_result["name"], row["shares"], usd(lookup_result["price"]), usd(total)])

    return render_template("index.html", user_quotes=user_quotes, cash=usd(cash), total=usd(grand_total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        symbol = request.form.get("symbol")

        # validation
        if(not symbol):
            return apology("must provide quote symbol", 400)
       
        lookup_result = lookup(symbol)

        if not lookup_result:
            return apology("no such quote", 400)

        if(not request.form.get("shares")):
            return apology("must provide shares", 400)
        
        shares = None

        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("must provide integer", 400)

        if shares < 1:
            return apology("number of shares must be more than 0", 400)

        user_id = session["user_id"]
        cash_select = "SELECT cash FROM users WHERE id = ?"

        cash = db.execute(cash_select, user_id)[0]["cash"]

        print("CASH")
        print(cash)

        total = lookup_result["price"] * shares

        if total > cash:
            return apology(f"you don't have enogh money to buy {shares} shares of {symbol}", 400)
        
        # save transaction
        transaction_insert = "INSERT INTO transactions(user_id, symbol, company, price, shares) VALUES (?, ?, ?, ?, ?)"
        db.execute(transaction_insert, user_id, symbol, lookup_result["name"], lookup_result["price"], shares)

        # check if user already has this quote
        wallet_select = "SELECT * FROM wallet WHERE user_id = ? AND symbol LIKE ?"
        
        row = db.execute(wallet_select, user_id, symbol)
        
        print(row)

        if len(row) == 0:
            wallet_insert = "INSERT INTO wallet(user_id, symbol, shares) VALUES(?, ?, ?)"
            db.execute(wallet_insert, user_id, symbol, shares)
        else:
            current_shares = row[0]["shares"]
            wallet_update = "UPDATE wallet SET shares = ? WHERE user_id = ?"
            db.execute(wallet_update, current_shares + shares, user_id)

        # update user's cash
        users_update = "UPDATE users SET cash = ? WHERE id = ?"
        db.execute(users_update, cash - total, user_id)

        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    user_id = session["user_id"]

    transaction_select = "SELECT * FROM transactions WHERE user_id = ?"
    rows = db.execute(transaction_select, user_id)

    transactions = []

    for row in rows:
        transactions.append([row["symbol"], row["company"], row["price"], row["shares"], row["transaction_date"]])

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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
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
    if request.method == "POST":
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("you must provide quote symbol", 400)
        
        lookup_result = lookup(symbol)

        if not lookup_result:
            return apology("no such quote", 400)
        
        lookup_result["price"] = usd(lookup_result["price"])
    
        return render_template("quoted.html", data=lookup_result)
    
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("must provide username", 400)
        
            
        username_select = "SELECT * FROM users WHERE username LIKE ?"
        
        rows = db.execute(username_select, username)
        
        if len(rows) != 0:
            return apology("username already taken", 400)

        if not password:
            return apology("must provide password", 400)
        
        if not (password == confirmation):
            return apology("passwords doesn't match")

        hashed_password = generate_password_hash(password)
        
        data = [username, hashed_password]
        users_insert = "INSERT INTO users(username, hash) VALUES(?, ?)"
        index = db.execute(users_insert, username, hashed_password)
        
        print(index)

        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    user_id = session["user_id"]

    if request.method == "POST":

        symbol = request.form.get("symbol")

        print(symbol)

        if not symbol:
            return render_template("must provide symbol", 400)

    # shares validation   
        if(not request.form.get("shares")):
            return apology("must provide shares", 400)
        
        shares = None

        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("must provide integer", 400)

        if shares < 1:
            return apology("number of shares must be more than 0", 400)
    ############

        shares_select = "SELECT shares FROM wallet WHERE user_id = ? AND symbol LIKE ?"
        user_shares = db.execute(shares_select, user_id, symbol)[0]["shares"]

        if shares > user_shares:
            return apology(f"you don't have {shares} shares of {symbol}")
        
        lookup_result = lookup(symbol)

        total = shares * lookup_result["price"]

        if shares == user_shares:
            wallet_delete = "DELETE FROM wallet WHERE user_id = ? AND symbol LIKE ?"
            db.execute(wallet_delete, user_id, symbol)

        else:
            wallet_update = "UPDATE wallet SET shares = ? WHERE user_id = ? AND symbol LIKE ?"
            db.execute(wallet_update, user_shares - shares, user_id, symbol)
        
        user_cash_update = "UPDATE users SET cash = cash + ? WHERE id = ?"
        db.execute(user_cash_update, total, user_id)

        transactions_insert = "INSERT INTO transactions(user_id, symbol, company, price, shares) VALUES (?, ?, ?, ?, ?)"
        db.execute(transactions_insert, user_id, symbol, lookup_result["name"], lookup_result["price"], -shares)

        return redirect("/")

    symbols_select = "SELECT symbol FROM wallet WHERE user_id = ?"
    rows = db.execute(symbols_select, user_id)

    symbols = []
    
    for row in rows:
        symbols.append(row["symbol"]) 

    return render_template("sell.html", symbols=symbols)

@app.route("/preferences")
def preferences():
    return render_template("preferences.html")

@app.route("/password", methods=["GET", "POST"])
def password():
    if(request.method == "POST"):
        user_id = session["user_id"]

        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")



        if not old_password:
            return apology("must provide old password", 403)

        user_select = "SELECT hash FROM users WHERE id = ?"
        password = db.execute(user_select, user_id)[0]["hash"]

        if not check_password_hash(password, old_password):
                    return apology("Invalid old password", 403)

        if not new_password:
            return apology("must provide new password", 403)

        if new_password != confirmation:
            return apology("password doesn't match")

        password = generate_password_hash(new_password)

        user_update = "UPDATE users SET hash = ? WHERE id = ?"

        db.execute(user_update, password, user_id)

        return render_template("password_changed.html")

    return render_template("password.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
