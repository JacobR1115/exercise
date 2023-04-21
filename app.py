import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///exercise.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# TODO: expand homepage, create search, and create plan pages

@app.route("/", methods=["GET"])
@login_required
def homepage():
    return render_template("homepage.html")

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
        if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["userID"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # TODO: Create parameters for the username, email, and password

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # User did not input a username
        if not request.form.get("username"):
            return apology("must provide username", 403)
        
        elif not request.form.get("email"):
            return apology("must provide emial", 403)

        # User did not input password or confirmation password
        elif not request.form.get("password") and not request.form.get("confirmation"):
            return apology("must provide password and confirm passoword", 403)

        # User's password and confirmation do not match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("password and confirmation password must match", 403)

        username = request.form.get("username")
        email = request.form.get("email")
        password = generate_password_hash(request.form.get("password"))

        # Check if username already exists
        if db.execute("SELECT * FROM users WHERE username = ?", username):
            return apology("username already exists", 403)

        # Insert username and passowrd into users
        rows = db.execute("INSERT INTO users (username, email, password) VALUES(?, ?, ?)", username, email, password)

        return redirect("/login")

    # User reached route via GET (by clicking a link or via redirect)
    else:
        return render_template("register.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")