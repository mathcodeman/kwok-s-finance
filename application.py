import os
import time
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session,url_for
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

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    print(session["user_id"])
    cash = db.execute("SELECT cash FROM users WHERE id = ?;", session["user_id"] )[0]["cash"]
    current_position = db.execute("SELECT * FROM buy_sell WHERE buy_sell_id = ?;",session["user_id"] )

    total_balance = cash
    for i in current_position:
        i["price"]=lookup(i["symbol"]).get("price")
        i["total"]= float(i["price"])*float(i["share"])
        total_balance += i["total"]
        print(total_balance)
        #Calculate average holding price
        price_share = db.execute("SELECT * FROM txn_history WHERE txn_id = ? AND symbol = ?;",session["user_id"],i["symbol"])
        total_share = db.execute("SELECT share FROM buy_sell WHERE buy_sell_id = ? AND symbol = ?;", session["user_id"],i["symbol"])[0]["share"]
        sum = 0
        for x in price_share:
            sum += float(x["price"])*float(x["share"])
            avg_holding = sum/total_share
        i["holding_price"] = avg_holding
        PnL = (float(i["price"])-float(avg_holding))/float(avg_holding)*100
        i["PnL_ratio"] = PnL

    return render_template("index.html",cash=cash,current_position=current_position, total_balance=total_balance, Title = "Your personal porfolio")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    buy_symbol = request.form.get("Symbol")
    buy_shares = request.form.get("shares")
    if request.method == "POST":
        if not buy_symbol:
            return apology("Please enter stock symbol", 403 )

        #Check whether user enter vaild stock symbol
        elif lookup(buy_symbol) == None:
            return apology("Invaild stock symbol", 403 )

        #Check whether user enter share amount
        elif not buy_shares:
            return apology("Please enter shares amout", 403 )


        #Retrieve data for txn_history_storing purpose
        current_price = lookup(buy_symbol).get('price')
        current_symbol = lookup(buy_symbol).get('symbol')
        current_name = lookup(buy_symbol).get('name')
        current_time = time.ctime(time.time())

        #Check current balance of user has
        balance = db.execute("SELECT cash FROM users WHERE id = ?;", session["user_id"])[0]["cash"]

        #Calculate the total cost of the purchase
        purchase_cost = float(current_price) * float(buy_shares)

        #Check if customer has suffient fund for this txn
        if purchase_cost > balance:
            return apology("You dont have enough balance in the account", 403)
        else:

            #Update new balance for user of the trade
            new_cash = balance - purchase_cost
            update_balance = db.execute("UPDATE users SET cash = ? WHERE id = ?;",new_cash,session["user_id"])

            #(Need to modify this table) Record the txn history to database
            txn_record = db.execute("INSERT INTO txn_history (price,purchase_cost,share,symbol,txn_id,time) VALUES(?, ?, ?, ?, ?, ?) ;",current_price,purchase_cost,buy_shares,current_symbol,session["user_id"],current_time)

            #CREATE TABLE txn_history (Price of the current share, total cost of the trade, symbol of the trade, BUY/SELL, tradetime)

            try:
                #Check whether current stock has been store in database
                current_share = db.execute("SELECT share FROM buy_sell WHERE symbol = ? AND buy_sell_id = ?;", current_symbol, session["user_id"])[0]["share"]
            except IndexError:
                #Create database for current stock if not exsited yet
                new_share = db.execute("INSERT INTO buy_sell(buy_sell_id, share, symbol, name) VALUES(?, ?, ?, ?);",session["user_id"],buy_shares,current_symbol,current_name)
            else:
                #Update share number if current stock already stored in database
                add_share = current_share + int(buy_shares)
                update_share = db.execute("UPDATE buy_sell SET share = ? WHERE symbol = ? AND buy_sell_id = ?;", add_share, current_symbol, session["user_id"])

            


        return redirect("/")
    else:
        return render_template("buy.html",Title = "You can buy stocks here")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    txn_history = db.execute("SELECT * FROM txn_history WHERE txn_id = ?;", session["user_id"])
    return render_template("history.html",txn_history=txn_history)


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
        return render_template("login.html",Title = "Welcome to the trading world")


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
    symbol = request.form.get("symbol")

    if request.method == "POST":
        # Check out whether is vaild symbol
        quote_detail = lookup(symbol)
        if quote_detail == None:
            return apology("Invaild symbol", 403 )
        else:
            return render_template("quote_detail.html", quote_detail=quote_detail)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    #Fortget User ID
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        password_check = request.form.get("password-check")
        # Check if user enter username
        if not username:
            return apology("Missing user name", 403 )

        # Check if user enter password
        elif not password:
            return apology("Missing password", 403 )

        # Check if user re-enter username
        elif not password_check:
            return apology("Please confirm your password", 403 )

        # Check if user's password same as the re-enter password
        elif password!=password_check:
            return apology("Your password does not match", 403 )

        # Hash the password and store into database
        password_hash = generate_password_hash(password)
        db.execute("INSERT INTO users (username,hash) VALUES(?, ?)", username,password_hash)

        print(password_hash)

        return redirect('/')
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # Look up all stocks that user currently holding to create selection for frontend option
    symbols = db.execute("SELECT symbol FROM buy_sell WHERE buy_sell_id = ?;", session["user_id"])

    # Check customer's current balance remaining
    balance = db.execute("SELECT cash FROM users WHERE id = ?;", session["user_id"])[0]["cash"]


    if request.method == "POST":
        sell_shares = request.form.get("shares")
        sell_symbol = request.form.get("symbols")

        if not sell_symbol:
            return apology("Please select the stock", 403)

        elif not sell_shares:
            return apology("Please enter share amount", 403)

        # Look up the current price of the selected stock
        sell_price = lookup(sell_symbol).get("price")
        current_time = local_time = time.ctime(time.time())

        # Retrieve number of shares of this stock in user's account from database
        current_share = db.execute("SELECT share FROM buy_sell WHERE symbol = ? AND buy_sell_id = ?;", sell_symbol, session["user_id"])[0]["share"]

        # Check if user input numer of share # TODO
        # Check if share is vaild input # TODO

        # Check if number of share user trying to sell is greater than what user's currently holding
        if int(sell_shares) > int(current_share):
            return apology("Short selling is too risky my friend", 403 )
        else:
            # Update new balance after user sold the share currently owned
            sell_cost = int(sell_shares) * sell_price
            new_cash = balance + sell_cost
            update_balance = db.execute("UPDATE users SET cash = ? WHERE id = ?;",new_cash,session["user_id"])

            # Update share amount after user sold the share
            min_share = int(current_share) - int(sell_shares)
            update_share = db.execute("UPDATE buy_sell SET share = ? WHERE symbol = ? AND buy_sell_id = ?;", min_share, sell_symbol, session["user_id"])

            sell_share = int(sell_shares) * -1
            txn_record = db.execute("INSERT INTO txn_history (price,purchase_cost,share,symbol,txn_id,time) VALUES(?, ?, ?, ?, ?, ?) ;",sell_price,sell_cost,sell_share,sell_symbol,session["user_id"],current_time)

            # Check if the current stock's number of share is zero, if yes then clear data of this stock data from database
            lastest_share = db.execute("SELECT share FROM buy_sell WHERE symbol = ? AND buy_sell_id = ?;", sell_symbol, session["user_id"])[0]["share"]
            if lastest_share == 0:
                clear = db.execute("DELETE FROM buy_sell WHERE symbol = ? AND buy_sell_id = ?;", sell_symbol, session["user_id"])

        

        return redirect('/')
    else:
        return render_template("sell.html",symbols = symbols,Title = "You can sell your shares here")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

@app.route("/add_fund", methods=["GET", "POST"])
@login_required
def add_fund():
    balance = db.execute("SELECT cash from users WHERE id =?;",session["user_id"])[0]["cash"]
    if request.method == "POST":
        new_cash = request.form.get("amount")
        if not new_cash:
            return apology("Please enter amount you want to deposit", 403)
        new_deposit = float(new_cash) + float(balance)
        db.execute("UPDATE users SET cash = ? WHERE id = ?;",new_deposit,session["user_id"])
        return redirect("/")
    else:
        return render_template("add_fund.html",Title="Add fund to your account")

@app.route("/min_fund", methods=["GET", "POST"])
@login_required
def min_fund():
    balance = db.execute("SELECT cash from users WHERE id =?;",session["user_id"])[0]["cash"]
    if request.method == "POST":
        new_cash = request.form.get("amount")
        if not new_cash:
            return apology("Please enter amount you want to withdraw", 403)
        elif int(new_cash) > balance:
            return apology("You can not withdraw more than you have", 403)
        new_deposit = float(balance) - float(new_cash)
        db.execute("UPDATE users SET cash = ? WHERE id = ?;",new_deposit,session["user_id"])
        return redirect("/")
    else:
        return render_template("min_fund.html",Title="Add fund to your account")

@app.route("/setting",methods=["GET","POST"])
@login_required
def setting():
    if request.method == "POST":
        # Check Old password
        old_password = request.form.get("old_password")
        old_password_db = db.execute("SELECT hash FROM users WHERE id = ?;",session["user_id"])[0]["hash"]
        check_password = check_password_hash(old_password_db,old_password)
        if check_password is True:
            new_password = request.form.get("password")
            new_password_check = request.form.get("password_check")
            if new_password == new_password_check:
                new_password_hashed = generate_password_hash(new_password)
                db.execute("UPDATE users SET hash = ? WHERE id = ?;",new_password_hashed,session["user_id"] )
                print("changed")
        print(check_password)
        return redirect("/")
    else:
        return render_template("setting.html",Title="Change Password")

if __name__=="__main__":
    app.run(debug=True)