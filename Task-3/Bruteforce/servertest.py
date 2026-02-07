from flask import Flask, request

app = Flask(__name__)

@app.route("/", methods=["GET"])
def home():
    return '<a href="/login">Go to login page</a>'

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        pwd = request.form.get("password")

        if pwd == "admin123":
            return "Login success"

        return "Invalid password", 401

    return """
    <h2>Login Page</h2>
    <form method="post">
        Username: <input name="username"><br>
        Password: <input name="password" type="password"><br>
        <input type="submit">
    </form>
    """

if __name__ == "__main__":
    app.run(debug=True)
