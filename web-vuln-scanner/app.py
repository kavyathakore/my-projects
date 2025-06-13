from flask import Flask, request, render_template
from scanner import scan_xss_sqli

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    if request.method == "POST":
        url = request.form.get("url")
        results = scan_xss_sqli(url)
    return render_template("index.html", results=results)

if __name__ == "__main__":
    app.run(debug=True)
