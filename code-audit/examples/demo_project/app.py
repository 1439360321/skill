from flask import Flask, request
import pickle
import os

app = Flask(__name__)


@app.route("/pickle", methods=["POST"])
def handle_pickle():
    data = request.get_data()
    obj = pickle.loads(data)  # CWE-502
    return str(obj)


@app.route("/cmd", methods=["GET"])
def run_cmd():
    cmd = request.args.get("cmd", "")
    os.system(cmd)  # CWE-78
    return "done"


@app.route("/safe", methods=["GET"])
def safe_endpoint():
    name = request.args.get("name", "world")
    return f"Hello, {name[:50]}!"  # Safe: bounded


if __name__ == "__main__":
    app.run(debug=True)
