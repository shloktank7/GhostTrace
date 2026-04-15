from __future__ import annotations

from flask import Flask, jsonify, request, send_from_directory

from ghosttrace.engine import scan_identity


app = Flask(__name__, static_folder="static", static_url_path="")


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


@app.post("/api/scan")
def scan():
    payload = request.get_json(silent=True) or {}
    query = payload.get("query", "")
    hardening = payload.get("hardening", {})
    result = scan_identity(query, hardening)
    return jsonify(result)


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "GhostTrace"})


if __name__ == "__main__":
    app.run(debug=True, port=5001)

