import os
import requests
from functools import wraps
from flask import Flask, request, jsonify
import jwt

from validate import validate_input, scan_output

app = Flask(__name__)

JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is not set.")

JWT_ALGORITHM = "HS256"
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3"


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        token = None
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()

        if not token:
            return jsonify({"error": "Missing or invalid token."}), 401

        try:
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token."}), 401

        return f(*args, **kwargs)
    return decorated


@app.route("/chat", methods=["POST"])
@token_required
def chat():
    data = request.get_json(silent=True) or {}
    user_input = data.get("message", "")

    valid, error_msg = validate_input(user_input)
    if not valid:
        return jsonify({"error": error_msg}), 400

    try:
        resp = requests.post(
            OLLAMA_URL,
            json={"model": OLLAMA_MODEL, "prompt": user_input, "stream": False},
            timeout=60,
        )
        resp.raise_for_status()
        model_output = resp.json().get("response", "")
    except requests.RequestException as e:
        return jsonify({"error": f"Model request failed: {str(e)}"}), 502

    safe, scan_error = scan_output(model_output)
    if not safe:
        return jsonify({"error": "Response blocked by output scanner."}), 400

    return jsonify({"response": model_output}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)  # nosec B104 - intentional bind for containerized deployment
