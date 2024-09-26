#!/usr/bin/env python3
"""
Basic Flask app
"""
from auth import Auth
from flask import Flask, jsonify, request

AUTH = Auth()

app = Flask(__name__)


@app.route("/", methods=['GET'])
def Bienvenue():
    """ main route """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=['POST'])
def users():
    """
    register route
    """
    email = request.form.get('email')
    password = request.form.get('password')
    try:
        AUTH.register_user(email, password)
        return jsonify({"email": f"{email}", "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
