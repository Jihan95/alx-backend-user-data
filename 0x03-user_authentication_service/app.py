#!/usr/bin/env python3
"""
Basic Flask app
"""
from auth import Auth
from flask import Flask, jsonify, request, abort, make_response, redirect

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


@app.route("/sessions", methods=['POST'])
def login():
    """
    sessions route
    """
    email = request.form.get('email')
    password = request.form.get('password')
    if not AUTH.valid_login(email, password):
        abort(401)
    session_id = AUTH.create_session(email)
    response = make_response(jsonify({
        "email": f"{email}", "message": "logged in"
        }))
    response.set_cookie('session_id', session_id, httponly=True)
    return response


@app.route("/sessions", methods=['DELETE'])
def logout():
    """
    logout
    """
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session)
    if user is None:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect('/')


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
