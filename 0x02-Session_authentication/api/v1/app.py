#!/usr/bin/env python3
"""
Route module for the API
"""
from os import getenv
from api.v1.views import app_views
from flask import Flask, jsonify, abort, request
from flask_cors import (CORS, cross_origin)
from api.v1.auth.session_auth import SessionAuth
import os


app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})
auth = None
env_value = os.getenv("AUTH_TYPE")
if env_value == "auth":
    from api.v1.auth.auth import Auth
    auth = Auth()

if env_value == "basic_auth":
    from api.v1.auth.basic_auth import BasicAuth
    auth = BasicAuth()

if env_value == "session_auth":
    auth = SessionAuth()


@app.errorhandler(404)
def not_found(error) -> str:
    """ Not found handler
    """
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(401)
def unauthorized(error) -> str:
    """ Unauthorized handler
    """
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden(error) -> str:
    """ Forbidden handler
    """
    return jsonify({"error": "Forbidden"}), 403


@app.before_request
def check_auth():
    """
    method to check authentication before request
    """
    if auth is not None:
        ex = [
                '/api/v1/status/',
                '/api/v1/unauthorized/',
                '/api/v1/forbidden/',
                '/api/v1/auth_session/login/'
                ]
        if not auth.require_auth(request.path, ex):
            return
        is_auth = auth.authorization_header(request)
        has_cookie = auth.session_cookie(request)
        if is_auth is None and has_cookie is None:
            abort(401)
        if auth.current_user(request) is None:
            abort(403)
        request.current_user = auth.current_user(request)


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
