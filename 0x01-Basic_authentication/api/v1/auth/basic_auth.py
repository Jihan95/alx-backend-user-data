#!/usr/bin/env python3
"""
Basic auth
"""
from api.v1.auth.auth import Auth
from typing import Union, Tuple
import base64


class BasicAuth(Auth):
    """
    Basic Authentication
    """
    def extract_base64_authorization_header(
            self, authorization_header: str) -> Union[None, str]:
        """
        extract_base64_authorization_header
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header.split(" ", 1)[1].strip()

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> Union[None, str]:
        """
        decode_base64_authorization_header
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> Tuple[
                    Union[None, str], Union[None, str]]:
        """
        Extract user cradentials
        """
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        user_name, password = decoded_base64_authorization_header.split(':')
        return user_name, password
