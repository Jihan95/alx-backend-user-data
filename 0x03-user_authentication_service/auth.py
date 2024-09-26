#!/usr/bin/env python3
"""
hash password
"""
import bcrypt


def _hash_password(password):
    """
         method that takes in a password string arguments and returns bytes.
    """
    password = password.encode('utf-8')
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password, salt)
