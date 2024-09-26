#!/usr/bin/env python3
"""
hash password
"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4
from typing import Union, Optional


def _hash_password(password: str) -> bytes:
    """
         method that takes in a password string arguments and returns bytes.
    """
    password = password.encode('utf-8')
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password, salt)


def _generate_uuid() -> str:
    """
    The function should return a string representation of a new UUID
    """
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
         take mandatory email and password string arguments and return
         a User object.
        """
        try:
            user = self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hashed_pwd = _hash_password(password)
            return self._db.add_user(email, hashed_pwd)

    def valid_login(self, email: str, password: str) -> bool:
        """
        Try locating the user by email. If it exists, check the password
        with bcrypt.checkpw. If it matches return True. In any other case,
        return False
        """
        try:
            user = self._db.find_user_by(email=email)
            password = password.encode('utf-8')
            if bcrypt.checkpw(password, user.hashed_password):
                return True
            return False
        except Exception:
            return False

    def create_session(self, email: str) -> Union[str, None]:
        """
         It takes an email string argument and returns the session ID
        """
        try:
            session_id = _generate_uuid()
            user = self._db.find_user_by(email=email)
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except Exception:
            return None

    def get_user_from_session_id(self, session_id: str) -> User:
        """
        get user by session_id
        """
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """
        destroy session
        """
        try:
            self._db.update_user(user_id, session_id=None)
        except NoResultFound:
            return None

    def get_reset_password_token(self, email: str): -> str:
        """
        Generate reset password token
        """
        try:
            user = self._db.find_user_by(email=email)
            reset_token = _generate_uuid()
            self._db.update_user(user.id, reset_token=reset_token)
            return reset_token
        except NoResultFound:
            raise ValueError
