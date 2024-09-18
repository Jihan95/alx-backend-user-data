#!/usr/bin/env python3
"""
Authentication class
"""
from flask import request  # type: ignore
from typing import List, TypeVar, Union
User = TypeVar('User')


class Auth:
    """
    This class is the template for all authentication system
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        paths that requires authentication
        """
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        stripped_path = path.rstrip('/')
        for excluded in excluded_paths:
            stripped_excluded = excluded.rstrip('/')
            if stripped_excluded.endswith('*'):
                if stripped_path.startswith(stripped_excluded[:-1]):
                    return False
            elif stripped_path == stripped_excluded:
                return False
        return True

    def authorization_header(self, request=None) -> Union[str, None]:
        """
        authorization header
        """
        if request is None or 'Authorization' not in request.headers:
            return None
        return request.headers['Authorization']

    def current_user(self, request=None) -> Union[User, None]:
        """
        current user
        """
        return None
