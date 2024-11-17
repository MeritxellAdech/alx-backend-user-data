#!/usr/bin/env python3
""" Authentication module for API """

from flask import request
from typing import List, TypeVar


class Auth:
    """Authentication system template"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Check the need for authorization
        Return:
            - Path if there is the need
            - False if not"""
        return False

    def authorization_header(self, request=None) -> str:
        """Check the access level
        Return:
            - None if request is empty
            - Flask request object"""
        return None

    def current_user(self, request=None) -> TypeVar("User"):
        """Check who is the current user
        Return:
            - None if request is empty
            - FLask request object"""
        return None
