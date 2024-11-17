#!/usr/bin/env python3
""" Authentication module for API """

from flask import request
from typing import List, TypeVar


class Auth:
    """Authentication system template"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Check the need for authorization
        Return:
            - True if :path: is not in list of :excluded_paths:
            - False if :path: is in list of :excluded_paths:"""
        if path is None or excluded_paths is None or excluded_paths == []:
            return True
        accepted_path = path if path.endswith('/') else path + '/'
        return False if accepted_path in excluded_paths else True

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
