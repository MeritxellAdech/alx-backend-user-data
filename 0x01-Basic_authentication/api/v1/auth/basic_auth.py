#!/usr/bin/env python3
""" Basic authentication module for API """

from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """Basic authentication
    Inheritance:
        - from Auth"""

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """Extract base64 type of authorization header
        Parameters:
            - authorization_header: str
                The header of the authorization
        Return:
            - the Base64 part of the authorization header
            - None if the header is None"""
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith('Basic '):
            return None
        else:
            return authorization_header.replace('Basic ', '')
