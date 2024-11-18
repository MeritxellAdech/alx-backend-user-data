#!/usr/bin/env python3
""" Basic authentication module for API """

import base64
from api.v1.auth.auth import Auth
from base64 import decode
from typing import TypeVar


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
        if not authorization_header.startswith("Basic "):
            return None
        else:
            return authorization_header.replace("Basic ", "")

    def decode_base64_authorization_header(
        self, base64_authorization_header: str
    ) -> str:
        """Decode base64 string to its utf-8 string representation
        Parameters:
            - base64_authorization_header: str
                Authorization header
        Returns:
            - the decoded value of a Base64 string"""
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            # Decode the Base64 string to bytes
            decoded_bytes = base64.b64decode(base64_authorization_header)
            # Convert bytes to a UTF-8 string
            return decoded_bytes.decode("utf-8")
        except Exception:
            # Return None if decoding fails
            return None

    def extract_user_credentials(
        self, decoded_base64_authorization_header: str
    ) -> (str, str):
        """Extracts user email and password from a decoded Base64 string.

        Args:
            decoded_base64_authorization_header:str
                - The decoded Base64 string.

        Returns:
            - tuple: (user_email, user_password)
            - (None, None) if invalid."""
        if decoded_base64_authorization_header is None:
            return (None, None)
        if not isinstance(decoded_base64_authorization_header, str):
            return (None, None)
        if ":" not in decoded_base64_authorization_header:
            return (None, None)
        return tuple(decoded_base64_authorization_header.split(":"))

    def user_object_from_credentials(
        self, user_email: str, user_pwd: str
    ) -> TypeVar("User"):
        """Retrieves a User instance based on email and password.

        Args:
            user_email (str):
                - The user's email address.
                - user_pwd (str): The user's password.

        Returns:
            - The User instance
            - None if credentials are invalid."""
        if not isinstance(user_email, str) or user_email is None:
            return None
        if not isinstance(user_pwd, str) or user_pwd is None:
            return None

        #
        from models.user import User

        # Verify that email match
        user = User.search({"email": user_email})
        # User not found
        if not user or len(user) == 0:
            return None

        # Get the first found user
        found_user = user[0]

        # Verify the user password is valid
        if not found_user.is_valid_password(user_pwd):
            return None

        return found_user
