import json
from flask import request, _request_ctx_stack, abort
from functools import wraps
from jose import jwt
from urllib.request import urlopen
import logging
from logging import FileHandler, Formatter
import sys


AUTH0_DOMAIN = 'coffee-project.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'coffee-shop'
CLIENT_ID = 'DwVmx8VRF8xkaCGjJCgxDGZmFc2oa2ky'


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


'''
Retrieves the headers from the token.
'''


def get_token_auth_header():
    auth_headers = request.headers.get('Authorization', None)

    if not auth_headers:
        raise AuthError("Authorization header is missing", 401)

    auth_parts = auth_headers.split()

    if len(auth_parts) != 2:
        raise AuthError('Malformed header: Should contain 2 parts.', 401)
    elif auth_parts[0].lower() != 'bearer':
        raise AuthError('Malformed header: Must start with "Bearer".', 401)

    return auth_parts[1]


'''
Verifies the permissions provided within the JWT match what the API returned.
'''


def check_permissions(permission, payload):
    if 'permissions' not in payload:
        raise AuthError('Header invalid: No permissions attribute.', 400)

    if permission not in payload['permissions']:
        raise AuthError("Unauthorized to access resource", 401)


'''
Decodes and verifies the JWT with data from the Auth0 API.
'''


def verify_decode_jwt(token):
    json_url = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    json_web_key = json.loads(json_url.read())
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    print(unverified_header, file=sys.stderr)
    if 'kid' not in unverified_header:
        raise AuthError('Header invalid: Key-ID is missing.', 401)

    for key in json_web_key['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
        else:
            raise AuthError("Unauthorized to access this resource.", 401)

    if rsa_key:
        try:
            payload = jwt.decode(token,
                                 rsa_key,
                                 algorithms=ALGORITHMS,
                                 audience=API_AUDIENCE,
                                 issuer=f'https://{AUTH0_DOMAIN}/')
            return payload

        except jwt.ExpiredSignatureError:
            raise AuthError('Token expired: Please log in again.', 401)

        except jwt.JWTClaimsError:
            raise AuthError('Claim error: Detected within JWT', 401)

        except Exception:
            raise AuthError('Invalid header in JWT.', 400)

    raise AuthError('Invalid header: Unable to decode JWT', 400)


def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator
