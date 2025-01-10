import asyncio
import base64
import hashlib
import httpx
import os
import secrets
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from enum import StrEnum
from typing import Optional
from urllib.parse import urlencode, parse_qs

from sv_test_logger import logger

load_dotenv()


class Stage(StrEnum):
    TEST = 'test'
    DEV = 'dev'


class OIDCAuth:
    def __init__(self, stage: Stage = 'dev'):
        self.sv_base_url = f"https://sv-{stage}.secretsvault.net"
        self.sv_api_url = f"https://wapi-{stage}.secretsvault.net"
        self.kc_auth_url = f"https://auth-{stage}.secretsvault.net"
        self.client_id = "sv-web-portal"
        self.realm = "secret-vault"

        # PKCE and state values
        self.code_verifier = secrets.token_urlsafe(64)
        self.state = secrets.token_urlsafe(32)

    def _create_code_challenge(self) -> str:
        """Create PKCE code challenge from verifier"""
        hash_value = hashlib.sha256(self.code_verifier.encode()).digest()
        return base64.urlsafe_b64encode(hash_value).decode().rstrip('=')

    def _build_auth_params(self, redirect_uri: str) -> dict:
        return {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': 'openid',
            'state': self.state,
            'code_challenge': self._create_code_challenge(),
            'code_challenge_method': 'S256'
        }

    async def kc_authenticate(self) -> Optional[str]:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            try:
                # Build the authentication URL
                redirect_uri = f"{self.sv_base_url}/home"
                auth_params = self._build_auth_params(redirect_uri)
                auth_endpoint = f"{self.kc_auth_url}/realms/{self.realm}/protocol/openid-connect/auth"
                auth_url = f"{auth_endpoint}?{urlencode(auth_params)}"

                # Get login page to obtain
                response = await client.get(auth_url)
                response.raise_for_status()

                logger.info("=== Initial Auth Request ===")
                logger.info(f"Status: {response.status_code}")

                # Extract login url
                soup = BeautifulSoup(response.text, 'html.parser')
                form = soup.find('form', id='kc-form-login')
                if not form:
                    raise Exception("Login form not found")
                login_url = form['action']

                # Add credentials
                login_data = {
                    "username": "sv-" + os.getenv('SV_USERNAME'),  # Adding sv- prefix is mandatory
                    "password": os.getenv('SV_PASSWORD')
                }

                # Submit login form
                logger.info("=== Submitting Login Form ===")
                logger.debug("Login URL: " + login_url)
                response = await client.post(
                    login_url,
                    data=login_data
                )
                logger.info(f"Status: {response.status_code}")

                # Parse the response URL
                url = str(response.url)
                if 'code=' not in url and 'Location' in response.headers:
                    url = response.headers['Location']

                if 'code=' not in url:
                    logger.error(f"No authorization code found in URL: {url}")
                    logger.debug("Response body preview: " + response.text[:500])
                    return None

                # Parse query parameters
                query = parse_qs(url.split('?')[1])
                code = query.get('code', [None])[0]
                returned_state = query.get('state', [None])[0]

                # Verify state parameter
                if not code or returned_state != self.state:
                    logger.error("Invalid state parameter in response")
                    return None

                # Exchange code for token
                token_url = f"{self.kc_auth_url}/realms/{self.realm}/protocol/openid-connect/token"
                token_data = {
                    'grant_type': 'authorization_code',
                    'client_id': self.client_id,
                    'code': code,
                    'redirect_uri': redirect_uri,
                    'code_verifier': self.code_verifier
                }

                logger.info(f"=== Exchanging code for token ===")
                logger.info(f"Code: {code}")
                logger.debug(f"Redirect URI: {redirect_uri}")

                response = await client.post(
                    token_url,
                    data=token_data
                )
                response.raise_for_status()

                tokens = response.json()
                return tokens['access_token']

            except httpx.RequestError as e:
                logger.error(f"Network error: {e}")
                return None
            except httpx.HTTPStatusError as e:
                logger.error(f"HTTP error {e.response.status_code}: {e.response.text}")
                return None
            except Exception as e:
                logger.error(f"Authentication failed: {e}")
                return None

    async def sv_authenticate(self, access_token: str) -> Optional[str]:
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                token_url = f"{self.sv_api_url}/auth/token"  # ?app_vendor_id=lta-hBQnyM5Z3W9KUVRc"
                response = await client.post(
                    token_url,
                    params={'app_vendor_id': 'lta-hBQnyM5Z3W9KUVRc'},
                    json={'token': access_token}
                )
                response.raise_for_status()
                return response.json()['token']
            except httpx.RequestError as e:
                logger.error(f"Network error: {e}")
                return None
            except httpx.HTTPStatusError as e:
                logger.error(f"HTTP error {e.response.status_code}: {e.response.text}")
                return None
            except Exception as e:
                logger.error(f"Authentication failed: {e}")
                return None


async def main():
    auth = OIDCAuth()
    kc_token = await auth.kc_authenticate()
    if kc_token:
        logger.info("=== Keycloak authentication successful! ===")
        logger.info(f"Keycloak access token: {kc_token}")
    else:
        logger.error("=== Keycloak authentication failed! ===")
        return

    sv_token = await auth.sv_authenticate(kc_token)
    if sv_token:
        logger.info("=== SV authentication successful! ===")
        logger.info(f"SV access token: {sv_token}")
    else:
        logger.error("=== Authentication failed! ===")


if __name__ == "__main__":
    asyncio.run(main())
