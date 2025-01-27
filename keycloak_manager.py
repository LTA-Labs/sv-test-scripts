#!/usr/bin/env python3

import argparse
import asyncio
import csv
import httpx
import os
import random
import string
from dataclasses import dataclass, asdict
from datetime import datetime
from dotenv import load_dotenv
from typing import List, Tuple

from config import DEFAULT_STAGE, DEFAULT_EMAIL_TEST_DOMAIN, logger, ServerData, STAGES
from sv_oidc_auth import OIDCAuth
from utils import validate_username

load_dotenv()


# Default values from environment variables
DEFAULT_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID')
DEFAULT_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET')


@dataclass
class AccessToken:
    access_token: str
    token_type: str
    expires_in: int
    issue_at: float

    def is_valid(self):
        now = datetime.now().timestamp()
        return now < self.issue_at + self.expires_in

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class KcUser:
    id: str
    username: str
    email: str


class KcAdmin:

    def __init__(self, client_id: str, client_secret: str, stage: str = DEFAULT_STAGE):
        server_data: ServerData = STAGES.get(stage)
        if server_data is None:
            raise ValueError(f"Stage value '{stage}' is not valid")
        self.stage = stage
        self.base_url = server_data.kc_url
        self.api_url = server_data.api_url
        self.realm = server_data.realm
        self._client_id = client_id
        self._client_secret = client_secret
        self._client = httpx.AsyncClient()
        self._client.headers.update({"Content-Type": "application/json"})
        self._get_token()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self._client.aclose()

    async def get_users(self, page: int = 0, page_size: int = 100):
        return await self._get(
            f"{self.base_url}/admin/realms/{self.realm}/users?first={page}&max={page_size}"
        )

    async def get_user(self, user_id):
        return await self._get(f"{self.base_url}/admin/realms/{self.realm}/users/{user_id}")

    async def create_user(self, username: str, password: str, email: str = None, set_free_license: bool = False) -> bool:
        try:
            email = validate_username(email) or validate_username(username)
            if email is None:
                raise ValueError("Username is not valid")
            username = validate_username(username, check_sv_prefix=True)
            response = await self._post(
                f"{self.base_url}/admin/realms/{self.realm}/users",
                json={
                    "username": username,
                    "email": email,
                    "emailVerified": True,
                    "enabled": True,
                    "credentials": [{
                        "type": "password",
                        "value": password,
                        "temporary": False
                    }]
                }
            )
            response.raise_for_status()
            logger.info(f"User created successfully: {username}")

            if set_free_license:
                auth = OIDCAuth(self.stage)
                auth_info = await auth.kc_authenticate(username, password)
                if auth_info:
                    logger.info(f"=== {username}: Keycloak authentication successful! ===")
                    sv_token = await auth.sv_authenticate(auth_info.get('access_token'))
                    if sv_token:
                        logger.info(f"=== {username}: SV authentication successful! ===")
                        response = await self._client.post(
                            url=f"{self.api_url}/license/select_license",
                            json={
                                "license_id": "portal_lite" + ("" if self.stage == 'pre' else "-nWqbR"),
                                "is_yearly": False,
                                "lang": "en",
                                "coupon": ""
                            },
                            headers={
                                "Authorization": f"Bearer {sv_token}",
                                "Content-Type": "application/json"
                            }
                        )
                        try:
                            response.raise_for_status()
                            logger.info(f"=== {username}: Free license assigned successfully! ===")
                        except httpx.HTTPError as e:
                            logger.error(f"Failed to assign free license to {username}: {str(e)}")
                    else:
                        logger.error(f"=== {username}: SV authentication failed! ===")
                else:
                    logger.error(f"=== {username}: Keycloak authentication failed! ===")

            return True
        except httpx.HTTPError as e:
            logger.error(f"Failed to create user {username}: {str(e)}")
            return False

    async def delete_user(self, username: str) -> bool:
        try:
            # First, find the user
            username = validate_username(username, check_sv_prefix=True)
            users = await self.get_users(page_size=1000)
            user = next((u for u in users if u["username"] == username), None)

            if not user:
                logger.warning(f"User not found: {username}")
                return False

            await self._delete(f"{self.base_url}/admin/realms/{self.realm}/users/{user['id']}")
            logger.info(f"User deleted successfully: {username}")
            return True
        except httpx.HTTPError as e:
            logger.error(f"Failed to delete user {username}: {str(e)}")
            return False

    def _get_token(self):
        try:
            response: httpx.Response = httpx.post(
                f"{self.base_url}/realms/master/protocol/openid-connect/token",
                data={
                    "scope": "openid",
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            now = datetime.now().timestamp()
            json_data = response.json()

            token = AccessToken(
                access_token=json_data["access_token"],
                token_type=json_data["token_type"],
                expires_in=json_data["expires_in"],
                issue_at=now,
            )
            self._token = token
            self._client.headers.update(
                {"Authorization": f"{token.token_type} {token.access_token}"}
            )
        except httpx.HTTPError as e:
            logger.error(f"Failed to get admin token: {str(e)}")
            raise e

    async def _get(self, url, as_json=True):
        if not self._token.is_valid():
            self._get_token()

        if as_json:
            result = await self._client.get(url)
            return result.json()

        return await self._client.get(url)

    async def _post(self, url, **kwargs):
        if not self._token.is_valid():
            self._get_token()
        return await self._client.post(url, **kwargs)

    async def _delete(self, url):
        if not self._token.is_valid():
            self._get_token()
        return await self._client.delete(url)


async def process_users(action: str, csv_file: str, client_id: str,
                        client_secret: str, set_free_license: bool, stage: str):
    async with KcAdmin(client_id, client_secret, stage) as admin:
        with open(csv_file, 'r') as f:
            reader = csv.reader(f, delimiter=';')
            users = list(reader)

        results = {
            "success": 0,
            "failed": 0,
            "total": len(users)
        }

        # Process users in parallel with a concurrency limit
        batch_size = 5
        for i in range(0, len(users), batch_size):
            batch = users[i:i + batch_size]
            tasks = []
            for username, password in batch:
                if action == "create":
                    task = admin.create_user(username, password, set_free_license=set_free_license)
                else:
                    task = admin.delete_user(username)
                tasks.append(task)

            results_batch = await asyncio.gather(*tasks)
            results["success"] += sum(1 for r in results_batch if r)
            results["failed"] += sum(1 for r in results_batch if not r)

            logger.info(f"Progress: {i + len(batch)}/{len(users)}")

        logger.info(f"Operation completed: {results}")


def generate_users(count: int, prefix: str = "user", password_length: int = 8) -> List[Tuple[str, str]]:
    if password_length < 8:
        raise ValueError("Password length must be at least 8 characters")

    users = []
    for i in range(1, count + 1):
        username = f"{prefix}{i}{DEFAULT_EMAIL_TEST_DOMAIN}"

        # Ensure password contains at least one capital letter, one digit, and one special character
        uppercase = random.choice(string.ascii_uppercase)
        digit = random.choice(string.digits)
        special = random.choice("!@#$%^&*()-_=+.")

        # Fill the rest of the password with random characters
        remaining_length = password_length - 3
        other_chars = ''.join(random.choices(
            string.ascii_letters + string.digits + "!@#$%^&*()-_=+.",
            k=remaining_length
        ))

        # Combine all parts and shuffle to randomize
        password = list(uppercase + digit + special + other_chars)
        random.shuffle(password)
        password = ''.join(password)

        users.append((username, password))

    return users


def main():
    parser = argparse.ArgumentParser(description="Keycloak User Management CLI")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Create command
    create_parser = subparsers.add_parser("create", help="Create users from CSV file")
    create_parser.add_argument("--csv", required=True, help="CSV file with username;password")
    create_parser.add_argument("--client-id", default=DEFAULT_CLIENT_ID, help=f"Client ID")
    create_parser.add_argument("--client-secret", default=DEFAULT_CLIENT_SECRET, help="Client Secret")
    create_parser.add_argument("--not-free-license", action='store_true',
                               help="Don't automatically set the free license to this user")
    create_parser.add_argument('--stage', type=str, default=DEFAULT_STAGE,
                               help='Stage to be managed', choices=['dev', 'test', 'pre'])

    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete users from CSV file")
    delete_parser.add_argument("--csv", required=True, help="CSV file with username;password")
    delete_parser.add_argument("--client-id", default=DEFAULT_CLIENT_ID, help=f"Client ID")
    delete_parser.add_argument("--client-secret", default=DEFAULT_CLIENT_SECRET, help="Client Secret")
    delete_parser.add_argument('--stage', type=str, default=DEFAULT_STAGE,
                               help='Stage to be managed', choices=['dev', 'test', 'pre'])

    # Generate command
    generate_parser = subparsers.add_parser("generate", help="Generate CSV file with random users")
    generate_parser.add_argument("--count", type=int, required=True, help="Number of users to generate")
    generate_parser.add_argument("--output", required=True, help="Output CSV file")
    generate_parser.add_argument("--prefix", default="user_", help="Username prefix")

    args = parser.parse_args()

    if args.command in ("create", "delete"):
        if not (args.client_id and args.client_secret):
            logger.error("Please specify all required params via CLI or environment variable")
            parser.print_help()
            return

        asyncio.run(process_users(
            args.command,
            args.csv,
            args.client_id,
            args.client_secret,
            not getattr(args, 'not_free_license', False),
            args.stage
        ))
    elif args.command == "generate":
        users = generate_users(args.count, args.prefix)
        with open(args.output, 'w', newline='') as f:
            writer = csv.writer(f, delimiter=';')
            writer.writerows(users)
        logger.info(f"Generated {args.count} users in {args.output}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
