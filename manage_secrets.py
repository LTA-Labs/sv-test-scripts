#!/usr/bin/env python3

import csv
import random
from pathlib import Path
from typing import Dict
from sv_secret_manager import SecretVaultManager, Secret
from config import DEFAULT_STAGE, logger, logging_file, REMOTES_FILES_URL
from utils import generate_users


def validate_file_path(file_path: str) -> bool:
    path = Path(file_path)
    if not path.exists():
        logger.error(f"File not found: {file_path}")
        return False
    return True


def process_csv_record(record: Dict[str, str], stage: str, operation: str, remote: bool = False) -> bool:
    """Process a single CSV record for secret backup or restore."""
    try:
        # Validate required fields
        required_fields = ['username', 'password', 'secret_type', 'secret', 'secret_desc', 'keepic']
        for field in required_fields:
            if not record.get(field):
                logger.error(f"Missing required field: {field}")
                return False

        # Validate files exist for file/image type secrets and keepic
        # if record['secret_type'] == 'file':
        #     if not validate_file_path(record['secret']):
        #         return False
        #
        # if not validate_file_path(record['keepic']):
        #     return False

        # Create secret submission object
        secret = Secret(
            name=record['secret_desc'],
            type=record['secret_type'],
            tag='',
            content=record['secret'],
            keepic_path=record['keepic']
        )

        # Process secret using the manager
        with SecretVaultManager(stage=stage, remote=remote) as manager:
            logger.info(f"Attempting to {operation} secret for user: {record['username']}")

            # Authenticate
            if not manager.authenticate(username=record['username'], password=record['password']):
                logger.error(f"Authentication failed for user: {record['username']}")
                return False

            # Perform operation
            if operation == 'backup':
                success = manager.backup_secret(secret)
            else:  # restore
                success = manager.restore_secret(secret)

            if success:
                logger.info(f"Successfully {operation}ed secret for user: {record['username']}")
                return True
            else:
                logger.error(f"Failed to {operation} secret for user: {record['username']}")
                return False

    except Exception as e:
        logger.error(f"Error processing record for user {record['username']}: {str(e)}")
        return False


def process_secrets_file(csv_file: str, stage: str, operation: str, remote: bool = False) -> Dict[str, int]:
    """Process all records in the CSV file."""
    results = {
        "total": 0,
        "success": 0,
        "failed": 0
    }

    try:
        with open(csv_file, 'r', newline='') as f:
            reader = csv.DictReader(f, delimiter=';')

            for record in reader:
                results["total"] += 1
                logger.info(f"Processing record {results['total']}")

                if process_csv_record(record, stage, operation, remote):
                    results["success"] += 1
                else:
                    results["failed"] += 1

                logger.info(f"Progress: {results['success']}/{results['total']} successful")

    except Exception as e:
        logger.error(f"Error processing CSV file: {str(e)}")

    return results


def generate_sample_csv(input_file: str, output_file: str, num_records: int = 5):
    """Generate a sample CSV file with the required format using usernames and passwords from an external CSV."""
    try:
        headers = ['username', 'password', 'secret_type', 'secret', 'secret_desc', 'keepic']

        sample_keepic = Path('sample_keepic.jpg')

        if input_file and Path(input_file).is_file():
            # Read the external CSV file to get usernames and passwords
            with open(input_file, 'r', newline='') as f:
                reader = csv.reader(f, delimiter=';')
                user_data = list(reader)
        else:
            user_data = generate_users(num_records)

        if not user_data:
            logger.error("No user data found in the input CSV.")
            return

        with open(output_file, 'w', newline='') as outfile:
            writer = csv.writer(outfile, delimiter=';')
            writer.writerow(headers)

            # Generate sample records using the usernames and passwords from the external CSV
            for i in range(num_records):
                # Use modulo to loop through user_data if num_records > len(user_data)
                user_index = i % len(user_data)
                username, password = user_data[user_index]

                # Randomly choose secret type
                secret_type = random.choice(['text', 'file'])

                # Generate secret content based on type
                if secret_type == 'text':
                    secret_content = f'This is text secret #{i + 1}'
                else:
                    secret_content = random.choice(list(REMOTES_FILES_URL.keys()))

                writer.writerow([
                    username,
                    password,
                    secret_type,
                    secret_content,
                    f'Sample Secret {i + 1}',
                    str(sample_keepic)
                ])

        logger.info(f"Generated sample CSV file: {output_file} with {num_records} records.")

    except Exception as e:
        logger.error(f"Error generating sample CSV: {str(e)}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Secret Vault Manager Tool')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Generate command
    generate_parser = subparsers.add_parser('generate', help='Generate a sample CSV file')
    generate_parser.add_argument('--users-csv', default=None, help='Path to users CSV file')
    generate_parser.add_argument('--output-csv', required=True, help='Path to output CSV file')
    generate_parser.add_argument('--count', type=int, default=5,
                                 help='Number of records to generate')

    # Common arguments for backup and restore commands
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument('--csv', required=True, help='Path to CSV file with secret data')
    common_parser.add_argument('--stage', type=str, default=DEFAULT_STAGE,
                               help='Stage to be tested', choices=['dev', 'test', 'pre'])
    common_parser.add_argument('--local', action='store_true',
                               help='Use local WebDriver instead of remote Selenium Grid')

    # Backup command
    backup_parser = subparsers.add_parser('backup', help='Backup secrets from CSV file',
                                          parents=[common_parser])

    # Restore command
    restore_parser = subparsers.add_parser('restore', help='Restore secrets from CSV file',
                                           parents=[common_parser])

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command == 'generate':
        generate_sample_csv(args.users_csv, args.output_csv, args.count)
        return

    logger.info(f"Starting secret {args.command} process")
    results = process_secrets_file(args.csv, args.stage, args.command, remote=not getattr(args, 'local', False))

    logger.info("=== Final Results ===")
    logger.info(f"Total records processed: {results['total']}")
    logger.info(f"Successful {args.command}s: {results['success']}")
    logger.info(f"Failed {args.command}s: {results['failed']}")
    logger.info(f"Complete logs available in: {logging_file}")


if __name__ == "__main__":
    main()
