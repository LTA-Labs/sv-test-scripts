import csv
import random
from pathlib import Path
from typing import Dict
from sv_secret_manager import SecretVaultManager, Secret
from config import logger, logging_file, default_environment


def validate_file_path(file_path: str) -> bool:
    path = Path(file_path)
    if not path.exists():
        logger.error(f"File not found: {file_path}")
        return False
    return True


def process_csv_record(record: Dict[str, str], stage: str, operation: str) -> bool:
    """Process a single CSV record for secret backup or restore."""
    try:
        # Validate required fields
        required_fields = ['username', 'password', 'secret_type', 'secret', 'secret_desc', 'keepic']
        for field in required_fields:
            if not record.get(field):
                logger.error(f"Missing required field: {field}")
                return False

        # Validate files exist for file/image type secrets and keepic
        if record['secret_type'] == 'file':
            if not validate_file_path(record['secret']):
                return False

        if not validate_file_path(record['keepic']):
            return False

        # Create secret submission object
        secret = Secret(
            name=record['secret_desc'],
            type=record['secret_type'],
            tag='',
            content=record['secret'],
            keepic_path=record['keepic']
        )

        # Process secret using the manager
        with SecretVaultManager(stage=stage, headless=False) as manager:
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


def process_secrets_file(csv_file: str, stage: str, operation: str) -> Dict[str, int]:
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

                if process_csv_record(record, stage, operation):
                    results["success"] += 1
                else:
                    results["failed"] += 1

                logger.info(f"Progress: {results['success']}/{results['total']} successful")

    except Exception as e:
        logger.error(f"Error processing CSV file: {str(e)}")

    return results


def generate_sample_csv(output_file: str, num_records: int = 5):
    """Generate a sample CSV file with the required format."""
    try:
        headers = ['username', 'password', 'secret_type', 'secret', 'secret_desc', 'keepic']

        # Create a sample file for file-type secrets if it doesn't exist
        sample_file = Path('sample_secret.txt')
        if not sample_file.exists():
            sample_file.write_text('This is a sample file secret')

        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f, delimiter=';')
            writer.writerow(headers)

            # Generate sample records
            for i in range(num_records):
                # Randomly choose secret type
                secret_type = random.choice(['text', 'file'])

                # Generate secret content based on type
                if secret_type == 'text':
                    secret_content = f'This is secret #{i + 1}'
                else:
                    secret_content = str(sample_file)

                writer.writerow([
                    f'user{i + 1}',  # username
                    f'password{i + 1}',  # password
                    secret_type,  # secret_type
                    secret_content,  # secret
                    f'Sample Secret {i + 1}',  # secret_desc
                    './keepic.jpg'  # keepic
                ])

        logger.info(f"Generated sample CSV file: {output_file}")

    except Exception as e:
        logger.error(f"Error generating sample CSV: {str(e)}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Secret Vault Manager Tool')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Generate command
    generate_parser = subparsers.add_parser('generate', help='Generate a sample CSV file')
    generate_parser.add_argument('--csv', required=True, help='Path to output CSV file')
    generate_parser.add_argument('--num-records', type=int, default=5,
                                 help='Number of records to generate')

    # Common arguments for backup and restore commands
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument('--csv', required=True, help='Path to CSV file with secret data')
    common_parser.add_argument('--stage', type=str, default=default_environment,
                               help='Stage to be tested', choices=['dev', 'test', 'prod'])

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
        generate_sample_csv(args.csv, args.num_records)
        return

    logger.info(f"Starting secret {args.command} process")
    results = process_secrets_file(args.csv, args.stage, args.command)

    logger.info("=== Final Results ===")
    logger.info(f"Total records processed: {results['total']}")
    logger.info(f"Successful {args.command}s: {results['success']}")
    logger.info(f"Failed {args.command}s: {results['failed']}")
    logger.info(f"Complete logs available in: {logging_file}")


if __name__ == "__main__":
    main()
