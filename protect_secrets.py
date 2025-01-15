import csv
from pathlib import Path
from typing import Dict
from sv_secret_submitter import SecretVaultSubmitter, SecretSubmission
from config import logger, logging_file


def validate_file_path(file_path: str) -> bool:
    path = Path(file_path)
    if not path.exists():
        logger.error(f"File not found: {file_path}")
        return False
    return True


def process_csv_record(record: Dict[str, str], stage: str) -> bool:
    """Process a single CSV record for secret protection."""
    try:
        # Validate required fields
        required_fields = ['username', 'password', 'secret_type', 'secret', 'secret_desc', 'keepic']
        for field in required_fields:
            if not record.get(field):
                logger.error(f"Missing required field: {field}")
                return False

        # Validate files exist for file/image type secrets and keepic
        if record['secret_type'] in ['file', 'image']:
            if not validate_file_path(record['secret']):
                return False

        if not validate_file_path(record['keepic']):
            return False

        # Create secret submission object
        secret = SecretSubmission(
            name=record['secret_desc'],
            type=record['secret_type'],
            tag='',
            text=record['secret'] if record['secret_type'] == 'text' else '',
            keepic_path=record['keepic']
        )

        # Submit secret using the submitter
        with SecretVaultSubmitter(stage=stage, headless=False) as submitter:
            logger.info(f"Attempting to protect secret for user: {record['username']}")

            # Authenticate
            if not submitter.authenticate(username=record['username'], password=record['password']):
                logger.error(f"Authentication failed for user: {record['username']}")
                return False

            # Submit secret
            if submitter.submit_secret(secret):
                logger.info(f"Successfully protected secret for user: {record['username']}")
                return True
            else:
                logger.error(f"Failed to protect secret for user: {record['username']}")
                return False

    except Exception as e:
        logger.error(f"Error processing record for user {record['username']}: {str(e)}")
        return False


def process_secrets_file(csv_file: str, stage: str) -> Dict[str, int]:
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

                if process_csv_record(record, stage):
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

        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f, delimiter=';')
            writer.writerow(headers)

            # Generate sample records
            for i in range(num_records):
                writer.writerow([
                    f'user{i + 1}',  # username
                    f'password{i + 1}',  # password
                    'text',  # secret_type
                    f'This is secret #{i + 1}',  # secret
                    f'Sample Secret {i + 1}',  # secret_desc
                    f'./keepic.jpg'  # keepic
                ])

        logger.info(f"Generated sample CSV file: {output_file}")

    except Exception as e:
        logger.error(f"Error generating sample CSV: {str(e)}")


def main(stage: str):
    import argparse

    parser = argparse.ArgumentParser(description='Secret Protection Tool')
    parser.add_argument('--csv', required=True, help='Path to CSV file with secret data')
    parser.add_argument('--generate-sample', action='store_true',
                        help='Generate a sample CSV file')
    parser.add_argument('--num-records', type=int, default=1,
                        help='Number of records for sample generation')

    args = parser.parse_args()

    if args.generate_sample:
        generate_sample_csv(args.csv, args.num_records)
        return

    logger.info("Starting secret protection process")
    results = process_secrets_file(args.csv, stage)

    logger.info("=== Final Results ===")
    logger.info(f"Total records processed: {results['total']}")
    logger.info(f"Successful protections: {results['success']}")
    logger.info(f"Failed protections: {results['failed']}")
    logger.info(f"Complete logs available in: {logging_file}")


if __name__ == "__main__":
    stage = 'prod'
    main(stage)
