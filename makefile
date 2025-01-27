.PHONY: requirement
requirement:
	poetry export -f requirements.txt --without-hashes --output requirements.txt

.PHONY: generate_users
generate_users:
	poetry run keycloak_manager.py generate --count 10 --output users.csv

.PHONY: create_users
create_users:
	poetry run keycloak_manager.py create --csv users.csv --stage dev

.PHONY: delete_users
delete_users:
	poetry run keycloak_manager.py delete --csv users.csv --stage dev

.PHONY: generate_secrets
generate_secrets:
	poetry run manage_secrets.py generate --users-csv users.csv --output-csv secrets.csv --count 15

.PHONY: backup_secrets
backup_secrets:
	poetry run manage_secrets.py backup --csv secrets.csv --stage dev --local

.PHONY: restore_secrets
restore_secrets:
	poetry run manage_secrets.py restore --csv secrets.csv --stage dev --local