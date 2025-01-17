# Keycloak and Secret Management Tool

This project provides tools to manage users in Keycloak and handle the creation, backup, and restoration of secrets. The utilities are written in Python and are command-line driven.

---

## Table of Contents

- [Keycloak Management](#keycloak-management)
  - [Generating Users](#generating-users)
  - [Creating Users on the Server](#creating-users-on-the-server)
  - [Deleting Users on the Server](#deleting-users-on-the-server)
  - [Using Defaults from `.env`](#using-defaults-from-env)
  - [Overriding Specific Values](#overriding-specific-values)
- [Secret Management](#secret-management)
  - [Generating a Sample CSV](#generating-a-sample-csv)
  - [Backing Up Secrets](#backing-up-secrets)
  - [Restoring Secrets](#restoring-secrets)
- [Getting Help](#getting-help)

---

## Keycloak Management

### Generating Users
Use the following command to generate user data and save it to a CSV file:

```bash
python keycloak_manager.py generate --count 50 --output users.csv
```

- `--count`: Number of users to generate.
- `--output`: Path to the output CSV file where user data will be saved.

### Creating Users on the Server
Create users in a Keycloak server using the previously generated CSV file:

```bash
python keycloak_manager.py create --csv users.csv --realm myrealm --client-id myclient --client-secret mysecret
```

- `--csv`: Path to the CSV file containing user data.
- `--realm`: The Keycloak realm where users will be created.
- `--client-id`: The Keycloak client ID for authentication.
- `--client-secret`: The Keycloak client secret for authentication.

### Deleting Users on the Server
Delete users from a Keycloak server using a CSV file:

```bash
python keycloak_manager.py delete --csv users.csv --realm myrealm --client-id myclient --client-secret mysecret
```

### Using Defaults from `.env`
To simplify command usage, you can specify default values (e.g., `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET`) in a `.env` file. Then, use the following command:

```bash
python keycloak_manager.py create --csv users.csv
```

This will use the default values specified in the `.env` file.

### Overriding Specific Values
You can override individual values while still using defaults for others:

```bash
python keycloak_manager.py create --csv users.csv --realm custom-realm
```

---

## Secret Management

### Generating a Sample CSV
Generate a sample CSV file with placeholder secrets for testing or demonstration purposes:

```bash
python manage_secrets.py generate --csv secrets.csv --num-records 5
```

- `--csv`: Path to the output CSV file.
- `--num-records`: Number of records to generate.

### Backing Up Secrets
Backup existing secrets to a specified environment (e.g., production):

```bash
python manage_secrets.py backup --csv secrets.csv --stage prod
```

- `--csv`: Path to the CSV file where secrets will be stored.
- `--stage`: Target environment (e.g., `prod`, `dev`).

### Restoring Secrets
Restore secrets to a specified environment:

```bash
python manage_secrets.py restore --csv secrets.csv --stage prod
```

- `--csv`: Path to the CSV file containing the secrets.
- `--stage`: Target environment (e.g., `prod`, `dev`).

---

## Getting Help

Each script (`keycloak_manager.py` and `manage_secrets.py`) and its subcommands include a `--help` option to provide detailed usage instructions. For example:

```bash
python keycloak_manager.py --help
```

or

```bash
python manage_secrets.py backup --help
```

Use these commands to explore all available options and learn more about specific functionalities.

