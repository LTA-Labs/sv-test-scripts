FROM python:3.11-slim

WORKDIR /app

COPY . /app

RUN pip install poetry

RUN poetry install --no-root

RUN chmod +x keycloak_manager.py manage_secrets.py

ENTRYPOINT ["poetry", "run", "python"]