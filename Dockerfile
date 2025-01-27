FROM python:3.11-slim

WORKDIR /app

COPY ./requirements.txt /code/requirements.txt

RUN python -m pip install --no-cache-dir --upgrade pip

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

COPY . /app

RUN chmod +x keycloak_manager.py manage_secrets.py

ENTRYPOINT ["python"]