FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --gid 10001 app && useradd --uid 10001 --gid 10001 --create-home app

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY scripts ./scripts
COPY contracts ./contracts

RUN pip install --upgrade pip && pip install .

USER 10001

EXPOSE 8080

CMD ["python", "scripts/run_api.py"]
