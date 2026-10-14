# One image for every Python service (web, migrate, tests; later receiver/parser/poller/reporter).
FROM python:3.12.15-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TZ=UTC \
    PYTHONPATH=/srv

WORKDIR /srv
COPY requirements.txt requirements-dev.txt ./
RUN pip install -r requirements.txt -r requirements-dev.txt

# libcap2-bin: lets the non-root receiver bind syslog port 514 (only this one capability is granted).
# Pango + fonts: WeasyPrint PDF rendering for reports.
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
      libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/* \
 && setcap cap_net_bind_service=+ep "$(readlink -f /usr/local/bin/python3)"

COPY alembic.ini pyproject.toml ./
COPY app ./app
COPY services ./services
COPY tests ./tests
COPY samples ./samples

RUN useradd --system --uid 10001 --home /srv uniwatch && chown -R uniwatch /srv
USER uniwatch
