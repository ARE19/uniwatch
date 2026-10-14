# Services

Every Python service runs from the one `uniwatch-app` image (see `Dockerfile`); only the command differs.

| Service    | Phase | Entry point                       | Status |
|------------|-------|-----------------------------------|--------|
| web        | 1     | `uvicorn app.web.main:app`        | built  |
| migrate    | 1     | `alembic upgrade head` + bootstrap | built  |
| receiver   | 2     | `python -m app.receiver`          | built  |
| parser     | 3     | parser workers                    | todo   |
| poller     | 6     | SNMP / UniFi API poller           | todo   |
| reporter   | 8     | APScheduler report jobs           | todo   |

The receiver stays a separate container from web so UI restarts never drop logs.
