"""Scheduled-jobs service (APScheduler): report queue, monthly report schedules, Event Monitor alert rules."""

import asyncio
import logging
import signal

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.alerts.engine import AlertEngine
from app.forwarder import Forwarder, apply_retention
from app.intel import feeds as intel
from app.reporter.service import Reporter


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logging.getLogger("fontTools").setLevel(logging.WARNING)
    logging.getLogger("apscheduler").setLevel(logging.WARNING)  # one line per job run is noise
    reporter = Reporter()
    sched = AsyncIOScheduler(timezone="UTC")
    sched.add_job(reporter.drain, "interval", seconds=15, max_instances=1, coalesce=True, id="queue")
    sched.add_job(reporter.check_schedules, "interval", minutes=10, max_instances=1, coalesce=True, id="schedules")
    sched.add_job(intel.match_new_events, "interval", seconds=45, max_instances=1, coalesce=True, id="ioc-match")
    sched.add_job(AlertEngine().evaluate, "interval", seconds=60, max_instances=1, coalesce=True, id="alerts")
    sched.add_job(intel.refresh, "interval", hours=6, max_instances=1, coalesce=True, id="ioc-refresh")
    sched.add_job(Forwarder().run_once, "interval", seconds=10, max_instances=1, coalesce=True, id="forward")
    sched.add_job(apply_retention, "interval", hours=6, max_instances=1, coalesce=True, id="retention")
    sched.start()
    await reporter.check_schedules()  # once at startup, then every 10 minutes
    await intel.refresh()             # feeds at startup, then every 6 hours
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    sched.shutdown(wait=True)


if __name__ == "__main__":
    asyncio.run(main())
