"""Low-cost background monitoring worker."""

from __future__ import annotations

import logging
import time

from config import Config
from rag.models import init_db
from monitoring_service import refresh_all_provider_snapshots


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)


def main():
    init_db()
    interval = max(60, int(Config.MONITORING_REFRESH_INTERVAL_SECONDS))
    logger.info("Monitoring worker started with %ss interval", interval)

    while True:
        try:
            refresh_all_provider_snapshots(source="scheduled")
            logger.info("Scheduled monitoring refresh completed")
        except Exception:
            logger.exception("Scheduled monitoring refresh failed")
        time.sleep(interval)


if __name__ == "__main__":
    main()
