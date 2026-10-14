from app.drivers.base import PollDriver, PollError
from app.drivers.unifi import UnifiCloudDriver, UnifiControllerDriver

# poll_config["driver"] -> driver. Each is verified against a real controller/firmware before being added.
DRIVERS: dict[str, PollDriver] = {"unifi": UnifiControllerDriver(), "unifi_cloud": UnifiCloudDriver()}

__all__ = ["DRIVERS", "PollDriver", "PollError"]
