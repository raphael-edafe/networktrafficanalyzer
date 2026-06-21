"""Best-effort outbound notifications (Discord/Slack-style webhook) for serious alerts."""
import requests

from .models import SEVERITY_RANK


class Notifier:
    def __init__(self, config):
        self.url = config.notify_webhook_url
        self.min_rank = SEVERITY_RANK.get(config.notify_min_severity, 2)

    def send(self, alert):
        if not self.url or alert.rank < self.min_rank:
            return
        emoji = {"CRITICAL": "\U0001F6A8", "WARNING": "⚠️", "INFO": "ℹ️"}.get(
            alert.severity, "")
        text = f"{emoji} [{alert.severity}] {alert.category}: {alert.message}"
        try:
            # `content` works for Discord; `text` for Slack. Sending both is harmless.
            requests.post(self.url, json={"content": text, "text": text}, timeout=3)
        except Exception:
            pass  # never let alerting failures crash the sniffer
