import importlib.util
import json
import os
import pathlib
import tempfile
import unittest


os.environ.setdefault("NETWATCH_AUTH_ENABLED", "false")
os.environ.setdefault("NETWATCH_SECRET", "test-secret")
os.environ.setdefault("PIHOLE_ENABLED", "false")
os.environ.setdefault("NETWATCH_DISABLE_RUNTIME", "true")

MODULE_PATH = pathlib.Path(__file__).parents[1] / "api" / "netwatch_api.py"
SPEC = importlib.util.spec_from_file_location("netwatch_api", MODULE_PATH)
netwatch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(netwatch)


class ActiveUsageAccountingTests(unittest.TestCase):
    def setUp(self):
        self.devices = [
            {"ip": "192.0.2.10", "profile_id": "p1", "status": "online"},
            {"ip": "192.0.2.11", "profile_id": "p1", "status": "online"},
            {"ip": "192.0.2.20", "profile_id": "p2", "status": "online"},
        ]

    def test_online_presence_without_new_queries_does_not_count(self):
        current = {"192.0.2.10": 100, "192.0.2.11": 50}
        active, deltas = netwatch.active_profiles_from_query_deltas(
            self.devices, current, current, minimum_delta=1
        )
        self.assertEqual(active, set())
        self.assertEqual(deltas["p1"], 0)

    def test_first_sample_establishes_baseline_without_charging(self):
        active, deltas = netwatch.active_profiles_from_query_deltas(
            self.devices, {"192.0.2.10": 100}, {}, minimum_delta=1
        )
        self.assertEqual(active, set())
        self.assertEqual(deltas["p1"], 0)

    def test_activity_is_aggregated_across_profile_devices(self):
        active, deltas = netwatch.active_profiles_from_query_deltas(
            self.devices,
            {"192.0.2.10": 102, "192.0.2.11": 53, "192.0.2.20": 5},
            {"192.0.2.10": 100, "192.0.2.11": 50, "192.0.2.20": 5},
            minimum_delta=3,
        )
        self.assertEqual(active, {"p1"})
        self.assertEqual(deltas, {"p1": 5, "p2": 0})

    def test_counter_reset_never_creates_false_activity(self):
        active, deltas = netwatch.active_profiles_from_query_deltas(
            self.devices,
            {"192.0.2.10": 2},
            {"192.0.2.10": 100},
            minimum_delta=1,
        )
        self.assertEqual(active, set())
        self.assertEqual(deltas["p1"], 0)


class AccessLogTests(unittest.TestCase):
    def test_events_are_persisted_and_capped(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            old_path = netwatch.ACCESS_LOG_FILE
            old_max = netwatch.ACCESS_LOG_MAX_RECORDS
            old_days = netwatch.ACCESS_LOG_RETENTION_DAYS
            try:
                netwatch.ACCESS_LOG_FILE = os.path.join(temp_dir, "access_log.json")
                netwatch.ACCESS_LOG_MAX_RECORDS = 2
                netwatch.ACCESS_LOG_RETENTION_DAYS = 90
                profile = {"id": "p1", "name": "Test Profile"}
                for number in range(3):
                    netwatch.append_access_event(
                        "test", profile, "test", f"Event {number}"
                    )

                with open(netwatch.ACCESS_LOG_FILE) as handle:
                    stored = json.load(handle)
                self.assertEqual([event["title"] for event in stored], ["Event 1", "Event 2"])
                newest_first = netwatch.get_access_events(limit=20)
                self.assertEqual([event["title"] for event in newest_first], ["Event 2", "Event 1"])
            finally:
                netwatch.ACCESS_LOG_FILE = old_path
                netwatch.ACCESS_LOG_MAX_RECORDS = old_max
                netwatch.ACCESS_LOG_RETENTION_DAYS = old_days


if __name__ == "__main__":
    unittest.main()
