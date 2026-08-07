import os
import sys
from pathlib import Path
from unittest.mock import Mock

os.environ["NETWATCH_DISABLE_RUNTIME"] = "true"
os.environ["NETWATCH_AUTH_ENABLED"] = "false"
os.environ["NETWATCH_SECRET"] = "test-secret"

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
import netwatch_api as api


def test_pihole_v6_top_clients_uses_clients_response_and_counts():
    client = api.PiholeClient()
    client.ver = 6
    client._v6_get = Mock(return_value={
        "clients": [
            {"ip": "192.168.1.41", "name": "Test device", "count": 27},
            {"ip": "192.168.1.42", "name": None, "count": 13},
        ],
        "total_queries": 40,
    })

    result = client.top_clients(limit=None)

    assert result == [
        {
            "name": "Test device",
            "ip": "192.168.1.41",
            "count": 27,
            "pct": 67.5,
        },
        {
            "name": "192.168.1.42",
            "ip": "192.168.1.42",
            "count": 13,
            "pct": 32.5,
        },
    ]
    client._v6_get.assert_called_once_with(
        "/api/stats/top_clients",
        params={"count": 1000},
    )
