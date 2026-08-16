import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from wazuh_indexer import WazuhIndexerClient

def get_alert(alert_id: str):
    """
    Send alert_id to get more details about the alert
    """

    if not isinstance(alert_id, str):
        raise TypeError("alert_id must be a string")

    alert_id = alert_id.strip()

    if not alert_id:
        raise ValueError("alert_id cannot be empty")

    client = WazuhIndexerClient()

    alert = client.get_alert(alert_id)

    if alert is None:
        return {
            "status" : "not_found",
            "alert_id": alert_id
        }

    source = alert["_source"]

    return{
        "status": "success",
        "alert_id": alert["_id"],
        "evidence": source
    }


"""
To Test get alerts
"""
# from pretty_json import format_json
# print(format_json(get_alert("V5uiCqAB0yAL2NcCYXbz")))