import os

import requests
import urllib3
from dotenv import load_dotenv


load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WazuhIndexerClient:
    def __init__(self):
        self.base_url = os.getenv("WAZUH_INDEXER_URL")
        self.username = os.getenv("WAZUH_INDEXER_USER")
        self.password = os.getenv("WAZUH_INDEXER_PASSWORD")

    def search(self, index, query, size=10):
        url = f"{self.base_url}/{index}/_search"

        response = requests.post(
            url,
            auth = (self.username, self.password),
            headers = {"Content-Type": "application/json"},
            json = {
                "size":size,
                "query":query,
                "sort": [
                    {
                        "timestamp":{
                            "order": "desc"
                        }
                    }
                ]
            },
            verify = False,
            timeout=10
        )

        response.raise_for_status()

        return response.json()

    def get_alert(self, alert_id, ):
        url = f"{self.base_url}/wazuh-alerts-4.x-*/_search"

        response = requests.post(
            url,
            auth = (self.username, self.password),
            headers={"Content-Type": "application/json"},
            json={
                "size": 1,
                "query": {
                    "ids": {
                        "values": [alert_id]
                    }
                }
            },
            verify=False,
            timeout=10
        )

        response.raise_for_status()

        data = response.json()

        hits = data["hits"]["hits"]

        if not hits:
            return None

        return hits[0]