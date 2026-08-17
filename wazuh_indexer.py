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

    def get_alert(self, alert_id):
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

    def search_events(self, agent_id: str, start_time: str, end_time: str,size: int = 10):
        url = f"{self.base_url}/wazuh-alerts-4.x-*/_search"

        query = {
            "bool": {
                "must": [
                    {
                        "term": {
                            "agent.id": agent_id
                        }
                    }
                ],
                "filter": [
                    {
                        "range": {
                            "timestamp": {
                                "gte": start_time,
                                "lte": end_time
                            }
                        }
                    }
                ]
            }
        }

        response = requests.post(
            url,
            auth=(self.username, self.password),
            headers={"Content-Type": "application/json"},
            json={
                "size": size,
                "query": query,
                "sort": [
                    {
                        "timestamp": {
                            "order": "asc"
                        }
                    }
                ]
            },
            verify=False,
            timeout=10
        )

        response.raise_for_status()

        return response.json()

    def search_authentication_events(self, agent_id: str, start_time: str, end_time: str, size: int = 10):
        url = f"{self.base_url}/wazuh-alerts-4.x-*/_search"

        query = {
            "bool": {
                "must": [
                    {
                        "term": {
                            "agent.id": agent_id
                        }
                    }
                ],
                "filter": [
                    {
                        "range": {
                            "timestamp": {
                                "gte": start_time,
                                "lte": end_time
                            }
                        }
                    }
                ],
                "should": [
                    {
                        "term": {
                            "decoder.name": "sshd"
                        }
                    },
                    {
                        "term": {
                            "decoder.name": "pam"
                        }
                    }
                ],
                "minimum_should_match": 1
            }
        }

        response = requests.post(
            url,
            auth=(self.username, self.password),
            headers={"Content-Type": "application/json"},
            json={
                "size": size,
                "query": query,
                "sort": [
                    {
                        "timestamp": {
                            "order": "asc"
                        }
                    }
                ]
            },
            verify=False,
            timeout=10
        )

        response.raise_for_status()

        return response.json()

    def search_process_events(self,agent_id: str,start_time: str,end_time: str,size: int = 10):

        url = f"{self.base_url}/wazuh-alerts-4.x-*/_search"

        query = {
            "bool": {
                "must": [
                    {
                        "term": {
                            "agent.id": agent_id
                        }
                    },
                    {
                        "exists": {
                            "field": "data.command"
                        }
                    }
                ],
                "filter": [
                    {
                        "range": {
                            "timestamp": {
                                "gte": start_time,
                                "lte": end_time
                            }
                        }
                    }
                ]
            }
        }

        response = requests.post(
            url,
            auth=(self.username, self.password),
            headers={"Content-Type": "application/json"},
            json={
                "size": size,
                "query": query,
                "sort": [
                    {
                        "timestamp": {
                            "order": "asc"
                        }
                    }
                ]
            },
            verify=False,
            timeout=10
        )

        response.raise_for_status()

        return response.json()


# SSH Tunnel command
# ssh -L 9200:127.0.0.1:9200 vboxuser@192.168.56.101