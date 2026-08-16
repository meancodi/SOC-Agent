import os

import requests
import urllib3
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# The above line disables SSL certificate checking when making HTTPS calls
# This is because Wazuh has its own certificate, not a publicly signed one

class WazuhClient:

    def __init__(self):
        self.base_url = os.getenv("WAZUH_API_URL")
        self.username = os.getenv("WAZUH_API_USER")
        self.password = os.getenv("WAZUH_API_PASSWORD")

        self.token = None

    def authenticate(self):
        url = f"{self.base_url}/security/user/authenticate"

        response = requests.post(
            url,
            auth = (self.username, self.password),
            verify = False, # ignores the SSL certificate
            timeout=10
        )

        response.raise_for_status() # Checks for status codes such as 401, 200, etc.

        data = response.json()
        self.token = data["data"]["token"]

        return self.token

    def _headers(self):
        if not self.token:
            raise RuntimeError("Client is not authenticated")

        return {
            "Authorization": f"Bearer {self.token}"
        }

    def get(self, endpoint, params=None):
        response = requests.get(
            f"{self.base_url}{endpoint}",
            headers=self._headers(),
            params=params,
            verify=False,
            timeout=10
        )

        response.raise_for_status()

        return response.json()