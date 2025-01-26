import requests

class Web3ConnectionError(Exception):
    def __init__(self, message, code, data):
        super().__init__(message)
        self.code = code
        self.data = data

class Web3APIError(Exception):
    def __init__(self, message, code, data):
        super().__init__(message)
        self.code = code
        self.data = data

class HTTPJSONRPCer:
    def __init__(self, url):
        self._url = url
        self._id_counter = 0

    def _generate_id(self):
        self._id_counter += 1
        return self._id_counter

    def do_request(self, method, params):
        request_id = self._generate_id()
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": request_id
        }

        headers = {"Content-Type": "application/json"}

        try:
            response = requests.post(self._url, json=payload, headers=headers)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise Web3ConnectionError("The node isn't returning valid JSON", -32700, str(e))

        try:
            response_data = response.json()
        except ValueError:
            raise Web3ConnectionError("The node isn't returning valid JSON", -32700, response.text)

        if "error" not in response_data:
            return response_data.get("result")

        error = response_data["error"]
        raise Web3APIError(error.get("message"), error.get("code"), error.get("data"))
