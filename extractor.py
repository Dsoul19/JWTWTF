import requests
import re
import logging
import json
from requests.exceptions import RequestException, SSLError, Timeout
from urllib.parse import urljoin
import websocket
import threading
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

class TokenExtractor:
    def __init__(self):
        self._target = None
        self._headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        self._proxies = None
        self._timeout = 5
        self._ws_tokens = []
        self._ws_running = False

    @property
    def target(self):
        return self._target

    @target.setter
    def target(self, value):
        if not isinstance(value, str) or not value.startswith(("http://", "https://")):
            raise ValueError("Target must be a valid URL starting with http:// or https://")
        self._target = value
        logger.info(f"Target set to: {self._target}")

    def set_proxy(self, proxy_url):
        self._proxies = {"http": proxy_url, "https": proxy_url}
        logger.info(f"Proxy set to: {proxy_url}")

    def extract(self, return_all=False, include_js=False, include_ws=False, include_api=False, ws_duration=5):
        """
        Extract JWTs from various sources at the target URL.
        :param return_all: Return all tokens if True, first token if False.
        :param include_js: Extract from linked JavaScript files.
        :param include_ws: Extract from WebSocket traffic.
        :param include_api: Scan API endpoints in response.
        :param ws_duration: Duration (seconds) to monitor WebSocket traffic.
        :return: Single token (str), list of tokens, or error message.
        """
        if not self.target:
            return "No target set."

        tokens = []
        try:
            response = requests.get(
                self.target,
                timeout=self._timeout,
                verify=False,
                headers=self._headers,
                proxies=self._proxies,
                allow_redirects=True
            )
            response.raise_for_status()
            logger.info(f"Fetched {response.url}")

            tokens.extend(self._extract_from_response(response))
            
            if include_js:
                js_tokens = self._from_js_files(response)
                if js_tokens:
                    tokens.extend(js_tokens)
            
            if include_ws:
                ws_tokens = self._from_websocket(duration=ws_duration)
                if ws_tokens:
                    tokens.extend(ws_tokens)
            
            if include_api:
                api_tokens = self._from_api_endpoints(response)
                if api_tokens:
                    tokens.extend(api_tokens)

            if not tokens:
                return "No JWT found."
            return tokens if return_all else tokens[0]

        except (SSLError, Timeout, RequestException) as e:
            logger.error(f"Extraction error: {str(e)}")
            return f"Error extracting token: {str(e)}"
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return f"Unexpected error: {str(e)}"

    def _extract_from_response(self, response):
        tokens = []
        if header_token := self._from_header(response):
            tokens.append(header_token)
        if cookie_tokens := self._from_cookie(response):
            tokens.extend(cookie_tokens)
        if body_tokens := self._from_body(response.text):
            tokens.extend(body_tokens)
        if url_tokens := self._from_url(self.target):
            tokens.extend(url_tokens)
        return tokens

    def _from_header(self, response):
        auth = response.headers.get("Authorization", "")
        if "Bearer " in auth:
            token = auth.split("Bearer ")[1]
            return token if self._is_jwt(token) else None
        return None

    def _from_cookie(self, response):
        return [cookie.value for cookie in response.cookies if self._is_jwt(cookie.value)]

    def _from_body(self, text):
        pattern = r"eyJ[A-Za-z0-9\-_]{2,}\.[A-Za-z0-9\-_]{2,}\.[A-Za-z0-9\-_]{2,}"
        return [match for match in re.findall(pattern, text) if self._is_jwt(match)]

    def _from_url(self, url):
        pattern = r"eyJ[A-Za-z0-9\-_]{2,}\.[A-Za-z0-9\-_]{2,}\.[A-Za-z0-9\-_]{2,}"
        return [match for match in re.findall(pattern, url) if self._is_jwt(match)]

    def _from_js_files(self, response):
        tokens = []
        js_urls = re.findall(r'<script[^>]+src=["\'](.*?)["\']', response.text)
        for js_url in js_urls:
            full_url = urljoin(self.target, js_url)
            try:
                js_response = requests.get(full_url, timeout=self._timeout, verify=False, headers=self._headers, proxies=self._proxies)
                js_tokens = self._from_body(js_response.text)
                if js_tokens:
                    logger.info(f"Found JWTs in JS file: {full_url}")
                    tokens.extend(js_tokens)
            except Exception as e:
                logger.debug(f"Failed to fetch JS {full_url}: {str(e)}")
        return tokens

    def _from_websocket(self, duration=5):
        ws_url = self.target.replace("http", "ws")
        self._ws_tokens = []
        self._ws_running = True
        thread = threading.Thread(target=self._ws_monitor, args=(ws_url, duration))
        thread.start()
        thread.join()
        return self._ws_tokens

    def _ws_monitor(self, ws_url, duration):
        try:
            ws = websocket.WebSocket()
            ws.connect(ws_url)
            start_time = time.time()
            while self._ws_running and (time.time() - start_time) < duration:
                data = ws.recv()
                tokens = self._from_body(data)
                if tokens:
                    logger.info("Found JWTs in WebSocket traffic")
                    self._ws_tokens.extend(tokens)
            ws.close()
        except Exception as e:
            logger.debug(f"WebSocket error: {str(e)}")
        finally:
            self._ws_running = False

    def _from_api_endpoints(self, response):
        tokens = []
        api_urls = re.findall(r'["\'](https?://[^"\']+?)["\']', response.text)
        for url in api_urls[:5]:
            try:
                api_response = requests.get(url, timeout=self._timeout, verify=False, headers=self._headers, proxies=self._proxies)
                api_tokens = self._extract_from_response(api_response)
                if api_tokens:
                    logger.info(f"Found JWTs in API endpoint: {url}")
                    tokens.extend(api_tokens)
            except Exception as e:
                logger.debug(f"API fetch error {url}: {str(e)}")
        return tokens

    def _is_jwt(self, token):
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return False
            import base64
            for part in parts[:2]:
                padded = part + "=" * (4 - len(part) % 4) if len(part) % 4 else part
                base64.urlsafe_b64decode(padded)
            return True
        except Exception:
            return False