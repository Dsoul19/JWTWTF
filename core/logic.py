import base64
import json
import jwt
from datetime import datetime
import hmac
import hashlib

class JWTLogic:
    def __init__(self):
        self.tokens = {}
        self.current_id = None

    def add_token(self, token, token_id="default"):
        try:
            self.tokens[token_id] = {
                "token": token,
                "decoded": self.decode_token(token, verify=False),
                "secret": None,
                "alg": jwt.get_unverified_header(token).get("alg", "HS256")
            }
            self.current_id = token_id
        except Exception as e:
            return f"Error adding token: {str(e)}"

    def set_secret(self, secret, token_id=None):
        tid = token_id or self.current_id
        if tid in self.tokens:
            self.tokens[tid]["secret"] = secret

    def set_algorithm(self, algorithm, token_id=None):
        tid = token_id or self.current_id
        if tid in self.tokens:
            self.tokens[tid]["alg"] = algorithm

    def decode_token(self, token, verify=True):
        try:
            if verify and self.tokens.get(self.current_id, {}).get("secret"):
                return jwt.decode(token, self.tokens[self.current_id]["secret"], algorithms=[self.tokens[self.current_id]["alg"]])
            return jwt.decode(token, options={"verify_signature": False})
        except Exception as e:
            return f"Error decoding token: {str(e)}"

    def encode_token(self, payload, header=None, token_id=None):
        tid = token_id or self.current_id
        if tid not in self.tokens:
            return "Token ID not found."
        secret = self.tokens[tid]["secret"]
        if not secret:
            return "Secret not set."
        header = header or jwt.get_unverified_header(self.tokens[tid]["token"])
        try:
            return jwt.encode(payload, secret, algorithm=header.get("alg"), headers=header)
        except Exception as e:
            return f"Error encoding token: {str(e)}"

    def analyze(self, token_id=None):
        tid = token_id or self.current_id
        if tid not in self.tokens:
            return "No token set."
        token = self.tokens[tid]["token"]
        header = jwt.get_unverified_header(token)
        payload = self.decode_token(token, verify=False)
        output = [f"Token ID: {tid}", f"Header: {json.dumps(header, indent=2)}", f"Payload: {json.dumps(payload, indent=2)}"]
        now = int(datetime.now().timestamp())
        for claim in ["iat", "exp", "nbf"]:
            if claim in payload:
                ts = datetime.fromtimestamp(payload[claim])
                output.append(f"{claim}: {ts} (UTC)")
                if claim == "exp" and payload[claim] < now:
                    output.append("[-] TOKEN EXPIRED!")
                elif claim == "nbf" and payload[claim] > now:
                    output.append("[-] TOKEN NOT YET VALID!")
        return "\n".join(output)

    def sign_hs(self, header, payload, hash_length=256):
        secret = self.tokens[self.current_id]["secret"]
        if not secret:
            return "Secret not set."
        contents = self._gen_contents(header, payload)
        if hash_length == 384:
            sig = hmac.new(secret.encode(), contents.encode(), hashlib.sha384).digest()
        elif hash_length == 512:
            sig = hmac.new(secret.encode(), contents.encode(), hashlib.sha512).digest()
        else:
            sig = hmac.new(secret.encode(), contents.encode(), hashlib.sha256).digest()
        return f"{contents}.{base64.urlsafe_b64encode(sig).decode().rstrip('=')}"

    def _gen_contents(self, header, payload):
        return (base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).decode().rstrip("=") +
                "." + base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("="))

    def compare_tokens(self, token_id1, token_id2):
        if token_id1 not in self.tokens or token_id2 not in self.tokens:
            return "One or both token IDs not found."
        p1, p2 = self.tokens[token_id1]["decoded"], self.tokens[token_id2]["decoded"]
        diff = [f"{key}: {p1.get(key)} vs {p2.get(key)}" for key in set(p1.keys()) | set(p2.keys()) if p1.get(key) != p2.get(key)]
        return "Differences:\n" + "\n".join(diff) if diff else "No differences found."