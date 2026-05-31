import json
import os
import re
import urllib.request
import urllib.error

from core.env_loader import load_dotenv


class LLMClient:
    """
    Minimal OpenAI-compatible chat completion client.

    It uses only Python standard library so Part 3 does not depend on extra packages.

    Required .env:
        LLM_API_KEY=xxx
        LLM_BASE_URL=https://your-provider.example/v1
        LLM_MODEL=your-model-name

    Optional .env:
        LLM_TIMEOUT=60
        LLM_TEMPERATURE=0
    """

    def __init__(self):
        load_dotenv(".env")

        self.api_key = os.getenv("LLM_API_KEY", "").strip()
        self.base_url = os.getenv("LLM_BASE_URL", "").strip().rstrip("/")
        self.model = os.getenv("LLM_MODEL", "").strip()
        self.timeout = int(os.getenv("LLM_TIMEOUT", "60"))
        self.temperature = float(os.getenv("LLM_TEMPERATURE", "0"))

    def is_available(self):
        return bool(self.api_key and self.base_url and self.model)

    def chat(self, messages, temperature=None):
        if not self.is_available():
            raise RuntimeError(
                "LLM is not configured. Please set LLM_API_KEY, LLM_BASE_URL, and LLM_MODEL in .env."
            )

        endpoint = self._chat_endpoint()
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature if temperature is None else temperature
        }

        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            },
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"LLM HTTP error {exc.code}: {error_body}") from exc
        except Exception as exc:
            raise RuntimeError(f"LLM request failed: {exc}") from exc

        try:
            return data["choices"][0]["message"]["content"]
        except Exception as exc:
            raise RuntimeError(f"Unexpected LLM response format: {data}") from exc

    def _chat_endpoint(self):
        if self.base_url.endswith("/chat/completions"):
            return self.base_url
        return self.base_url.rstrip("/") + "/chat/completions"


def extract_json_object(text):
    """
    Robustly extract a JSON object from LLM output.

    Handles:
    - pure JSON
    - ```json fenced code block
    - prose + JSON object
    """
    if text is None:
        raise ValueError("Empty LLM output")

    text = text.strip()

    # Remove fenced code block if present.
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.DOTALL)
    if fenced:
        text = fenced.group(1).strip()

    # Try direct parse.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try extracting first object.
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError(f"No JSON object found in LLM output: {text[:300]}")

    candidate = text[start:end + 1]
    return json.loads(candidate)
