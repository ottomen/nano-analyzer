import json
import os
import random
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------


def load_api_keys():
    keys = {}
    for var in ("OPENROUTER_API_KEY", "OPENAI_API_KEY"):
        val = os.environ.get(var)
        if val:
            keys[var] = val
    return keys


def resolve_backend(model, keys):
    if "/" in model:
        api_key = keys.get("OPENROUTER_API_KEY")
        if not api_key:
            print(
                f"❌ Model '{model}' uses OpenRouter (provider/model format) "
                "but OPENROUTER_API_KEY is not set.",
                file=sys.stderr,
            )
            print("   Set it with:  export OPENROUTER_API_KEY=sk-or-...",
                  file=sys.stderr)
            sys.exit(1)
        return os.getenv("OPENROUTER_API_URL"), api_key, model, {
            "HTTP-Referer": "https://github.com/weareaisle/nano-analyzer",
            "X-Title": "nano-analyzer",
        }

    api_key = keys.get("OPENAI_API_KEY")
    if not api_key:
        print(
            f"❌ Model '{model}' uses OpenAI but OPENAI_API_KEY is not set.",
            file=sys.stderr,
        )
        print("   Set it with:  export OPENAI_API_KEY=sk-...", file=sys.stderr)
        sys.exit(1)
    return os.getenv("OPENAI_API_URL"), api_key, model, {}


_http_session = None
_http_lock = threading.Lock()
_api_semaphore = None


def _get_session():
    global _http_session
    if _http_session is None:
        with _http_lock:
            if _http_session is None:
                _http_session = urllib.request.build_opener(
                    urllib.request.HTTPHandler(),
                    urllib.request.HTTPSHandler(),
                )
    return _http_session


def init_api_semaphore(max_concurrent):
    global _api_semaphore
    _api_semaphore = threading.Semaphore(max_concurrent)


def call_llm(model, messages, keys, json_mode=False, max_retries=3, reasoning_effort=None):
    api_url, api_key, model_name, extra_headers = resolve_backend(model, keys)
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        **extra_headers,
    }
    payload = {"model": model_name, "messages": messages}
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    if reasoning_effort:
        payload["reasoning_effort"] = reasoning_effort

    session = _get_session()

    for attempt in range(max_retries):
        time.sleep(
            random.uniform(0.1, 3.0)
            if attempt == 0
            else 2 ** attempt + random.uniform(0, 2)
        )
        try:
            t0 = time.time()
            with _api_semaphore:
                request = urllib.request.Request(
                    api_url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                with session.open(request, timeout=120) as resp:
                    status_code = resp.status
                    response_text = resp.read().decode("utf-8", errors="replace")
                elapsed = time.time() - t0

            if status_code == 429 or status_code >= 500:
                time.sleep(2 ** attempt + random.uniform(0, 1))
                continue

            if status_code != 200:
                raise RuntimeError(f"API {status_code}: {response_text[:200]}")

            data = json.loads(response_text)
            if "error" in data:
                raise RuntimeError(f"API error: {data['error']}")

            content = data["choices"][0]["message"]["content"]
            if content is None:
                content = data["choices"][0]["message"].get(
                    "reasoning_content") or ""
            usage = data.get("usage", {})
            return content, usage, elapsed

        except urllib.error.HTTPError as e:
            status_code = e.code
            response_text = ""
            try:
                response_text = e.read().decode("utf-8", errors="replace")
            except Exception:
                response_text = str(e)

            if status_code == 429 or status_code >= 500:
                time.sleep(2 ** attempt + random.uniform(0, 1))
                continue

            raise RuntimeError(f"API {status_code}: {response_text[:200]}")

        except (
            urllib.error.URLError,
            TimeoutError,
            socket.timeout,
            ConnectionResetError,
            OSError,
        ) as e:
            if attempt == max_retries - 1:
                raise RuntimeError(
                    f"Connection failed after {max_retries} retries: {e}")
            time.sleep(2 ** attempt + random.uniform(0, 1))

    raise RuntimeError("Max retries exceeded")
