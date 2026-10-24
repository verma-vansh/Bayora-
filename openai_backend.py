"""Optional real-model backend. Needs egress to api.openai.com (see docker-compose.openai.yml)."""
import httpx


def complete(prompt: str, system: str, api_key: str, model: str, client: httpx.Client | None = None) -> str:
    c = client or httpx.Client(timeout=30.0)
    r = c.post("https://api.openai.com/v1/chat/completions",
               headers={"Authorization": f"Bearer {api_key}"},
               json={"model": model, "max_tokens": 400,
                     "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]})
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]
