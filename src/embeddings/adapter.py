"""Embeddings adapter scaffold. Supports OpenAI embeddings as an example."""
import os
import requests

LLM_PROVIDER = os.environ.get('LLM_PROVIDER', 'mock')
LLM_API_KEY = os.environ.get('LLM_API_KEY')


def get_embedding(text: str) -> list[float]:
    if LLM_PROVIDER == 'mock' or not LLM_API_KEY:
        # simple hash-based mock embedding
        return [float(ord(c) % 97) for c in text[:64]]

    if LLM_PROVIDER == 'openai':
        url = 'https://api.openai.com/v1/embeddings'
        headers = {'Authorization': f'Bearer {LLM_API_KEY}'}
        payload = {'model': os.getenv('OPENAI_EMBEDDING_MODEL', 'text-embedding-3-small'), 'input': text}
        resp = requests.post(url, json=payload, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return data['data'][0]['embedding']

    # fallback
    return [0.0]
