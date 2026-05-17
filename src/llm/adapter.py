"""LLM adapter with retries and provider abstraction."""
import os
import requests
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

LLM_PROVIDER = os.environ.get('LLM_PROVIDER', 'mock')
LLM_API_KEY = os.environ.get('LLM_API_KEY')

# Optional OpenAI model
OPENAI_MODEL = os.environ.get('OPENAI_MODEL', 'gpt-3.5-turbo')


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=8), retry=retry_if_exception_type(Exception))
def send_prompt(prompt: str) -> str:
    if LLM_PROVIDER == 'mock' or not LLM_API_KEY:
        resp = requests.post('https://httpbin.org/post', json={'prompt': prompt}, timeout=10)
        return resp.text
    # Provider specific implementations
    headers = {'Authorization': f'Bearer {LLM_API_KEY}', 'Content-Type': 'application/json'}
    if LLM_PROVIDER == 'openai':
        url = 'https://api.openai.com/v1/chat/completions'
        payload = {
            'model': OPENAI_MODEL,
            'messages': [
                {'role': 'system', 'content': 'You are an assistant that redacts sensitive data.'},
                {'role': 'user', 'content': prompt}
            ],
            'max_tokens': 1024,
            'temperature': 0.0
        }
        resp = requests.post(url, json=payload, headers=headers, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        # Extract assistant content
        try:
            return data['choices'][0]['message']['content']
        except Exception:
            return resp.text

    # Fallback generic provider
    resp = requests.post('https://api.example-llm.com/v1/generate', json={'prompt': prompt}, headers=headers, timeout=10)
    resp.raise_for_status()
    return resp.text
