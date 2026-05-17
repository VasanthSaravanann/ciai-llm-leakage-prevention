"""LLM adapter with retries and provider abstraction."""
import os
import requests
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

LLM_PROVIDER = os.environ.get('LLM_PROVIDER', 'mock')
LLM_API_KEY = os.environ.get('LLM_API_KEY')


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=8), retry=retry_if_exception_type(Exception))
def send_prompt(prompt: str) -> str:
    if LLM_PROVIDER == 'mock' or not LLM_API_KEY:
        resp = requests.post('https://httpbin.org/post', json={'prompt': prompt}, timeout=10)
        return resp.text
    # Placeholder: add provider-specific code here (OpenAI, Anthropic, etc.)
    headers = {'Authorization': f'Bearer {LLM_API_KEY}'}
    # Example for provider - replace with real endpoint and payload
    resp = requests.post('https://api.example-llm.com/v1/generate', json={'prompt': prompt}, headers=headers, timeout=10)
    resp.raise_for_status()
    return resp.text
