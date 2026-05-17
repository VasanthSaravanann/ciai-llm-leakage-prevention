import os
from celery import Celery

redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
broker = os.environ.get('CELERY_BROKER_URL', redis_url)

worker = Celery('ciai_worker', broker=broker, backend=broker)

worker.conf.update(task_serializer='json', accept_content=['json'], result_serializer='json')
