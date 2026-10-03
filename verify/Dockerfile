FROM python:3.11-slim

WORKDIR /repo
COPY app/src/ /repo/app/src/
COPY tools/ /repo/tools/
COPY tests/ /repo/tests/
COPY verify/verify.py /repo/verify/verify.py

ENV PYTHONPATH=/repo/app/src:/repo/tools \
    APP_URL=http://app:8000

CMD ["python", "verify/verify.py"]
