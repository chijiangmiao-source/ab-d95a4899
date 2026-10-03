FROM python:3.11-slim

WORKDIR /srv
COPY app /srv/app

RUN pip install --no-cache-dir pytest==9.1.1

EXPOSE 8080

HEALTHCHECK --interval=3s --timeout=2s --start-period=2s --retries=10 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status==200 else 1)"

CMD ["python", "-m", "app.server"]
