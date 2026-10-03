FROM python:3.11-slim

WORKDIR /srv
COPY src/ /srv/

ENV PORT=8000
EXPOSE 8000

CMD ["python", "-m", "server"]
