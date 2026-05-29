FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY . .

RUN uv sync

CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
