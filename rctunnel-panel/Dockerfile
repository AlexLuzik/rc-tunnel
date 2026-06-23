FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY rctunnel_panel ./rctunnel_panel
COPY scripts ./scripts
COPY agent ./agent
COPY deploy/install.sh ./deploy/install.sh
ENV PYTHONUNBUFFERED=1
CMD ["python","-m","rctunnel_panel"]
