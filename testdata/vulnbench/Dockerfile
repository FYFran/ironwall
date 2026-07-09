FROM python:3.7-slim  # EOL, many CVEs
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
# Running as root
USER root
EXPOSE 80
CMD ["python", "app.py"]
ENV SECRET_KEY=in-dockerfile-hardcoded
