FROM golang:1.24-alpine

# VULN: COPY . copies everything including .env, .git
COPY . .

# VULN: InsecureSkipVerify
ENV GO_INSECURE_SKIP_VERIFY=true

# VULN: Debug mode
ENV DEBUG=true
ENV APP_DEBUG=true

# VULN: Running as root (no USER directive)
RUN go build -o /app .

# VULN: Exposed database port
EXPOSE 5432

CMD ["/app"]
