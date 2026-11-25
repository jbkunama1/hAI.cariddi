# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
ARG CARIDDI_REF=39aebc1ce7e43a2c59de194d0d1e29a034c8ab3c
RUN apk add --no-cache git ca-certificates
WORKDIR /src
RUN git init . && git remote add origin https://github.com/edoardottt/cariddi.git && git fetch --depth=1 origin ${CARIDDI_REF} && git checkout --detach FETCH_HEAD && test "$(git rev-parse HEAD)" = "${CARIDDI_REF}" && rm -rf .git
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -o /out/cariddi ./cmd/cariddi
FROM python:3.13-alpine
RUN apk add --no-cache ca-certificates tzdata && addgroup -g 10001 app && adduser -D -u 10001 -G app app && mkdir -p /data && chown app:app /data
COPY --from=builder /out/cariddi /usr/local/bin/cariddi
COPY --from=builder /src /usr/share/cariddi/source
COPY runner.py web.py /app/
LABEL org.opencontainers.image.source="https://github.com/jbkunama1/hAI.cariddi"
LABEL org.opencontainers.image.description="Cariddi with web UI for Portainer"
WORKDIR /data
USER 10001:10001
EXPOSE 8080
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 HOME=/tmp
ENTRYPOINT ["python", "/app/web.py"]
