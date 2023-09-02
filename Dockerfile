FROM alpine:latest

COPY ./dist/phase-alpine-build /usr/local/bin/phase

RUN chmod +x /usr/local/bin/phase

ENTRYPOINT ["/usr/local/bin/phase"]
