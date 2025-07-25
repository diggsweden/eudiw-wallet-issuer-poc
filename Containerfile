FROM cgr.dev/chainguard/jre:latest@sha256:9b76380d3faecf083648120f33e38e1bb98195419bc6acf4e3f10ca854e2c4f3

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
