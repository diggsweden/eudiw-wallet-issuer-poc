FROM cgr.dev/chainguard/jre:latest@sha256:14dc2fa681735e9d9b50c709f7cb0c0c8f704bb9e269449d596371ea9b8718d2

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
