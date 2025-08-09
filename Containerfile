FROM cgr.dev/chainguard/jre:latest@sha256:89c59ce8aa1e386b36ba481f0d10f444d53cc0f032cea2a986fd4b9862abe7aa

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
