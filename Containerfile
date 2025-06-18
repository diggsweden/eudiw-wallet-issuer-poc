FROM cgr.dev/chainguard/jre:latest@sha256:c3e04cab8dfed37b4bed42e36067aec6301da6eadeac4b2437e56ab3addae102

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
