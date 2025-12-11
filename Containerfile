FROM cgr.dev/chainguard/jre:latest@sha256:ca9892df315d5419a702f5a3aae88548d0e3baa2f4cef86c08d1e0a9a89bf3e8

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
