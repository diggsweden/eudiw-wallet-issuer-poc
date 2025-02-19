FROM cgr.dev/chainguard/jre:latest@sha256:ab6f429e3fdf2b84edbec5f470e3d4cb722949f07373813df0ea320e411b3b72

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
