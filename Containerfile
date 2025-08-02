FROM cgr.dev/chainguard/jre:latest@sha256:b9dc15b01d78e4216c8e07ff029b60d5e97d2b2afd6b52e05ff720b0abb39905

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
