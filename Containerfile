FROM cgr.dev/chainguard/jre:latest@sha256:0ce8e2297ff2fdea1b11897c0d3433785833b0ac8c13283b36afa303a704f7fd

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
