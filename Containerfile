FROM cgr.dev/chainguard/jre:latest@sha256:e210680d61b774aa26e76d169ecc036d1fd90e1e5bada56818747cf2b848e2ea

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
