FROM cgr.dev/chainguard/jre:latest@sha256:b55f342e84f459d032d267e8c1d3b4fd032c8804203224d5e89ab1bed8c1917c

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
