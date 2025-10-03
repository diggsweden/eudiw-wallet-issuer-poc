FROM cgr.dev/chainguard/jre:latest@sha256:cd3f3f82edd13a4e21e0f2e05861aad2d51380cfecd3bcce87486149482b1181

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
