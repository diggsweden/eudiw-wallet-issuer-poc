FROM cgr.dev/chainguard/jre:latest@sha256:fe5cfa3a3352299d6b43516d80b4d31514a3d9d40b68a3015de879b3899d70ea

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
