FROM cgr.dev/chainguard/jre:latest@sha256:52baa8923a6ac5e3b2f1fd5c11dc906bafab6f9bba6bee17672ef1946652ddfc

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
