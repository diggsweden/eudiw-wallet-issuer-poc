FROM cgr.dev/chainguard/jre:latest@sha256:35d28eef888426205e1523cd4d5ceea6e0608c94cf58029ea8d3006ea278d269

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
