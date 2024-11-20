# Credential Wallet Issuer POC

## Preparations

Do the mkcert config and /etc/hosts config in [quick-start](../dev-environment/compose/quick-start.md)

Install jdk21

## Start the server

### command line

```
SPRING_PROFILES_ACTIVE=dev ./gradlew bootRun
```

### Start the server in IntelliJ

Run as gradle project. Add the variable `SPRING_PROFILES_ACTIVE=dev` in the run/debug configuration.

### docker-compose

See [quick-start](../dev-environment/compose/quick-start.md)
```
cd dev-environment/compose
docker-compose --profile ewc up
```
The DemoTestsController can not run in compose.

## Code duplication maintenance notes

id-service-api should be public available dependency. As a work around the code is duplicated from a private repo.

mkdir ~/tmp
cd ~/tmp
git clone <git@gitlab.digg.se>:iam/apps/iam-id-proxy-service-api.git
cd id-service-api
cp -r  src/main/java/se/swedenconnect $LSP_PID_POC_HOME/auth/src/main/java/se/

And keep dependencies in build.gradle up to date.
