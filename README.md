# Credential Wallet Issuer PoC

  [![REUSE](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.reuse.software%2Fstatus%2Fgithub.com%2Fdiggsweden%2Feudiw-wallet-issuer-poc&query=status&style=for-the-badge&label=REUSE)](https://api.reuse.software/info/github.com/diggsweden/eudiw-wallet-issuer-poc)
  [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/diggsweden/eudiw-wallet-issuer-poc/badge?style=for-the-badge)](https://scorecard.dev/viewer/?uri=github.com/diggsweden/eudiw-wallet-issuer-poc)
  [![Tag](https://img.shields.io/github/v/tag/diggsweden/eudiw-wallet-issuer-poc?style=for-the-badge&color=yellow)](https://github.com/diggsweden/eudiw-wallet-issuer-poc/tags)


This a PoC test library, and is currently under development. It should not be used by a third party in the current state. This might change in the future, but for now - consider this repository a Friday afternoon hack!

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
