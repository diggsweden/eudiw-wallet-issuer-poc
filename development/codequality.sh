#!/usr/bin/env bash

# Run a code quality check

# bash strict mode - undefined vars, propagate pipefails
set -uo pipefail

declare -A EXITCODES=()
declare -A SUCCESS_MESSAGES=()

readonly RED=$'\e[31m'
readonly NC=$'\e[0m'
readonly GREEN=$'\e[32m'
readonly YELLOW=$'\e[0;33m'
readonly FAIL_EMOJI='\xf0\x9f\x98\xb1'
readonly HAPPY_EMOJI='\xf0\x9f\x98\x80'

#Terminal chars
readonly CHECKMARK=$'\xE2\x9C\x94'
readonly MISSING=$'\xE2\x9D\x8C'

#MAVEN OPTS
#readonly MAVEN_CLI_OPTS=(--batch-mode --no-transfer-progress --errors --fail-at-end -Dstyle.color=always -DinstallAtEnd=true -DdeployAtEnd=true)

# Determine container runtime
CONTAINER_RUNTIME=""

determine_container_runtime() {
  if command -v podman &>/dev/null; then
    CONTAINER_RUNTIME="podman"
  elif command -v docker &>/dev/null; then
    CONTAINER_RUNTIME="docker"
  else
    printf '%b Error:%b Neither podman https://podman.io/ nor docker https://docker.io/ is available in path/installed.\n' "${RED}" "${NC}" >&2
    exit 1
  fi
}

is_command_available() {
  local COMMAND="${1}"
  local INFO="${2}"

  if ! [ -x "$(command -v "${COMMAND}")" ]; then
    printf '%b Error:%b %s is not availble in path/installed.\n' "${RED}" "${NC}" "${COMMAND}" >&2
    printf 'See %s for more info about the command.\n' "${INFO}" >&2
    exit 1
  fi
}

print_header() {
  local HEADER="$1"
  printf '%b\n************ %s ***********%b\n\n' "${YELLOW}" "$HEADER" "${NC}"
}

store_exit_code() {
  declare -i STATUS="$1"
  local KEY="$2"
  local INVALID_MESSAGE="$3"
  local VALID_MESSAGE="$4"

  if [[ "${STATUS}" -ne 0 ]]; then
    EXITCODES["${KEY}"]="${INVALID_MESSAGE}"
  else
    SUCCESS_MESSAGES["${KEY}"]="${VALID_MESSAGE}"
  fi
}

lint() {
  export MEGALINTER_DEF_WORKSPACE='/repo'
  print_header 'LINTER HEALTH (MEGALINTER)'
  ${CONTAINER_RUNTIME} run --rm --volume "$(pwd)":/repo -e MEGALINTER_CONFIG='development/megalinter.yml' -e DEFAULT_WORKSPACE=${MEGALINTER_DEF_WORKSPACE} -e LOG_LEVEL=INFO ghcr.io/oxsecurity/megalinter-java:v8.3.0
  store_exit_code "$?" "Lint" "${MISSING} ${RED}Lint check failed, see logs (std out and/or ./megalinter-reports) and fix problems.${NC}\n" "${GREEN}${CHECKMARK}${CHECKMARK} Lint check passed${NC}\n"
  printf '\n\n'
}

commit() {
  local compareToBranch='main'
  local currentBranch
  currentBranch=$(git branch --show-current)
  print_header 'COMMIT HEALTH (CONFORM)'
  print_header 'COMMIT HEALTH (CONFORM)'

  if [[ "$(git rev-list --count ${compareToBranch}..)" == 0 ]]; then
    printf "%s" "${GREEN} No commits found in current branch: ${YELLOW}${currentBranch}${NC}, compared to: ${YELLOW}${compareToBranch}${NC} ${NC}"
    store_exit_code "$?" "Commit" "${MISSING} ${RED}Commit check count failed, see logs (std out) and fix problems.${NC}\n" "${YELLOW}${CHECKMARK}${CHECKMARK} Commit check skipped, no new commits found in current branch: ${YELLOW}${currentBranch}${NC}\n"
  else
    ${CONTAINER_RUNTIME} run --rm -i --volume "$(pwd)":/repo -w /repo ghcr.io/siderolabs/conform:v0.1.0-alpha.30-2-gfadbbb4 enforce --base-branch="${compareToBranch}"
    store_exit_code "$?" "Commit" "${MISSING} ${RED}Commit check failed, see logs (std out) and fix problems.${NC}\n" "${GREEN}${CHECKMARK}${CHECKMARK} Commit check passed${NC}\n"
  fi

  printf '\n\n'
}

# format() {
#   print_header 'FORMATTING (PRETTIER and EDITORCONFIG)'
#   mvn prettier:write "${MAVEN_CLI_OPTS[@]}" -Dcode-quality -DskipTests -Dprettier.nodePath="$(which node)" -Dprettier.npmPath="$(which npm)"
#   store_exit_code "$?" "Format" "${MISSING} ${RED}Format check failed, see logs (std out) and fix problems.${NC}\n" "${GREEN}${CHECKMARK}${CHECKMARK} Format check passed${NC}\n"
#   printf '\n\n'
# }

# coverage() {
#   print_header 'COVERAGE (JACOCO)'
#   mvn clean verify "${MAVEN_CLI_OPTS[@]}" -Dcoverage -Djacoco.fail=true
#   store_exit_code "$?" "Coverage" "${MISSING} ${RED}Coverage check failed, see logs (./target/jacoco-report/index.html) and fix problems.${NC}\n" "${GREEN}${CHECKMARK}${CHECKMARK} Coverage check passed${NC}\n"
#   printf '\n\n'
# }

check_exit_codes() {
  printf '%b********* CODE QUALITY RUN SUMMARY ******%b\n\n' "${YELLOW}" "${NC}"

  for key in "${!EXITCODES[@]}"; do
    printf '%b' "${EXITCODES[$key]}"
  done
  printf "\n"

  for key in "${!SUCCESS_MESSAGES[@]}"; do
    printf '%b' "${SUCCESS_MESSAGES[$key]}"
  done
  printf "\n"

  if [[ "${#EXITCODES[@]}" -gt 0 ]]; then
    printf '%s %b\n' "${RED}${#EXITCODES[@]} of the code quality checks failed!${NC}" "${FAIL_EMOJI}"
    exit 1
  else
    printf '%s%b\n' "${GREEN}${CHECKMARK} All code quality checks passed!${NC}" "${HAPPY_EMOJI}"
    exit 0
  fi
}

determine_container_runtime
is_command_available 'node' 'https://nodejs.org/'
is_command_available 'npm' 'https://nodejs.org/'
is_command_available 'sed' ''

lint
#format
commit
#coverage

check_exit_codes
