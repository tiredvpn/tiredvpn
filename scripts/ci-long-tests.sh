#!/usr/bin/env bash
# ci-long-tests.sh - the server tests too long for -short, run by name.
#
# The unit-test step of CI and of the release workflow runs
# go test -race -timeout 5m -short, and these tests skip under -short
# (longTest, or a Short check of their own): run with it, they took
# internal/server past 5 minutes, then left it too close to them. Every
# server test above about 5 s under -race is here. This script is their gate in both
# workflows. It runs them with -race and fails unless each one reports
# PASS - a test that skipped, or vanished from the list, fails it too.
set -euo pipefail

want=(
  TestAHungUpClientsLegEndsOnTheExitsDeadline
  TestEveryRelayPathKeepsASparseProxiedStream
  TestAPushOnlyPhoneKeepsItsRelayLeg
  TestAOneWayDownloadToAClientKeepsTheSession
  TestASteadyOneWayDownloadKeepsTheLeg
  TestADialRelayLetsItsLegGoWhenTheClientHangsUp
  TestADirectREALITYClientKeepsItsSessionOnASparseDownload
  TestAnOldClientOnASparseDownloadKeepsItsBridgeLeg
  TestAnOldClientOnASparseDownloadKeepsItsSinkLeg
  TestASparseDownloadThroughAProxyRelayKeepsItsLeg
  TestConfusionUnauthenticatedGetsNoRelay
  TestAnH2ProxySessionWithNothingDownStillEndsOnItsDeadline
  TestPollingFirstHeadHasDeadline
  TestAnIdlePollingSessionGetsNoUplinkKeepalive
  TestTheRelayKeepaliveIsOffTheClientsGrid
  TestARelayBridgeWritesUpAfterAQuietDownload
  TestRawDispatchUnauthenticatedGetsNoTunnel
  TestPollingIdleSessionStaysRegistered
  TestHTTP1UnauthenticatedGetsNoTunnel
  TestPlaintextH2RefusesUnboundToken
  TestUntaggedAndForeignFallbacksStillGoToTheDonor
  TestReplayedFallbackHelloGoesToTheDonor
  TestWeakRegistrySecretsAreSaidWithTheTag
)

log="${RUNNER_TEMP:-$(mktemp -d)}/long-tests.log"
echo "expecting PASS from ${#want[@]} tests"
set +e
go test -race ./internal/server/ -run "^($(IFS='|'; echo "${want[*]}"))\$" \
  -v -count=1 -timeout 20m 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}
set -e
if [ "$rc" -ne 0 ]; then
  echo "::error::long tests failed (exit $rc)"
  exit "$rc"
fi
bad=0
for t in "${want[@]}"; do
  if ! grep -qE -- "^--- PASS: ${t} \(" "$log"; then
    echo "::error::${t} did not report PASS"
    bad=1
  fi
done
exit "$bad"
