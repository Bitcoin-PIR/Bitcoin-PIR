#!/usr/bin/env bash
# Advisory CI summary: wait for every other workflow run GitHub created
# for $HEAD_SHA (event=pull_request) and report one green/red result.
#
# Driven by .github/workflows/ci-summary.yml. Because GitHub has already
# applied each workflow's own path filters when creating runs, the set of
# sibling runs for the head SHA IS the set of applicable lanes — no path
# mapping is duplicated here.
#
# Environment:
#   GH_TOKEN   token for gh api (actions: read)
#   REPO       owner/name
#   HEAD_SHA   PR head commit SHA
#   SELF_NAME  this workflow's name, excluded from the wait set
# Tunables: SETTLE_SECONDS (60), POLL_SECONDS (30), DEADLINE_SECONDS (4200).
#
# Exit 0: every sibling run completed with success/skipped/neutral.
# Exit 1: any run failed/cancelled/timed out, or the deadline passed.
set -euo pipefail

: "${GH_TOKEN:?}" "${REPO:?}" "${HEAD_SHA:?}" "${SELF_NAME:?}"
SETTLE_SECONDS="${SETTLE_SECONDS:-60}"
POLL_SECONDS="${POLL_SECONDS:-30}"
DEADLINE_SECONDS="${DEADLINE_SECONDS:-4200}"

# Give GitHub time to create all runs for the head SHA before the first
# poll, so a lane that starts slowly is not missed entirely.
sleep "$SETTLE_SECONDS"

start_epoch="$(date +%s)"

fetch_siblings() {
    gh api "repos/$REPO/actions/runs?event=pull_request&head_sha=$HEAD_SHA&per_page=100" \
        --jq '[.workflow_runs[] | {name, status, conclusion, html_url}]' \
      | jq --arg self "$SELF_NAME" '[ .[] | select(.name != $self) ]'
}

print_table() {
    jq -r '.[] | "\(.conclusion // .status)\t\(.name)\t\(.html_url)"' <<< "$1" \
      | sort
}

while :; do
    siblings="$(fetch_siblings)"

    failed="$(jq '[ .[] | select(.status == "completed"
        and (.conclusion | IN("success", "skipped", "neutral") | not)) ]' <<< "$siblings")"
    pending="$(jq '[ .[] | select(.status != "completed") ]' <<< "$siblings")"
    failed_count="$(jq 'length' <<< "$failed")"
    pending_count="$(jq 'length' <<< "$pending")"
    total_count="$(jq 'length' <<< "$siblings")"

    if [ "$failed_count" -gt 0 ]; then
        echo "FAILED — $failed_count of $total_count sibling workflow run(s) did not succeed:"
        print_table "$failed"
        echo
        echo "Full set:"
        print_table "$siblings"
        [ -n "${GITHUB_STEP_SUMMARY:-}" ] && {
            echo "## CI summary: FAILED"
            echo '```'
            print_table "$siblings"
            echo '```'
        } >> "$GITHUB_STEP_SUMMARY"
        exit 1
    fi

    if [ "$pending_count" -eq 0 ]; then
        echo "GREEN — all $total_count sibling workflow run(s) completed successfully:"
        print_table "$siblings"
        [ -n "${GITHUB_STEP_SUMMARY:-}" ] && {
            echo "## CI summary: all $total_count triggered workflows green"
            echo '```'
            print_table "$siblings"
            echo '```'
        } >> "$GITHUB_STEP_SUMMARY"
        exit 0
    fi

    now_epoch="$(date +%s)"
    if [ $(( now_epoch - start_epoch )) -ge "$DEADLINE_SECONDS" ]; then
        echo "TIMED OUT — $pending_count of $total_count sibling run(s) still pending after ${DEADLINE_SECONDS}s:"
        print_table "$pending"
        exit 1
    fi

    echo "waiting: $pending_count of $total_count sibling run(s) still pending ($(( now_epoch - start_epoch ))s elapsed)"
    sleep "$POLL_SECONDS"
done
