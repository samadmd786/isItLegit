#!/usr/bin/env bash
# Tear down everything deploy.sh created.
#   scripts/destroy.sh --profile <deployer-profile> [--region us-east-1]
set -euo pipefail
PROFILE=""; REGION="us-east-1"
while [[ $# -gt 0 ]]; do case "$1" in --profile) PROFILE="$2"; shift 2;; --region) REGION="$2"; shift 2;; *) exit 1;; esac; done
[[ -n "$PROFILE" ]] || { echo "--profile is required" >&2; exit 1; }
aws_() { aws --profile "$PROFILE" --region "$REGION" "$@"; }
ACCOUNT="$(aws_ sts get-caller-identity --query Account --output text)"
APP_ID="$(aws_ amplify list-apps --query "apps[?name=='isthislegit'].appId | [0]" --output text)"
[[ "$APP_ID" != "None" && -n "$APP_ID" ]] && aws_ amplify delete-app --app-id "$APP_ID" >/dev/null && echo "deleted Amplify app"
aws_ cloudformation delete-stack --stack-name isthislegit && aws_ cloudformation wait stack-delete-complete --stack-name isthislegit && echo "deleted stack"
aws_ s3 rb "s3://isthislegit-deploy-$ACCOUNT-$REGION" --force >/dev/null 2>&1 && echo "deleted deploy bucket" || true
