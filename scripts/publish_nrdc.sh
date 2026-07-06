#!/usr/bin/env bash
#
# publish_nrdc.sh — publish the local NR-DC test state so a fresh
#   `git clone --recursive` of L25GC-plus + this branch can build and run
#   `bash ./test_nrdc_local.sh`.
#
# What it does, in order:
#   1) commits each submodule's local changes on branch $BRANCH and pushes it
#      to that submodule's existing (nycu-ucr) remote
#   2) adds free-ran-ue as a submodule (williamlin0518/free-ran-ue)
#   3) in the parent: stages third_party/, test_nrdc_local.sh, the bumped
#      submodule pointers and .gitmodules, commits and pushes on $BRANCH
#
# SAFETY: dry-run by default. Preview first:
#     bash scripts/publish_nrdc.sh
# Then execute for real (needs push access to the nycu-ucr submodule repos):
#     DRY_RUN=0 bash scripts/publish_nrdc.sh
#
set -u
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

BRANCH="${BRANCH:-nrdc-test}"
DRY_RUN="${DRY_RUN:-1}"
RAN_URL="${RAN_URL:-https://github.com/williamlin0518/free-ran-ue.git}"

# Submodules that carry local changes required for a clean build/run.
# (onvm-upf uses `git add -u` so its untracked subprojects/dpdk is NOT committed.)
SUBMODULES=(NFs/amf NFs/smf NFs/nrf NFs/nssf NFs/pcf NFs/udm NFs/udr NFs/ausf NFs/chf NFs/xio NFs/onvm-upf)

yel(){ printf '\033[0;33m%s\033[0m\n' "$*"; }
grn(){ printf '\033[0;32m%s\033[0m\n' "$*"; }
run(){
    if [[ "$DRY_RUN" == "1" ]]; then
        printf '  [dry-run] %s\n' "$*"
    else
        printf '  + %s\n' "$*"
        eval "$@"
    fi
}

[[ "$DRY_RUN" == "1" ]] && yel "=== DRY RUN (set DRY_RUN=0 to execute) ===" || yel "=== EXECUTING (branch: $BRANCH) ==="

# ---------------------------------------------------------------------------
# 1) submodules: commit local changes on $BRANCH and push
# ---------------------------------------------------------------------------
for sm in "${SUBMODULES[@]}"; do
    [[ -d "$sm/.git" || -f "$sm/.git" ]] || { yel "skip $sm (not a submodule checkout)"; continue; }
    if [[ -z "$(git -C "$sm" status --porcelain --untracked-files=no)" ]]; then
        yel "skip $sm (no tracked changes)"
        continue
    fi
    yel "-- $sm"
    run "git -C '$sm' checkout -B '$BRANCH'"
    run "git -C '$sm' add -u"
    run "git -C '$sm' commit -m 'nrdc local test: X-IO replace wiring + NR-DC fixes'"
    run "git -C '$sm' push -u origin '$BRANCH'"
    # bump the pointer in the parent index
    run "git add '$sm'"
done

# ---------------------------------------------------------------------------
# 2) add free-ran-ue as a submodule (RAN sim the test drives)
# ---------------------------------------------------------------------------
if git config -f .gitmodules --get submodule.free-ran-ue.url >/dev/null 2>&1; then
    yel "free-ran-ue already a submodule"
else
    yel "-- adding free-ran-ue submodule ($RAN_URL)"
    # dir already exists as a clone; --force reuses it and records its commit
    run "git submodule add --force '$RAN_URL' free-ran-ue"
    run "git add .gitmodules free-ran-ue"
fi

# ---------------------------------------------------------------------------
# 3) parent: vendor third_party/, add the test script, commit + push
# ---------------------------------------------------------------------------
yel "-- parent repo"
run "git checkout -B '$BRANCH'"
run "git add third_party test_nrdc_local.sh scripts/publish_nrdc.sh scripts/update_xio.sh"
# base configs the test stages from (safe: the script backs up + restores at runtime)
run "git add config/amfcfg.yaml config/smfcfg.yaml 2>/dev/null || true"
run "git commit -m 'nrdc local test: vendor third_party + RAN submodule, portable X-IO, env-safe test script'"
run "git push -u origin '$BRANCH'"

grn "done. A cloner then runs:"
grn "  git clone --recursive -b $BRANCH https://github.com/nycu-ucr/L25GC-plus"
grn "  cd L25GC-plus && ./scripts/setup.sh cn && bash ./test_nrdc_local.sh"
