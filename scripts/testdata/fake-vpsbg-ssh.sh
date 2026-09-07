#!/usr/bin/env bash
S=$FAKE_VPSBG_STATE
echo "ssh $*" >> "$S/log"
[[ "$(cat "$S/ssh")" == 1 ]]
