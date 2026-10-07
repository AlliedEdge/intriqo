#!/usr/bin/env bash
# Fixed, private profile used by the Intriqo demo wrappers.
# shellcheck shell=bash

export INTRIQO_LAB_PROFILE=demo
export INTRIQO_DEMO_ATTACKER_NAMESPACE="intriqo-attacker"
export INTRIQO_DEMO_VICTIM_NAMESPACE="intriqo-victim"
export INTRIQO_DEMO_SWITCH_NAMESPACE="intriqo-switch"
export INTRIQO_DEMO_MONITOR_NAMESPACE="intriqo-monitor"
export INTRIQO_DEMO_MONITOR_INTERFACE="tap-intriqo"
export INTRIQO_DEMO_BRIDGE="br-intriqo"
export INTRIQO_DEMO_STATE_FILE="${INTRIQO_DEMO_STATE_FILE:-/run/intriqo-demo-topology.json}"
