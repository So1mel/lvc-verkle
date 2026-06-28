#!/usr/bin/env bash
set -euo pipefail

sage reference/sage/sanity_check.sage
sage reference/sage/run_all_tests.sage
