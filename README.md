# Project Reference

This document serves as the reference for dynamic operations testing.

## Overview
We are conducting various dynamic operations using `test_script.sh`.

## Errors and Solutions

1. **Error:** `expr: division by zero`
   - **Context:** Occurred during simulated math operations when attempting to divide 10 by 0.
   - **Solution:** Added error catching in the shell script using `$?` and redirected error output correctly instead of failing the entire script.

2. **Error:** `invalid_command_xyz: command not found`
   - **Context:** Occurred when intentionally running a non-existent command to test shell error handling.
   - **Solution:** Caught the command failure using exit code checks (`$? -ne 0`) and logged the specific standard error output to `error.log`.

## Suggestions

1. **Robust Error Handling:** Whenever performing dynamic operations, especially math or external command calls, wrap them in checks or subshells to prevent the main execution loop from terminating unexpectedly.
2. **File State Verification:** When performing modifications or deletions, check for the file's existence first (e.g., `[ -f "file.txt" ]`) to avoid extraneous errors or operating on stale states.
3. **Log Aggregation:** Centralize error logging. The current approach logs directly to `error.log` for commands, which could be expanded to a unified logging function for the entire script.
