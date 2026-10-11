#!/bin/sh
# Stand in for sandbox-exec's fixed -p <profile> prefix in native pipe tests.
shift 2
exec "$@"
