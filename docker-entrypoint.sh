#!/bin/dumb-init /bin/sh
set -e

# Note above that we run dumb-init as PID 1 in order to reap zombie processes
# as well as forward signals to all processes in its session. Normally, sh
# wouldn't do either of these functions so we'd leak zombies as well as do
# unclean termination of all our sub-processes.

# If the user is trying to run virustotal directly with some arguments, then
# pass them to virustotal.
if [ "${1:0:1}" = '-' ]; then
    set -- virustotal "$@"
fi

# # Look for Vault subcommands.
# if [ "$1" = 'server' ]; then
#     shift
#     set -- vault server \
#         -config="$VAULT_CONFIG_DIR" \
#         -dev-root-token-id="$VAULT_DEV_ROOT_TOKEN_ID" \
#         -dev-listen-address="$VAULT_DEV_LISTEN_ADDRESS" \
#         "$@"
# elif [ "$1" = 'version' ]; then
#     # This needs a special case because there's no help output.
#     set -- vault "$@"
# elif vault --help "$1" 2>&1 | grep -q "vault $1"; then
#     # We can't use the return code to check for the existence of a subcommand, so
#     # we have to use grep to look for a pattern in the help output.
#     set -- vault "$@"
# fi

# If we are running virustotal, make sure it executes as the proper user.
if [ "$1" = 'virustotal' ]; then
    set -- gosu malice virustotal "$@"
fi

exec "$@"
