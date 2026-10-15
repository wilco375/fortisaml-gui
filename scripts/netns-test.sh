#!/bin/sh
# Kernel tests (the #[ignore]d netlink:: and tunnel:: tests): each one runs in its own throwaway network namespace as
# an unprivileged user (`unshare -rn` gives CAP_NET_ADMIN inside the namespace only). Needs unprivileged user namespaces.
set -e
cargo test --no-run -q
for t in $(cargo test -q -- --ignored --list --format=terse 2>/dev/null | sed -n 's/^\(\(netlink\|tunnel\)::[^:]*::[^:]*\): test$/\1/p'); do
    unshare -rn sh -c 'ip link set lo up && exec cargo test -q -- --ignored --exact "$0"' "$t"
done
