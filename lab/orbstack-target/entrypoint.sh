#!/bin/sh
set -eu

if [ ! -s /run/target-authorized-key ]; then
    echo "missing public key: create runtime/ssh/orbstack-target.pub first" >&2
    exit 1
fi

install -d -o scanner_ro -g scanner_ro -m 0700 /home/scanner_ro/.ssh
install -o scanner_ro -g scanner_ro -m 0600 \
    /run/target-authorized-key /home/scanner_ro/.ssh/authorized_keys

mkdir -p /run/sshd
ssh-keygen -A

# Keep the account usable for public-key authentication without storing or
# printing a reusable password. Password authentication is disabled in sshd.
random_password="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
printf 'scanner_ro:%s\n' "$random_password" | chpasswd
unset random_password

/usr/sbin/sshd -t
/usr/sbin/apache2ctl -D FOREGROUND &
apache_pid=$!
/usr/sbin/sshd -D -e &
sshd_pid=$!

stop_services() {
    kill "$apache_pid" "$sshd_pid" 2>/dev/null || true
    wait "$apache_pid" "$sshd_pid" 2>/dev/null || true
}

trap stop_services INT TERM
if wait "$sshd_pid"; then
    status=0
else
    status=$?
fi
stop_services
exit "$status"
