#! /bin/sh

# change owner of the possible volumes
chown -R 1001:1001 /var/acmeca
chown -R 1001:1001 /etc/acmeca

# sart acmeca as user 1001
su-exec 1001:1001 "$@"