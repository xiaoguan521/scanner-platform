FROM debian:12.15-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; \
    chmod 0755 /usr/sbin/policy-rc.d; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        apache2 \
        mariadb-server \
        openssh-server \
        postgresql \
        python3 \
        redis-server \
        tomcat10; \
    rm -rf /var/lib/apt/lists/*; \
    rm -f /usr/sbin/policy-rc.d; \
    useradd --create-home --user-group --uid 10001 --shell /bin/sh scanner_ro; \
    install -d -m 0755 /run/sshd; \
    printf '%s\n' '<!doctype html><html><head><title>Scanner lab target</title></head><body><h1>Debian package scan target</h1></body></html>' > /var/www/html/index.html

COPY apache-version.conf /etc/apache2/conf-available/zz-scanner-lab-version.conf
COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /usr/local/sbin/scanner-lab-entrypoint

RUN a2enconf zz-scanner-lab-version \
    && chmod 0755 /usr/local/sbin/scanner-lab-entrypoint

EXPOSE 22 80

ENTRYPOINT ["/usr/local/sbin/scanner-lab-entrypoint"]
