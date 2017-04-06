FROM alpine:latest
COPY flex /opt/spiffe/flex
COPY install-flex.sh /opt/spiffe/

VOLUME /var/lib/spiffe/flex

CMD ["/opt/spiffe/install-flex.sh"]
