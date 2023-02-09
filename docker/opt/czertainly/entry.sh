#!/bin/sh

czertainlyHome="/opt/czertainly"
source ${czertainlyHome}/static-functions

log "INFO" "Launching the Keystore Entity Provider"
java $JAVA_OPTS -jar ./app.jar

#exec "$@"