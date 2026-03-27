#!/bin/bash
# Fix elastic-agent manager hostname to point to Logstash
# Run after so-elastic-agent container starts
sleep 10
LOGSTASH_IP=$(docker inspect so-logstash --format "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" 2>/dev/null)
if [ -z "$LOGSTASH_IP" ]; then
    LOGSTASH_IP="172.17.1.29"
fi
docker exec so-elastic-agent sh -c "cp /etc/hosts /tmp/hfix && grep -v manager /tmp/hfix > /tmp/hfix2 && echo \"$LOGSTASH_IP manager\" >> /tmp/hfix2 && cp /tmp/hfix2 /etc/hosts" 2>/dev/null
docker exec so-elastic-agent elastic-agent restart 2>/dev/null
logger "fix-elastic-agent-hosts: Set manager to $LOGSTASH_IP"
