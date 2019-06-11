#!/usr/bin/env bash

command="$@"
# adding additional cron job
echo $command | sed --regexp-extended 's/\\(.)/\1/g' | crontab -
# start cron daemon
crond 
# trap SIGINT and SIGTERM signals and gracefully exit
trap "echo \"stopping cron\"; kill \$!; exit" SIGINT SIGTERM
# show logs by $docker logs -f
touch /checker/log/dashboard_checker.log
tail -f /checker/log/dashboard_checker.log

