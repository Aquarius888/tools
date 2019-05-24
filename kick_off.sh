#!/usr/bin/env bash

command="$@"

echo $command | sed --regexp-extended 's/\\(.)/\1/g' | crontab -

crond 

trap "echo \"stopping cron\"; kill \$!; exit" SIGINT SIGTERM

touch /checker/dashboard_checker.log
tail -f /checker/dashboard_checker.log 

