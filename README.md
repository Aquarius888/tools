# Dashboard checker
Python requirements:
The tool has been tested with Python 3.6 (and 2.7, but 3.6 is recommended) and requires following modules:
- requests
- elasticsearch

## Usage with docker container
1. git clone https://github.com/Aquarius888/tools.git
2. Copy settings.py.sample as settings.py
2.1. Fill gaps (token, dash_list and other fields (if it is required))
3. Copy to the directory /etc/hosts
4. Build docker image (alpine, python3.6)
<br/>\# docker build --network=host -t dash-checker:latest .
5. Run container (see commands in Native usage section)
<br/>\#  docker run --rm -v /vagrant/local/dash-checker:/checker --network=host dash-checker dashboard_checker.py -h


### Native usage:
<br/> $ python3 dashboard_checker.py (default run, doesn't delete old annotations, default time window and tag is 'NO DATA')
<br/> $ python3 dashboard_checker.py -c 86400 (deletes old annotation for last 24h (86400 seconds), default time window and tag is 'NO DATA')
<br/> $ python3 dashboard_checker.py -d graphite (goes through only graphite datasource panels, default time window and tag is 'NO DATA')
<br/> $ python3 dashboard_checker.py -t TAG (goes through all implemented datasources panels, create annotations with tag TAG)
<br/> $ python3 dashboard_checker.py -i (dry run, test mode)