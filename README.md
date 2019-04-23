# Dashboard checker
requirements:
The tool has been tested with Python 3.6 and requires following modules:
- requests
- elasticsearch
 


1. Copy settings.py.sample as settings.py
2. Fill token
3. Fill dash_list and other fields (if it is required)

Usage:
- $ python3 dashboard_checker.py (default run, doesn't delete old annotations, default time window and tag is 'NO DATA')
- $ python3 dashboard_checker.py -c 86400 (deletes old annotation for last 24h (86400 seconds), default time window and tag is 'NO DATA')
- $ python3 dashboard_checker.py -d graphite (goes through only graphite datasource panels, default time window and tag is 'NO DATA')
- $ python3 dashboard_checker.py -t TAG (goes through all implemented datasources panels, create annotations with tag TAG)
- $ python3 dashboard_checker.py -i (dry run, test mode)