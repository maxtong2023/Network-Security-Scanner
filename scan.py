# write a python program that takes a list of web domains as an input and ouputs a json dict with information about each domain
import time 
import sys
import json

input_file = sys.argv[1]
output_file = sys.argv[2]

with open(input_file, 'r') as f:
    domains = f.readlines()
 # domains now a list

domain_dict = {}

for domain in domains: 
    current_time = time.time()
    domain_dict[domain.strip()] = {
        'scan_time': current_time,
    }

    # is json object a dict? # yes. 
with open(output_file, 'w') as f:
    json.dump(domain_dict, f, sort_keys=True, indent=4)