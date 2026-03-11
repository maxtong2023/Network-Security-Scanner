# write a python program that takes a list of web domains as an input and ouputs a json dict with information about each domain
import time 
import sys
import json
import subprocess
import re
import requests
import socket
import maxminddb

input_file = sys.argv[1]
output_file = sys.argv[2]

public_dns_resolvers = [
    '208.67.222.222',
    '1.1.1.1',
    '8.8.8.8',
    '8.26.56.26',
    '9.9.9.9',
    '94.140.14.14',
    '185.228.168.9',
    '76.76.2.0',
    '76.76.19.19',
    '129.105.49.1',
    '74.82.42.42',
    '205.171.3.65',
    '193.110.81.0',
    '147.93.130.20',
    '51.158.108.203',
]

with open(input_file, 'r') as f:
    domains = f.readlines()
 # domains now a list

 
domain_dict = {}

def add_ipv4_and_ipv6(domain, atype):

    ips = set()

    for server in public_dns_resolvers:
        
        try:
            result = subprocess.check_output(["nslookup", "-type=" + atype, domain.strip(), server.strip()],
                timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            continue

        regex = ''

        if atype == 'A':
            regex = r'(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}'
        else:
            regex = r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'
        if "Non-authoritative answer:" in result:
            result = result.split("Non-authoritative answer:")[1]
        else:
            parts = result.split('\n\n', 1)
            result = parts[1] if len(parts) > 1 else result
        # i found this regex thing online on a website called ihateregex.io
        for match in re.finditer(regex, result):
            ips.add(match.group(0))
    return sorted(list(ips))

def add_HTTP(domain):
    result = {
        "http_server": None, 
        "insecure_http": False,
        "redirect_to_https": False, 
        "hsts": False,
    }

    try: 
        session = requests.Session()
        session.max_redirects = 10

        # port 80
        response = session.get("http://" + domain, timeout=5)
        result["insecure_http"] = True

        result["http_server"] = response.headers.get("Server", None)


        # redirect check 

        path= []
        for r in response.history: 
            path.append(r.url)
        path.append(response.url)

        for url in path: 
            if url[:8] == "https://":
                result["redirect_to_https"] = True

        if response.url[:8] == "https://":
            if "Strict-Transport-Security" in response.headers:
                result["hsts"] = True

        return result
    except (requests.exceptions.RequestException, requests.exceptions.TooManyRedirects) as e:
        print("error: " + str(e))
        pass
    return result
# git did not commit for som reason??
def add_TLS(domain):
    versions = []

    tls = {
        "SSLv2": "-ssl2",
        "SSLv3": "-ssl3",
        "TLSv1.0": "-tls1",
        "TLSv1.1": "-tls1_1",
        "TLSv1.2": "-tls1_2",
        "TLSv1.3": "-tls1_3",
    }

    for version, flag in tls.items():
        try: 
            subprocess.check_output(["openssl", "s_client", flag, "-connect", f"{domain}:443"], input= b'', timeout = 2, stderr=subprocess.STDOUT)
            versions.append(version)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            continue
    return versions

def add_root_ca(domain):
    try:
        output = subprocess.check_output(["openssl", "s_client", "-connect", f"{domain}:443"], input=b'', timeout=2, stderr=subprocess.STDOUT).decode("utf-8")

        matches = re.findall(r'depth=(\d+)\s+(.*)', output)
        if matches:
            best_depth = -1
            root_line = ''
            for d, line in matches:
                if int(d) > best_depth:
                    best_depth = int(d)
                    root_line = line
            o_match = re.search(r'O\s?=\s?([^,/\n]+)', root_line)
            if o_match:
                return o_match.group(1).strip().strip('"')

    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass
    
    return None

def add_rdns_names(ipv4_list):
    results = []

    for ip in ipv4_list:

        try:
            result = subprocess.check_output(["nslookup", "-type=PTR", ip], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            if 'name =' in result: 
                names = re.findall(r'name\s?=\s?([^\s\n]+)', result)
                for name in names: 
                    results.append(name.rstrip("."))
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            continue
    return results

def add_rtt(ipv4_list):

    rtts = []

    for ip in ipv4_list:
        for port in [22, 80, 443]:
            try:
                starttime = time.time()
                mysock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                mysock.settimeout(2)
                mysock.connect((ip, port))
                endtime = time.time()
                mysock.close()

                rtt = (endtime - starttime) * 1000
                rtts.append(rtt)
                break
                
            except socket.error:
                continue
    if not rtts: 
        return None
    else:
        return [int(min(rtts)), int(max(rtts))]

def add_geolocations(ipv4_list):
    locations = set()

    try:
        read = maxminddb.open_database('GeoLite2-City.mmdb')

        for ip in ipv4_list:

            data = read.get(ip)
            if not data:
                continue

            # documentation
            city = ''
            if 'city' in data:
                if 'names' in data['city']:
                    if 'en' in data['city']['names']:
                        city = data['city']['names']['en']
            country = ''
            if 'country' in data:
                if 'names' in data['country']:
                    if 'en' in data['country']['names']:
                        country = data['country']['names']['en']
            province = ''
            if data.get('subdivisions') and len(data['subdivisions']) > 0:
                first = data['subdivisions'][0]
                if 'names' in first and 'en' in first['names']:
                    province = first['names']['en']
            location = []
            if city:
                location.append(city)
            if province:
                location.append(province)
            if country:
                location.append(country)
            if location:
                locations.add(', '.join(location))
        read.close()
    except Exception as e:
        print("error: " + str(e))
        pass
    return sorted(locations)
        


    

# lots of domain name resolvers, check every one of them and return all the unique ones.  

for domain in domains:
    current_time = time.time()

    http_data = add_HTTP(domain.strip())
    ipv4_addresses = add_ipv4_and_ipv6(domain.strip(), 'A')
    domain_dict[domain.strip()] = {
        'scan_time': current_time,
        'ipv4_addresses': ipv4_addresses,
        'ipv6_addresses': add_ipv4_and_ipv6(domain.strip(), 'AAAA'),
        'http_server': http_data['http_server'],
        'insecure_http': http_data['insecure_http'],
        'redirect_to_https': http_data['redirect_to_https'],
        'hsts': http_data['hsts'],
        'tls_versions': add_TLS(domain.strip()),
        'root_ca': add_root_ca(domain.strip()),
        'rdns_names': add_rdns_names(ipv4_addresses),
        'rtt_range': add_rtt(ipv4_addresses),
        'geo_locations': add_geolocations(ipv4_addresses),

    }


    # is json object a dict? # yes. 
with open(output_file, 'w') as f:
    json.dump(domain_dict, f, sort_keys=True, indent=4)
#
# if required command line tool is missing, do not crash and just skip it

