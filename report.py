import sys
import json
import texttable

def generate_report(input_file, output_file):
    with open(input_file, 'r') as f:
        data = json.load(f)

    total = len(data)
    counts = {
        "SSLv2": 0,
        "SSLv3": 0, 
        "TLSv1.0": 0, 
        "TLSv1.1": 0, 
        "TLSv1.2": 0, 
        "TLSv1.3": 0, 
        "plain_http": 0, 
        "https_redirect": 0, 
        "hsts": 0, 
        "ipv6": 0
        }
    
    root_ca_freq = {}
    server_freq = {}
    rtt_list = []
    output = ""

    for domain in data:
        info = data[domain]

        #Section 1 
        output += "\nDOMAIN: " + str(domain) + "\n"
        for key in info:
            output += str(key) + ": " + str(info[key]) + "\n"

        # Section 2
        if info.get("rtt"):
            rtt_list.append([domain, info["rtt"][0], info["rtt"][1]])

        # Section 3
        ca = info.get("root_ca")
        if ca:
            root_ca_freq[ca] = root_ca_freq.get(ca, 0) + 1

        server = info.get("http_server")
        if server:
            server_freq[server] = server_freq.get(server, 0) + 1

        for version in info.get("tls_versions", []):
            if version in counts:
                counts[version] += 1
        if info.get("insecure_http"):
            counts["plain_http"] += 1
        if info.get("redirect_to_https"):
            counts["https_redirect"] += 1
        if info.get("hsts"):
            counts["hsts"] += 1
        if info.get("ipv6_addresses"):
            counts["ipv6"] += 1

    def make_table(headers, rows):
        tt = texttable.Texttable()
        tt.add_rows([headers] + rows)
        return tt.draw() + "\n"

    # sort by min index
    rtt_list.sort(key=lambda x: x[1])
    ca_rows = sorted(root_ca_freq.items(), key=lambda x: x[1], reverse=True)
    srv_rows = sorted(server_freq.items(), key=lambda x: x[1], reverse=True)

    # Percentage Table
    perc_rows = []
    for key in counts:
        if total > 0:
            p = (counts[key] * 100.0) / total
        else:
            p = 0
        perc_rows.append([key, "{0:.1f}%".format(p)])

    with open(output_file, 'w') as f:
        f.write(output + "\n")
        f.write("RTT Ranges\n")
        f.write(make_table(["Domain", "Min", "Max"], rtt_list))
        f.write("\nRoot CA Popularity\n")
        f.write(make_table(["Root CA", "Count"], ca_rows))
        f.write("\nWeb Server Popularity\n")
        f.write(make_table(["Server", "Count"], srv_rows))
        f.write("\nFeature Support Percentages\n")
        f.write(make_table(["Feature", "Percentage"], perc_rows))

if __name__ == "__main__":
    generate_report(sys.argv[1], sys.argv[2])