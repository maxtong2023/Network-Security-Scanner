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

    # Single pass to gather all statistics
    output_text = "--- PART 2 DATA ---\n"
    for domain in data:
        info = data[domain]
        
        # Section 1: Individual Listing
        output_text += f"\nDOMAIN: {domain}\n"
        for key in info:
            output_text += f"{key}: {info[key]}\n"

        # Section 2: RTT
        if info.get("rtt"):
            rtt_list.append([domain, info["rtt"][0], info["rtt"][1]])

        # Section 3: Popularity
        ca = info.get("root_ca")
        if ca:
            root_ca_freq[ca] = root_ca_freq.get(ca, 0) + 1
        
        srv = info.get("http_server")
        if srv:
            server_freq[srv] = server_freq.get(srv, 0) + 1

        # Section 4: Percentage counters
        for v in info.get("tls_versions", []):
            if v in counts: counts[v] += 1
        if info.get("insecure_http"): counts["plain_http"] += 1
        if info.get("redirect_to_https"): counts["https_redirect"] += 1
        if info.get("hsts"): counts["hsts"] += 1
        if info.get("ipv6_addresses"): counts["ipv6"] += 1

    # --- Table Helper Function ---
    def make_table(headers, rows):
        tt = texttable.Texttable()
        tt.add_rows([headers] + rows)
        return tt.draw() + "\n"

    # --- Prepare Tables ---
    # RTT Table: Sort by Min RTT (index 1)
    rtt_list.sort(key=lambda x: x[1])
    
    # Popularity Tables: Sort by Count (index 1) descending
    ca_rows = sorted(root_ca_freq.items(), key=lambda x: x[1], reverse=True)
    srv_rows = sorted(server_freq.items(), key=lambda x: x[1], reverse=True)

    # Percentage Table
    perc_rows = []
    for key in counts:
        p = (counts[key] / total) * 100 if total > 0 else 0
        perc_rows.append([key, f"{p:.1f}%"])

    # --- Write Results ---
    with open(output_file, 'w') as f:
        f.write(output_text + "\n")
        f.write("--- RTT RANGES (MIN TO MAX) ---\n")
        f.write(make_table(["Domain", "Min", "Max"], rtt_list))
        f.write("\n--- ROOT CA POPULARITY ---\n")
        f.write(make_table(["Root CA", "Count"], ca_rows))
        f.write("\n--- WEB SERVER POPULARITY ---\n")
        f.write(make_table(["Server", "Count"], srv_rows))
        f.write("\n--- FEATURE SUPPORT PERCENTAGES ---\n")
        f.write(make_table(["Feature", "Percentage"], perc_rows))

if __name__ == "__main__":
    generate_report(sys.argv[1], sys.argv[2])