import xml.etree.ElementTree as ET

def parse_openvas_file(openvas_file):
    """Parses an OpenVAS XML file and returns a list of vulnerabilities with CPE information and a list of hosts."""
    try:
        tree = ET.parse(openvas_file)
    except ET.ParseError as e:
        raise Exception(f"Error: Failed to parse {openvas_file}: {e}")
    root = tree.getroot()
    vulnerabilities = []
    hosts = []
    for result in root.findall("report/results/result"):
        vulnerability = {}
        vulnerability["name"] = result.findtext("name")
        vulnerability["severity"] = result.findtext("severity")
        vulnerability["cpe"] = []
        for nvt in result.findall("NVT"):
            cpe = nvt.findtext("cpe")
            if cpe:
                vulnerability["cpe"].append(cpe)
        vulnerabilities.append(vulnerability)
    for host in root.findall("report/host"):
        hosts.append(host.findtext("hostname"))
    return vulnerabilities, hosts

def get_vulnerable_hosts(openvas_file, severity_threshold):
    """Gets a list of all the hosts that are vulnerable from an OpenVAS XML file. Only hosts that are vulnerable to vulnerabilities with a severity of at least the severity_threshold are returned."""
    vulnerabilities, all_hosts = parse_openvas_file(openvas_file)
    if vulnerabilities is None or all_hosts is None:
        return None
    vulnerable_hosts = [host for host in all_hosts if host in [vuln["name"] for vuln in vulnerabilities if vuln["severity"] >= severity_threshold]]
    return vulnerable_hosts

def write_vulnerable_hosts_to_xml(vulnerable_hosts, filename):
    """Writes a list of vulnerable hosts to an XML file."""
    if not os.path.isfile(filename):
        return
    with open(filename, "w") as f:
        f.write("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n")
        f.write("<vulnerable_hosts>\n")
        for host in vulnerable_hosts:
            f.write("<host>{}</host>\n".format(host))
        f.write("</vulnerable_hosts>\n")
        print(f"Vulnerable hosts written to {filename}")

if __name__ == "__main__":
    openvas_file = input("Enter the path to the OpenVAS XML file: ")
    
    # Define severity threshold options
    severity_thresholds = {
        1: "Low",
        2: "Medium",
        3: "High",
        4: "Critical"
    }
    
    print("Severity threshold options:")
    for threshold, level in severity_thresholds.items():
        print(f"{threshold}: {level}")
    
    severity_threshold = int(input("Enter the severity threshold: "))
    
    vulnerable_hosts = get_vulnerable_hosts(openvas_file, severity_threshold)
    if vulnerable_hosts is None:
        print("No vulnerable hosts found")
        return
    filename = input("Enter the path to the XML file: ")
    write_vulnerable_hosts_to_xml(vulnerable_hosts, filename)
