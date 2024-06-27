import nmap
import subprocess
import requests

def run_nmap_scan(target_ip):
    nm = nmap.PortScanner()
    print(f"Scanning {target_ip} with Nmap...")
    nm.scan(target_ip, arguments='-sV -A -T4 -p- --script vuln')
    scan_results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                service = nm[host][proto][port]['name']
                version = nm[host][proto][port]['version']
                scan_results.append((port, service, version))
    return scan_results

def search_exploit_db(service, version):
    search_term = f"{service} {version}"
    print(f"Searching Exploit-DB for exploits for {search_term}...")
    try:
        result = subprocess.run(['searchsploit', search_term], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error running searchsploit: {str(e)}"

def search_nvd(service, version):
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={service} {version}"
    print(f"Searching NVD for exploits for {service} {version}...")
    try:
        response = requests.get(nvd_url)
        if response.status_code == 200:  # Korrektur hier: entferne die überflüssige Klammer
            return response.json()
        else:
            return f"Error fetching data from NVD: HTTP {response.status_code}"
    except Exception as e:
        return f"Error connecting to NVD: {str(e)}"

def run_dirbuster(target_ip):
    dirbuster_command = [
        'java', '-jar', 'DirBuster-1.0-RC1.jar', '-H', target_ip, '-u', 'directory-list-2.3-medium.txt',
        '-o', 'dirbuster_results.txt'
    ]
    print(f"Running DirBuster on {target_ip}...")
    try:
        result = subprocess.run(dirbuster_command, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error running DirBuster: {str(e)}"

def save_results_to_file(filename, results):
    with open(filename, 'w') as file:
        for result in results:
            file.write(result + "\n")

def read_results_from_file(filename):
    with open(filename, 'r') as file:
        lines = file.readlines()
    return lines

def execute_exploit(exploit_id):
    print(f"Executing exploit {exploit_id}...")
    try:
        result = subprocess.run(['searchsploit', '-m', exploit_id], capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error executing exploit {exploit_id}: {str(e)}")

def scan_and_search(target_ip):
    scan_results = run_nmap_scan(target_ip)
    all_results = []
    
    for port, service, version in scan_results:
        result_str = f"Port: {port}, Service: {service}, Version: {version}"
        print(result_str)
        all_results.append(result_str)
        
        exploits_db = search_exploit_db(service, version)
        all_results.append("Exploit-DB Results:")
        all_results.append(exploits_db)
        
        exploits_nvd = search_nvd(service, version)
        all_results.append("NVD Results:")
        if isinstance(exploits_nvd, dict):
            for item in exploits_nvd.get('result', {}).get('CVE_Items', []):
                cve_id = item['cve']['CVE_data_meta']['ID']
                description = item['cve']['description']['description_data'][0]['value']
                all_results.append(f"{cve_id}: {description}")
        else:
            all_results.append(exploits_nvd)
    
    dirbuster_results = run_dirbuster(target_ip)
    all_results.append("DirBuster Results:")
    all_results.append(dirbuster_results)

    save_results_to_file("scan_results.txt", all_results)
    print("Results saved to scan_results.txt")

def execute_exploits_from_file():
    results = read_results_from_file("scan_results.txt")
    exploits_section = False
    
    for line in results:
        if "Exploit-DB Results:" in line:
            exploits_section = True
            continue
        elif "NVD Results:" in line or "DirBuster Results:" in line:
            exploits_section = False
            continue
        
        if exploits_section and line.strip():
            exploit_id = line.split()[0]  # Annahme: Das Exploit-ID ist das erste Element in der Zeile
            execute_exploit(exploit_id)

def main_menu():
    while True:
        print("\nRnE - Reconnaissance and Exploit Tool")
        print("1. Run Nmap Scan and Search for Exploits")
        print("2. Execute Exploits from File")
        print("3. Exit")
        choice = input("Enter your choice: ")
        
        if choice == '1':
            target_ip = input("Enter the target IP address: ")
            scan_and_search(target_ip)
        elif choice == '2':
            execute_exploits_from_file()
        elif choice == '3':
            break
        else:
            print("Invalid choice. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main_menu()
