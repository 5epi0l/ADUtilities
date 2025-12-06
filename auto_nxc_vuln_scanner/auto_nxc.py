import subprocess
import argparse 


VULNS = {
    'zerologon': (False, True),
    'printnightmare': (False, True),
    'ms17-010': (False, True),
    'smbghost': (False, True),
    'petitpotam': (False, True),
    'nopac': (True, True),
    'ntlm_reflection': (True, True),
    'spooler': (True, False),
}

def run_scan(target, user, passwd, domain, module):
    
    cmd = ['nxc', 'smb', target]
    if user:
        cmd += ['-u', user, '-p', passwd]
        if domain:
            cmd += ['-d', domain]
    else:
        cmd += ['-u', '', '-p', '']
    
    cmd += ['-M', module]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout + result.stderr
        print(output)
        return output
    except Exception as e:
        error_msg = f"Error scanning {module}: {str(e)}"
        print(error_msg)
        return error_msg

def main():
    parser = argparse.ArgumentParser(description='NXC Vulnerability Scanner')
    parser.add_argument('-t', '--target', required=True, help='Target IP')
    parser.add_argument('-u', '--username', default='', help='Username')
    parser.add_argument('-p', '--password', default='', help='Password')
    parser.add_argument('-d', '--domain', default='', help='Domain')
    args = parser.parse_args()
    
    print(f"\n[*] Scanning {args.target}\n")
    vulnerable = []
    safe = []
    
    for module, (needs_creds, is_critical) in VULNS.items():
        
        if needs_creds and not args.username:
            print(f"[!] Skipping {module} - needs credentials\n")
            continue
        
        print(f"[*] Checking {module}...")
        output = run_scan(args.target, args.username, args.password, args.domain, module)
        print(output)
        
        if 'VULNERABLE' in output.upper():
            vulnerable.append((module, is_critical))
        else:
            safe.append(module)
        
        print()
    
    
    print("=========================================================================================================================================================================================")
    if vulnerable:
        print(f"\n[!] FOUND {len(vulnerable)} VULNERABILITY(IES):\n")
        for mod, crit in vulnerable:
            tag = " [CRITICAL]" if crit else ""
            print(f"  - {mod}{tag}")
    else:
        print("\n[+] No vulnerabilities found")
    
    if safe:
        print("\n[+] NOT VULNERABLE:")
        for mod in safe:
            print(f"  - {mod}")
    
    print("==================================================================================================================================================================================================")

if __name__ == '__main__':
    main()
