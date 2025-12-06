# Auto NXC Scanner

One-command vulnerability scanner using NetExec. Checks 8 critical Windows/AD vulnerabilities.

## Quick Start

```bash
python3 auto_nxc.py -t 10.10.10.10                    # Basic scan
python3 auto_nxc.py -t 10.10.10.10 -u user -p pass -d domain.local  # Authenticated
```

## Scanned Vulnerabilities

- ✅ **Critical**: zerologon, printnightmare, ms17-010, smbghost, petitpotam, nopac, ntlm_reflection  
- 🔍 **Info**: spooler (service detection)

## Output

Clear results showing:
- Vulnerable services (marked CRITICAL)
- Non-vulnerable services
- Authentication requirements for each check

## Usage

```bash
python3 auto_nxc.py -t TARGET [-u USERNAME] [-p PASSWORD] [-d DOMAIN]
```

**Note**: Some checks require credentials. Use only on authorized systems.
