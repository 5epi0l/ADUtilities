# Resurrect
A powerful Active Directory tombstone recovery tool for finding and restoring deleted users and computers.


# Overview

Resurrect is a Python-based tool designed to interact with Active Directory's Deleted Objects container (tombstones) to recover accidentally or maliciously deleted users and computers. Built with penetration testers and system administrators in mind, it provides a simple CLI interface for AD object recovery operations.



# Features

## 🔐 Secure Authentication

- **LDAPS Support** - Secure LDAP over SSL/TLS (port 636)
- **Pass-The-Hash** - Authenticate using NTLM hashes without plaintext passwords



## 🔍 Object Discovery

- **Find Deleted Objects** - Search for tombstoned users and computers in AD
- **Detailed Information** - View object names, GUIDs, and original OUs



## ♻️ Object Restoration

- **Custom Target OU** - Specify a different OU for restoration
- **Smart DN Handling** - Automatically strips `\0ADEL:GUID` suffixes from deleted objects



## 🛡️ Error Handling

- Graceful exception handling for LDAP operations
- Clear, user-friendly error messages



# Installation

```shell
# Clone the repository
git clone https://github.com/5epi0l/ADUtilities.git
cd ADUtilities/Resurrect

# Install dependencies
pip3 install -r requirements.txt
```




# Usage

## Find Deleted Objects

```shell
# Find all deleted users and computers
python3 adtomb.py find --domain example.com --username admin \
  --password 'Password123!' --target 10.10.11.72 --ldaps



# Using Pass-The-Hash
python3 adtomb.py find --domain example.com --username admin \
  --hash '8846f7eaee8fb117ad06bdd830b7586c' \ 
  --target 10.10.11.72 --ldaps
```


## Restore Deleted Objects

```shell
python3 adtomb.py restore --domain example.com --username admin \
  --password 'Password123!' --target 10.10.11.72 --ldaps \
  --guid "f88369c8-86a2-4a7f-a56c-9c15edd7d1e3" \
  --ou "OU=IT,OU=Users,DC=example,DC=com"
  
  
  python3 adtomb.py restore --domain example.com --username admin \
  --hash '149e0ed1f84c8fd4ecb11a9c2ab7af2b' --target 10.10.11.72 --ldaps \
  --guid "f88369c8-86a2-4a7f-a56c-9c15edd7d1e3" \
  --ou "OU=IT,OU=Users,DC=example,DC=com"
```



# Example Output

## Find Command Output

<img width="1048" height="188" alt="image" src="https://github.com/user-attachments/assets/507b0da0-2585-4022-a8af-991319d4c0bb" />




## Restore Command Output

<img width="1137" height="168" alt="image" src="https://github.com/user-attachments/assets/11f19c53-d5b4-46ae-b4e7-ec658b2ef99d" />



# Security Considerations

- Always use LDAPS (`--ldaps`) when possible to encrypt traffic
- Be cautious with Pass-The-Hash credentials - they're as sensitive as passwords
- Restored objects retain their original SIDs and group memberships
- Review restored object permissions before putting back into production
- Audit all restore operations in sensitive environments




## Troubleshooting

### "Invalid credentials" Error

- Verify username and password are correct
- Check if account is locked or disabled

### "Could not find deleted object"

- Object may have exceeded tombstone lifetime and been purged
- Verify GUID or DN is correct
- Ensure you have permissions to view Deleted Objects

### "Restore failed"

- Verify you have sufficient permissions
- Check if target OU exists
- Ensure object name doesn't conflict with existing objects



## TODO

- [ ]  **Kerberos Support** - Add Kerberos authentication as an alternative to NTLM
- [ ]  Export deleted objects to JSON/CSV
- [ ]  Find objects by their sAMAccountName
- [ ] Automatic Restoration to OUs

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the WTFPL License - see the LICENSE file for details.

## Disclaimer

This tool is intended for authorized security testing and administrative purposes only. Ensure you have proper authorization before using this tool against any Active Directory environment. The authors are not responsible for any misuse or damage caused by this tool.


## Contact

- GitHub Issues: [Report bugs or request features](https://github.com/5epi0l/ADUtilities/Resurrect/issues)
- email : 5epi0l@proton.me
