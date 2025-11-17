# Author: x4c1s
# LICENSE: WTFPL
# Date: 2025-11-17

#!/usr/bin/env python3

from ldap3 import Server, Connection, ALL, NTLM, BASE, MODIFY_DELETE, MODIFY_REPLACE
import argparse
import sys
from tabulate import tabulate
from ldap3.core.exceptions import (
    LDAPInvalidCredentialsResult,
    LDAPBindError,
    LDAPSocketOpenError,
    LDAPException
)


def find_deleted_objects(args):
    try:
        if args.target:
            print(f"[*] Connecting to {args.target}")
        elif args.dc:
            print(f"[*] Connecting to {args.dc}")
        dom = args.domain.split('.')[0]
        tld = args.domain.split('.')[1]
        if args.target:
            if args.ldaps:
                s = Server(host=args.target, port=636,use_ssl=True, get_info='ALL')
            else:
                s = Server(host=args.target, port=389, use_ssl=False, get_info='ALL')
        elif args.dc:
            if args.ldaps:
                s = Server(host=args.dc, port=636,use_ssl=True, get_info='ALL')
            else:
                s = Server(host=args.dc, port=389,use_ssl=False, get_info='ALL')
        else:
            print("[!] Please Specify either a DC or a target")
            sys.exit()
    
        if args.hash:
            if len(args.hash) == 32:
                try:
                    conn = Connection(s, user=f"{dom}\\{args.username}", password=f"aad3b435b51404eeaad3b435b51404ee:{args.hash}", auto_bind=True, authentication=NTLM, version=3, check_names=True, raise_exceptions=True)
                except LDAPInvalidCredentialsResult as e:
                    print("[!] Authentication failed: ", e)
                    sys.exit()

                except LDAPSocketOpenError as e:
                    print("[!] Unable to connect to the target: ",e)
                    sys.exit()
            elif len(args.hash) != 32:
                print("[!] Hash Length mismatch")
                sys.exit()
        elif args.password:
            try:
                conn = Connection(s, user=f"{dom}\\{args.username}", password=args.password, auto_bind=True, authentication=NTLM, version=3, check_names=True, raise_exceptions=True)
            except LDAPInvalidCredentialsResult as e:
                print("[!] Authentication failed: ", e)
                sys.exit()
            except LDAPSocketOpenError as e:
                print("[!] Unable to connect to the target: ", e)
                sys.exit()
        else:
            print("[!] Please Specify either a hash or a password")
            sys.exit()

        if not conn.bind():
            print("[!] Could not connect to the server")
            sys.exit()
        else:
            print("[*] Authentication successful")

        entry_list = conn.extend.standard.paged_search(
            search_base = f'CN=Deleted Objects,DC={args.domain.split(".")[0]},DC={args.domain.split(".")[1]}',
            search_filter = '(&(|(objectClass=User)(objectCategory=Computer))(isDeleted=TRUE))',
            search_scope = 'SUBTREE',
            attributes = ['cn', 'sAMAccountName', 'objectClass',  'lastKnownParent'],
            controls= [
                ('1.2.840.113556.1.4.417', True, None)
            ],
            paged_size = 5,
            generator=False
    )
        if not entry_list:
            print("[*] No deleted users found or your current user doesn't have the permissions to view them")
            sys.exit()
        else:
            print("[*] Deleted user(s) found\r\t")
            for entry in entry_list:
                attrs = entry.get('attributes')
                if not attrs:
                    continue
                guid = attrs.get('cn').split('\n')[1].split(':')[1]
                ou = attrs.get('lastKnownParent')
                sam = attrs.get('sAMAccountName')
                objectclass = attrs.get('objectClass')[3]
                data = [[sam, guid, ou, objectclass]]
        headers = ['username', 'GUID', 'OU', 'objectClass']
        print(tabulate(data, headers=headers, tablefmt='grid'))
    except Exception as e:
        print("[-] An error has occured", e)


def restore_deleted_objects(args):

    try:

        if args.target:
            print(f"[*] Connecting to {args.target}")
        elif args.dc:
            print(f"[*] Connecting to {args.dc}")
        dom = args.domain.split('.')[0]
        tld = args.domain.split('.')[1]
        if args.target:
            if args.ldaps:
                s = Server(host=args.target, port=636,use_ssl=True, get_info='ALL')
            else:
                s = Server(host=args.target, port=389, use_ssl=False, get_info='ALL')
        elif args.dc:
            if args.ldaps:
                s = Server(host=args.dc, port=636,use_ssl=True, get_info='ALL')
            else:
                s = Server(host=args.dc, port=389,use_ssl=False, get_info='ALL')
        else:
            print("[!] Please Specify either a DC or a target")
            sys.exit()
    
        if args.hash:
            if len(args.hash) == 32:
                try:
                    conn = Connection(s, user=f"{dom}\\{args.username}", password=f"aad3b435b51404eeaad3b435b51404ee:{args.hash}", auto_bind=True, authentication=NTLM, version=3, check_names=True, raise_exceptions=True)
                except LDAPInvalidCredentialsResult as e:
                    print("[!] Authentication failed: ", e)
                    sys.exit()

                except LDAPSocketOpenError as e:
                    print("[!] Unable to connect to the target: ",e)
                    sys.exit()
            elif len(args.hash) != 32:
                print("[-] Hash Length mismatch")
                sys.exit()
        elif args.password:
            try:
                conn = Connection(s, user=f"{dom}\\{args.username}", password=args.password, auto_bind=True, authentication=NTLM, version=3, check_names=True, raise_exceptions=True)
            except LDAPInvalidCredentialsResult as e:
                print("[!] Authentication failed: ", e)
                sys.exit()
            except LDAPSocketOpenError as e:
                print("[!] Unable to connect to the target: ", e)
                sys.exit()
        else:
            print("[!] Please Specify either a hash or a password")
            sys.exit()

        if not conn.bind():
            print("[-] Could not connect to the server")
            sys.exit()
        else:
            print("[*] Authentication successful")

        if args.guid:    
            entry_list = conn.extend.standard.paged_search(
            search_base = f'CN=Deleted Objects,DC={args.domain.split(".")[0]},DC={args.domain.split(".")[1]}',
            search_filter = f'(&(objectGuid={args.guid})(isDeleted=TRUE))',
            search_scope = 'SUBTREE',
            attributes = ['distinguishedName'],
            controls= [
                ('1.2.840.113556.1.4.417', True, None)
            ],
            paged_size = 5,
            generator=False
    )
            if not entry_list:
                print("[*] Could not find an object with the supplied GUID")
                sys.exit()
            else:
                for entry in entry_list:
                    attrs = entry.get('attributes')
                    if attrs:
                            dn = attrs.get('distinguishedName')
                            print(f"[*] Found Object : {dn}")
                            cn = dn.split(':')[0].split('\\')[0]
                            
                    else:
                            print("[!] Could not extract DN for the target object")

        new_dn = f"{cn},{args.ou}"


        try:
            changes = {
                'isDeleted': [(MODIFY_DELETE, [])],
                'distinguishedName': [(MODIFY_REPLACE, [new_dn])]

            }

            print("[*] Attempting to restore object")
            results = conn.modify(
                    dn,
                    changes,
                    controls=[
                        ('1.2.840.113556.1.4.417', True, None)
                    ]
                )
            if results:
                    print("[*] Object restored successfully")
                    print(f"[*] New DN: {new_dn}")
            else:
                print(f"[!] Could not restore object: {conn.result} ")
                print(f"[!] Error: {conn.last_error}")
        except Exception as e:
            print("[!] Error during restore operation: ", e)

    except Exception as e:
        print("[-] An error has occured", e)





def main():

    parser = argparse.ArgumentParser(
        description='Remotely find and restore TombStoned Users',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
# Find Deleted Users and Computers
python3 {sys.argv[0]} find --domain example.com --username admin --password password123 --target 10.10.11.70 

# Restore Objects to their OUs
python3 {sys.argv[0]} restore --domain example.com --username admin --password password123 --target 10.10.11.70 --guid f80369c8-96a2-4a7f-a56c-9c15edd7d1e3 --ou "OU=Staff,DC=evilcorp,DC=com"

# Pass-The-Hash Support
python3 resurrect.py find --domain example.com --username admin --ldaps --target 10.10.11.70 --hash 149e0ed1f84c8fd4ecb11a9c2ab7af2
            """
) 


    subparsers = parser.add_subparsers(
        title='commands',
        dest='command',
        help='Command to execute',
        metavar='{find,restore}'
    )

    def add_common_args(subparsers):
        subparsers.add_argument("--domain", help="Target Domain", required=True)
        subparsers.add_argument("--username", help="Username", required=True)
        subparsers.add_argument("--password", help="Password", required=False)
        subparsers.add_argument("--dc", help="Domain Controller", required=False)
        subparsers.add_argument("--target", help="Target", required=False)
        subparsers.add_argument("--ldaps", help="Force LDAP to authenticate over SSL", action="store_true", required=False)
        subparsers.add_argument("--hash", help="LM:NTLM hash", required=False)

    find_parser = subparsers.add_parser(
        'find',
        help='Search for Deleted Users and Computers in Active Directory'
    )

    restore_parser = subparsers.add_parser(
        'restore',
        help='Restore Deleted Objects to their respective OU'
    )
    add_common_args(find_parser)
    find_parser.set_defaults(func=find_deleted_objects)


    add_common_args(restore_parser)
    restore_parser.add_argument('--guid', required=True, help='GUID of the deleted object')
    restore_parser.add_argument('--ou', required=True, help='Target OU to restore to')
    restore_parser.set_defaults(func=restore_deleted_objects)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)

if __name__ == "__main__":
    main()


