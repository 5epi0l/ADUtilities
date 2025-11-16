# FixTime
# Author: x4c1s
# Date: 16/11/25
# License: WTFPL

import requests
import os
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-u", help="Target URL", required=True)

args = parser.parse_args()


def get_date():
    print("[*] Fetching time")
    try:
        r = requests.get(args.url + "/:5985/WSMAN")
        date_header = r.headers.get("Date")
        time = date_header.split()[4]
        if time:
            print("[*] time fetched: ", time)
            return time
        else:
            print("[-] Could not get remote time")
    except Exception as e:
        print("[*] An error has occured: ", e)

def set_date():
    time = get_date()
    try:
        print("[*] Syncing time")
        os.system("sudo timedatectl set-ntp off")
        os.system(f"sudo date -u --set {time}")
        print("[*] time Synced")
    except Exception as e:
        print("[-] An error has occured: ", e)


set_date()
