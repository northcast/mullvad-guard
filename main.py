import subprocess, os
import time
import re
from time import strftime, localtime
    
    
def name_and_login():
    result = subprocess.run(
        ["mullvad", "account", "get"],
        capture_output=True,
        text=True
        )
    
    lines = result.stdout.strip().splitlines()

    if len(lines) != 3:
        token = open("token", "r").read()

        subprocess.run(["mullvad", "account", "logout"],  stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT); subprocess.run(["mullvad", "account", "login", token],  stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        time.sleep(2)
        subprocess.run(["mullvad", "connect"], capture_output=False, text=False)
        time.sleep(1)
        return name_and_login()
        
    elif len(lines) == 3:
        local_device = lines[2].replace("Device name:", "")
        local_device = local_device.strip()
    else:
        return print("Unknown Error")


    open("logs", "a").writelines(f"[{strftime('%Y-%m-%d %H:%M:%S', localtime(time.time()))}] Local Device Update: {local_device}\n")
    return local_device


def get_whitelist():
    whitelist = open("whitelist", "r").read()    

    return whitelist.splitlines()

def loop(my_device):
    status = False
    whitelist = get_whitelist()

    result = subprocess.run(
        ["mullvad", "account", "list-devices"],
        capture_output=True,
        text=True
        )
    lines = result.stdout.strip().splitlines()

    for i in lines:
        if i == my_device:
            status = True
            continue
        elif i == "Devices on the account:":
            continue
        elif i in whitelist:
            continue
        else:
            open("logs", "a").writelines(f"[{strftime('%Y-%m-%d %H:%M:%S', localtime(time.time()))}] Remove Device: {i}\n")

            subprocess.run(
                ["mullvad", "account", "revoke-device", i],
                capture_output=False,
                text=False
                )

    
    return status


def main():
    local_account = name_and_login()

    while True:
        y = loop(my_device=local_account)
        if y == True:
            time.sleep(60)
            continue
        else:
            local_account = name_and_login()


if __name__ == "__main__":
    main()