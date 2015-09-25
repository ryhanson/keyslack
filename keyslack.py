import time
import json
import sys
import os
import threading
import subprocess
import urllib2
from collections import namedtuple
from websocket import create_connection
from ssl import SSLError
from slacker import Slacker, Error as SlackError


class SlackConnectionError(Exception):
    pass


class Response(object):
    def __init__(self, raw):
        self.raw = raw
        self.obj = self.json2obj(raw)

    @staticmethod
    def _json_object_hook(d):
        return namedtuple('obj', d.keys())(*d.values())

    def json2obj(self, data):
        return json.loads(data, object_hook=self._json_object_hook)


class KeySlack(object):
    def __init__(self, token):
        self.client = Slacker(token)
        self.socket = None
        self.socket_login = None
        self.socket_reading = False
        self.my = self.me()
        self.my_keybase = self.find_keybase(self.me())
        self.my_group = None
        self.groups = self.get_groups()
        self.input_thread = threading.Thread(target=self.get_input, args=())
        self.watch_thread = threading.Thread(target=self.group_watcher, args=())

        cwd = os.getcwd()
        if not os.path.exists(cwd + '/outbox'):
            os.mkdir(cwd + '/outbox', 0755)
        self.outbox = cwd + '/outbox/'

        if not os.path.exists(cwd + '/inbox'):
            os.mkdir(cwd + '/inbox', 0755)
        self.inbox = cwd + '/inbox/'

        if not os.path.exists(cwd + '/decryptbox'):
            os.mkdir(cwd + '/decryptbox', 0755)
        self.decryptbox = cwd + '/decryptbox/'

    @staticmethod
    def print_help():
        print "Usage: encrypt their_keybase_username [-m message] [-f file]"
        print "Examples: encrypt ryhanson -m \"You are so awesome dude\""
        print "          encrypt ryhanson -f certs.zip"

    @staticmethod
    def find_keybase(user):
        kb_str = "#keybase:"

        if hasattr(user.profile, 'title') and user.profile.title != -1:
            return user.profile.title[user.profile.title.find(kb_str) + len(kb_str):]
        elif hasattr(user.profile, 'phone') and user.profile.phone.find(kb_str) != -1:
            return user.profile.phone[user.profile.phone.find(kb_str) + len(kb_str):]
        elif hasattr(user.profile, 'skype') and user.profile.skype.find(kb_str) != -1:
            return user.profile.skype[user.profile.skype.find(kb_str) + len(kb_str):]
        else:
            return None

    def connect_realtime(self):
        if not self.socket:
            self.socket_login = Response(keyslack.client.rtm.start().raw).obj
            if self.socket_login.ok:
                try:
                    self.socket = create_connection(self.socket_login.url)
                    self.socket.sock.setblocking(0)
                    return self.socket
                except:
                    raise SlackConnectionError
        else:
            return self.socket

    def read_socket(self):
        data = ""
        while True:
            try:
                data += "{}\n".format(self.socket.recv())
            except SSLError as e:
                if e.errno == 2:
                    return ''
                raise
            return data.rstrip()

    def read_events(self):
        if self.socket:
            while True:
                json_data = self.read_socket()

                data = []
                events = []
                if json_data != '':
                    for d in json_data.split('\n'):
                        data.append(d)

                for item in data:
                    events.append(Response(item).obj)

                return events
        else:
            raise SlackConnectionError

    def auth_info(self):
        return Response(self.client.auth.test().raw).obj

    def me(self):
        return self.find_user(self.auth_info().user_id)

    def get_groups(self):
        return Response(self.client.groups.list().raw).obj.groups

    def find_group(self, name):
        return next((x for x in self.get_groups() if x.name == name), None)

    def find_user(self, uid):
        return Response(self.client.users.info(uid).raw).obj.user

    def encrypt(self, keybase_user, option, plain_msg):
        keybase_args = ['keybase', 'encrypt', '-s', keybase_user]
        plain_msg = plain_msg.strip('\'')
        plain_msg = plain_msg.strip('"')

        if option == '-m':
            keybase_args.append('-m')
            keybase_args.append(plain_msg)
            outfilename = "{0}-{1}.asc".format(time.strftime("%Y%m%d-%H%M%S"), self.my.name)
        elif option == '-f':
            keybase_args.append(plain_msg)
            outfilename = "{0}.asc".format(plain_msg)
        else:
            print "[!] Invalid option %s" % option
            return

        keybase_args.append('-o')
        keybase_args.append(self.outbox + outfilename)

        if option == '-m':
            print "[-] Encrypting your message..."
        elif option == '-f':
            print "[-] Encrypting your file..."

        encrypt_proc = subprocess.Popen(keybase_args, stdout=subprocess.PIPE)
        encrypt_proc.stdout.read()

        if os.path.exists(self.outbox + outfilename):
            print "[+] Encryption successful!"
            print "[+] PGP Message stored: " + self.outbox + outfilename

            upload_resp = self.client.files.upload(self.outbox + outfilename,
                                                   channels=self.my_group.id,
                                                   filename=outfilename,
                                                   title="PGP MSG for: " + keybase_user)

            if upload_resp.successful:
                print "[+] PGP MSG upload successfully!"
            else:
                print "[!] PGP MSG upload failed!"
        else:
            print "[!] Something went wrong :("

    def watch_group(self, group):
        self.my_group = group
        self.watch_thread.daemon = True
        self.watch_thread.start()

    def watch_input(self):
        # self.input_thread.daemon = True
        self.input_thread.start()

    def get_input(self):
        self.print_help()
        while True:
            if self.socket_reading:
                command = raw_input("KeySlack # ")
                if not command:
                    continue
                if command.startswith("encrypt"):
                    args = command.split(' ', 3)

                    if len(args) != 4:
                        self.print_help()
                    else:
                        keybase_user = args[1]
                        option = args[2]
                        plain_msg = args[3]
                        self.encrypt(keybase_user, option, plain_msg)

                    continue
                elif command == "help":
                    self.print_help()
                elif command != "exit":
                    print "Invalid command. Type 'help' for usage or 'exit' to quit."
                    continue
                else:
                    sys.exit('[!] Quiting now...')

    def group_watcher(self):
        if self.my_group is None:
            print "[!] Must specify slack group to watch..."
            return

        if keyslack.connect_realtime():
            while True:
                for event in keyslack.read_events():
                    if event.type == 'hello':
                        self.socket_reading = True
                    elif event.type == 'error':
                        self.socket_reading = False
                        break
                    elif event.type == 'file_created':
                        if self.is_pgp_for_me(event.file):
                            self.socket_reading = False
                            self.download_file(event.file.url_download, event.file.name)
                            self.decrypt(event.file.name)
                            self.socket_reading = True

            time.sleep(1)
        else:
            sys.exit("[!] Socket connection failed!")

    def is_pgp_for_me(self, in_file):
        is_pgp = in_file.title.startswith("PGP MSG")
        pgp_recipient = in_file.title.replace("PGP MSG for: ", "")

        return is_pgp and pgp_recipient == self.my_keybase

    def download_file(self, url, filename):
        contents = urllib2.urlopen(url)
        pgp_file = open(self.inbox + filename, 'w')
        pgp_file.write(contents.read())
        pgp_file.close()

    def decrypt(self, filename):
        decrypt_location = self.decryptbox + filename.replace('.asc', '')
        decrypt_args = ['keybase', 'decrypt', self.inbox + filename,
                        '-o', decrypt_location]

        decrypt_proc = subprocess.Popen(decrypt_args, stdout=subprocess.PIPE)
        decrypt_proc.stdout.read()

        if os.path.exists(decrypt_location):
            print "[+] Decryption successful!"
            print "[+] File stored: " + decrypt_location
        else:
            print "[!] Decryption failed..."


if not os.path.exists('token.txt'):
    print "Let's send encrypted shit through Slack!!"
    print "1. Make sure you have your Keybase CLI installed and setup."
    print "2. Update your Slack profile with #keybase:[keybase_username] at the end of your: title, skype, or phone."
    print "   Example: #keybase:ryhanson"
    print "3. Get a Slack auth token at the bottom of: https://api.slack.com/web"
    print "4. Enter the name of the private group to watch for PGP Messages.\n"

auth_filename = 'token.txt'
if os.path.exists(auth_filename):
    auth_file = open(auth_filename, 'r')
    auth_token = auth_file.read()
    auth_file.close()
else:
    auth_token = raw_input("Enter your Slack token: ")
    auth_file = open(auth_filename, 'w')
    auth_file.write(auth_token)
    auth_file.close()

group_filename = 'group.txt'
if os.path.exists(group_filename):
    group_file = open(group_filename, 'r')
    group_name = group_file.read()
    group_file.close()
else:
    group_name = raw_input("Enter your Slack Group: ")
    group_file = open(group_filename, 'w')
    group_file.write(group_name)
    group_file.close()

print "[-] Authenticating with your auth_token..."

keyslack = KeySlack(auth_token)
try:
    keyslack.auth_info()
except SlackError, error:
    sys.exit("[!] Authentication failed: %s" % error.message)

print "[+] Authenticated as %s" % keyslack.my.name
print "[-] Looking for your Keybase username..."

if keyslack.find_keybase(keyslack.my) is None:
    print "[!] No Keybase username found in your profile."
    print "[-] Add #keybase:[keybase_username] at the end of your: title, skype, or phone."
    sys.exit()

print "[+] Found your keybase username: %s" % keyslack.my_keybase
print "[-] Checking to see if you're a member of " + group_name + "..."

keygroup = keyslack.find_group(group_name)
if keygroup is None:
    sys.exit("[!] You aren't a member of the '" + group_name + "' group...")

print "[+] You are a member of " + keygroup.name + "!"
print "[-] Finding members of " + keygroup.name + "..."

# This loop could be used to send a message per slack user with keybase enabled
for member_uid in keygroup.members:
    member = keyslack.find_user(member_uid)
    print "[+] Found: " + member.real_name + " (" + member.name + ")"
    if keyslack.find_keybase(member) is not None:
        print "[+] " + member.real_name + "'s keybase username found: " + keyslack.find_keybase(member)

print "[-] Starting thread to watch " + keygroup.name + " for PGP messages...\n"

keyslack.watch_group(keygroup)
keyslack.watch_input()
