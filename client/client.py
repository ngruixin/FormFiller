import json
import requests
import os

import sys
sys.path.insert(0, '../Util')
import CryptUtils
import Filler


class client():

    user = None             # current session username logged in
    key = None              # private key of current user
    cookie = None           # auth cookie of current user, used by server to ensure user is authorized to perform action 
    session = None          # initialized session
    
    def __init__( self, host ):
        self.host = host
        # start session that does not verify ssl certificate (localhost self-signed)
        # remove if not localhost server
        requests.packages.urllib3.disable_warnings()
        self.session = requests.Session()
        self.session.verify = False

    def isAuthenticated(self):
        '''
        Verifies if a user is currently logged into the system
        '''
        return self.key is not None and self.user is not None and self.cookie is not None

    def fill(self, pdf, out_file):
        '''
        Fills out @pdf form fields with the data of the current user.
        Output into @outfile
        '''
        print("Filling form: " + pdf)
        if (self.isAuthenticated()): 
            r = self.session.get(self.host+"/"+self.user)
            if (r.text == ""):
                print("User has no data to fill")
                return
            plaintext = CryptUtils.decrypt(r.text, self.key)
            data = json.loads(plaintext)
            try: 
                Filler.fill(data, pdf, out_file)
                print("Successfully filled in " + out_file)
            except (Exception) as e:
                print(e)
                print("Please input a valid pdf")
        else: 
            print("No user logged in")

    def login(self, username, password):
        '''
        POST /login {username: @username, password: @password}
        Attempts to log into the system with @username and @password. Hashes 
        the password with sha256 before sending to the server to ensure that 
        the server never knows the plaintext password of the user (which is 
        used to generate the secret key of the user).
        '''
        auth = {'username': username, 'password': CryptUtils.sha256(password)}
        json_data = json.dumps(auth)
        headers = {"content-length": str(len(json_data))}
        r = self.session.post(self.host+"/login", data=json_data, headers=headers)
        if (r.status_code == 200):
            print("Welcome " + username)
            data = r.text
            salt = data.split('=')[1].encode()
            self.user = username
            self.key = CryptUtils.genKey(password, salt)
            self.cookie = r.headers['Set-Cookie']
        else: 
            print("Invalid username or password")

    def addField(self, key, value):
        '''
        data = GET /@username 
        POST /@username data add { key : value }
        Adds the @key @value pair to the current user details stored in the db. 
        Gets the currently stored details, decrypts it using the user's secret 
        key, adds the new key-value pair, encrypts it, then sends it back to the 
        db. Details (eg pair 'first name' 'john') are used to fill forms. 
        Cookie used to check authorization by server. 
        '''
        if (self.isAuthenticated()):
            header = {"Cookie": self.cookie}
            r = self.session.get(self.host+"/"+self.user, headers=header)
            if (r.status_code == 200):
                data = {}
                if r.text:
                    dec_data = CryptUtils.decrypt(r.text, self.key)
                    data = json.loads(dec_data)
                data[key] = value
                json_data = json.dumps(data)
                enc_data = CryptUtils.encrypt(json_data, self.key)
                headers = {"content-length": str(len(enc_data)), "Cookie": self.cookie}
                r = self.session.post(self.host+"/" + self.user, data=enc_data, headers=headers)
                print(r.text)
            else: 
                print("Adding field failed, please try again")
        else:
            print("No user logged in")
    
    def getFields(self):
        '''
        GET /@username
        Gets all details of the current logged-in user and decrypts the fields. 
        Cookie used to check authorization by server. 
        '''
        if (self.isAuthenticated()):
            header = {"Cookie": self.cookie}
            r = self.session.get(self.host+"/"+self.user, headers=header)
            if r.text:
                dec_data = CryptUtils.decrypt(r.text, self.key)
                print(dec_data)
            else:
                print(self.user + " has no data")
        else:
            print("No user logged in")

    def deleteData(self):
        '''
        Deletes all details of the currently logged-in user. Cookie used to check 
        authorization by server. 
        '''
        if (self.isAuthenticated()):
            data = ""
            headers = {"content-length": str(len(data)), "Cookie": self.cookie}
            r = self.session.post(self.host+"/" + self.user, data=data, headers=headers)
            print(r.text)
        else:
            print("No user logged in")

    def addUser(self, username, pwd):
        '''
        POST /adduser {username: @username, hash_pwd: sha256(@pwd), key_salt: salt}
        Generates salt (for generation of secret key), requests for a new user to be  
        added to the system. @pwd is hashed (sha256) before it is sent to the server. 
        '''
        hash_pwd = CryptUtils.sha256(pwd)
        key_salt = CryptUtils.genSalt()
        #print("key salt: " + key_salt)
        #print("hpwd:" + hash_pwd)
        data = {"username": username, "hash_pwd": hash_pwd, "key_salt": key_salt}
        json_data = json.dumps(data)
        headers = {"content-length": str(len(json_data))}
        r = self.session.post(self.host+"/adduser", data=json_data, headers=headers)
        print(r.text)

    def printUsage(self):
        usage = "\nList of commands supported: \n\n" + \
                "/adduser [username] [password]:    Adds a user to the current system\n\n" + \
                "/login [username] [password]:      Attempts to login with username and password\n\n" + \
                "/getdata                           Gets all data of the currently logged-in user\n\n" + \
                "/deldata                           Deletes all data of the currently logged-in user\n\n" + \
                "/add \"[key]\" \"[value]\"             Adds the key-value pair to the data of the user,\n\n" + \
                "                                   which is used to fill in form fields\n\n" + \
                "                                   e.g. /add \"First name\" \"John\"\n\n" + \
                "/fill [input.pdf] [output.pdf]     Fills @input.pdf with the user's data and generates\n\n" + \
                "                                   @output.pdf with all possible form fields filled\n\n" + \
                "                                   Input and output may be paths\n\n" + \
                "/help                              Prints help message\n" 
        print(usage)

    def parse(self, stdin):
        '''
        Parses the command line input of the user 
        '''
        try: 
            if (stdin.strip() == "/getdata"):
                self.getFields()
                return
            elif (stdin.strip() == "/deldata"):
                self.deleteData()
                return
            elif (stdin.strip() == "/help"):
                self.printUsage()
                return

            idx = stdin.index(" ")
            cmd = stdin[:idx].lower()
            arg = stdin[idx+1:]

            if (cmd == "/fill"): 
                idx = arg.index(" ")
                pdf = arg[:idx]
                out_file = arg[idx+1:]
                self.fill(pdf, out_file)

            elif (cmd == "/add"):
                # eg /add "First Name" "John" (require quotation marks!!)
                idx_first = arg.index("\"")
                idx_sec = arg.find("\"", idx_first+1)
                key = arg[idx_first+1:idx_sec]
                idx_third = arg.find("\"", idx_sec+1)
                idx_forth = arg.find("\"", idx_third+1)
                if (idx_sec == -1 or idx_third == -1 or idx_forth == -1):
                    raise Exception()
                value = arg[idx_third+1:idx_forth]
                self.addField(key, value)

            elif (cmd == "/adduser"):
                idx = arg.index(" ")
                username = arg[:idx]
                password = arg[idx+1:]
                self.addUser(username, password)

            elif (cmd == "/login"):
                idx = arg.index(" ")
                username = arg[:idx]
                password = arg[idx+1:]
                self.login(username, password)

            else: 
                raise Exception()
        except (Exception) as e:
            print(e)
            print("Invalid command")

def run(ip, port): 
    host = "https://" + ip + ":" + port
    c = client(host)
    while (True):
        stdin = input("> ")
        c.parse(stdin)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 client.py [server ip] [server port]")
        os._exit(0)
    if len(sys.argv) == 3:
        ip = sys.argv[1] 
        port = sys.argv[2]
        run(ip, port)