#!/usr/bin/env python
from plumbum import local, cli, FG, BG, TF,TEE, ProcessExecutionError, colors
from plumbum.cmd import cat,grep,sed,ls,echo
from contextlib import contextmanager
import os
import sys
import re
import pendulum
'''python --version
Tested on Ubuntu 18.04 with Python 2.7.15
sudo apt install python-pip
pip install pendulum
pip install plumbum
set env variable in .bashrc file using export, here user=ton
export FIFTPATH=/home/ton/ton-sources/ton/crypto/fift/lib:/home/ton/ton-sources/ton/crypto/smartcont'''
FIFTPATH = local.env["FIFTPATH"]

#you can connect to external interfaces IP:9300 or localhost
CONNECT_STR_LITE_CLIENT = "127.0.0.1:9300"
CONNECT_STR_ENGINE_CONSOLE = "127.0.0.1:9200"

# wallet address = -1:36c519c430b548944972aed18cb5c94dff832fc4324b7340bb50cfcfc440e485
# Bounceable address (for later access)
WALLET_ADDR = "kf82xRnEMLVIlElyrtGMtclN_4MvxDJLc0C7UM_PxEDkhV-B"

# Wallet filename  wallet_03_10_2019.addr
# in basename - without ext
WALLET_FILENAME = "wallet_03_10_2019"

# wallet seqno
CURRENT_SEQNO = ""

ELECTOR_ADDR = ""

# ACTIVE_ELECTION_ID = ""
START_ELECTION_PERIOD = ""

# START_ELECTION_PERIOD + 1 DAY
END_ELECTION_PERIOD = 0 

#maximal stake factor with respect to the minimal stake 176947/65536 = 2.7
MAX_FACTOR = "5"

#Stake amount + extra 1 GRAM to cover fee
STAKE = "100001."

# newkey
VAR_A = ""

# exportpub A => got public key
VAR_B = ""

# newkey for ADNL
VAR_C = ""

# validator-elect-req.fif
# loooooong string in HEX 
# string to sign
VAR_D = ""

# engine-console
# sign A D
# got signature
VAR_E = ""

#Check path and str type
#we use last.log in DIR and
# TODO: log.log + "success" file and .boc files in each ELECTION_DIR directory
#ELECTION_DIR =""


#Assign executables found in current dir
DIR = local.path(__file__) / '..'
fift = local[DIR / 'fift']
liteclient = local[DIR / 'lite-client']
validatorengine = local[DIR / 'validator-engine-console']

def check_env():
    '''check env for FIFTPATH'''
    #print("TODO")
    pass

def get_elector_address():
    '''get_elector_address then parse it'''
    global ELECTOR_ADDR
    print("Getting ELECTOR_ADDR...")
    try:
        #lite-client -a IP:9300 -p liteserver.pub -rc ' getconfig 1'
        # change .run to  & TEE(retcode = None) to execute command and output to stdout
        chain = liteclient ["-a", CONNECT_STR_LITE_CLIENT, "-p", "liteserver.pub", "-rc", 'getconfig 1'].run(retcode=None)
        now = pendulum.now(tz='Europe/Kiev')
        (echo[now.to_datetime_string()] >> "last.log")()
        (echo[chain[1:3]] >> "last.log")()
        x = re.search(r"elector_addr:x[0-9a-fA-F]{64}", chain[2])
        #print(x.group())
        ELECTOR_ADDR = re.search(r"[0-9a-fA-F]{64}", x.group())
        ELECTOR_ADDR = ELECTOR_ADDR.group()
        if ELECTOR_ADDR:
            print("ELECTOR_ADDR = " + ELECTOR_ADDR)
            return
        else:
            print("Some error on get_elector_address")
            sys.exit()
    except Exception as error:
        print(error, 'Failed on get_elector_address')

def get_election_time():
    '''get_election_time then parse it'''
    global START_ELECTION_PERIOD
    global END_ELECTION_PERIOD
    global ELECTION_DIR
    print("Getting ELECTION_TIME...")
    try:
        #lite-client -a IP:9300 -p liteserver.pub -rc 'runmethod -1:C7EAFBC106A7AA4BA3D16007C6AC64CAAC1078B4A43577339E246F466405E896 active_election_id'
        chain = liteclient ["-a", CONNECT_STR_LITE_CLIENT, "-p", "liteserver.pub", "-rc", 'runmethod -1:' + ELECTOR_ADDR + ' active_election_id'].run(retcode=None)
        #(echo[chain[1:3]] >> "log.log")()
        x = re.search(r"result:\s\s\[\s\d+\s\]", chain[2])
        #print(x.group())
        START_ELECTION_PERIOD = re.search(r"\d+", x.group())
        START_ELECTION_PERIOD = START_ELECTION_PERIOD.group()
        print("START_ELECTION_PERIOD = " + START_ELECTION_PERIOD)
        WORK_TIME = 1571749200 #Tuesday, October 22, 2019 4:00:00 PM GMT+03:00
        if (int(START_ELECTION_PERIOD) > WORK_TIME ):
            END_ELECTION_PERIOD = int(START_ELECTION_PERIOD)+86400
            #print("END_ELECTION_PERIOD = " + str(END_ELECTION_PERIOD))
            p = local.path(DIR / int(START_ELECTION_PERIOD))
            if p.exists():
                print(p+" Already exists!")
                #p.is_dir()
            else:
                p.mkdir()
                print(p+" Created this dir!")
            ELECTION_DIR = p
            now = pendulum.now(tz='Europe/Kiev')
            (echo[now.to_datetime_string()] >> p / "log.log")()
            (echo[chain[1:3]] >> p / "log.log")()
            
            return
        else:
            print("START_ELECTION_PERIOD = 0 or in past, exiting...")
            sys.exit()
    except Exception as error:
        print(error, 'Failed on get_election_time')

def get_seqno():
    '''get_seqno then parse it'''
    global CURRENT_SEQNO
    print("Getting CURRENT_SEQNO...")
    try:
        #lite-client -a IP:9300 -p liteserver.pub -rc 'runmethod kf82xRnEMLVIlElyrtGMtclN_4MvxDJLc0C7UM_PxEDkhV-B seqno'
        chain = liteclient ["-a", CONNECT_STR_LITE_CLIENT, "-p", "liteserver.pub", "-rc", 'runmethod ' + WALLET_ADDR + ' seqno'].run(retcode=None)
        x = re.search(r"result:\s\s\[\s\d+\s\]", chain[2])
        if x:
            y = re.search(r"\d+", x.group())
            CURRENT_SEQNO = y.group()
            #LAST_SEQNO = local.env["LAST_SEQNO"]
            #print ( "LAST_SEQNO was : " + LAST_SEQNO)

            print("CURRENT_SEQNO = " + CURRENT_SEQNO)
            #local.env["LAST_SEQNO"] = CURRENT_SEQNO
            #return CURRENT_SEQNO
    except Exception as error:
        print(error, 'Failed on get_seqno')

def check_success():
    '''check_success '''
    try:
        p = local.path(ELECTION_DIR / "success" )
        if p.is_file():
            print(p+" Success file already exists, so -> quit")
            sys.exit()
        else:
            print("Success file doesn't exist, so -> continue")
            return
    except Exception as error:
        print(error, 'Failed on check_success')

def write_success():
    '''write success file to prevent duplicates'''
    try:
        p = local.path(ELECTION_DIR / "success" )
        p.touch()
        if p.is_file():
            print("Success file created!")
        else:
            print("Some kind of error")
            return
    except Exception as error:
        print(error, 'Failed on check_success')


def check_3_files():
    #validator-to-sign.bin
    #validator-query.boc
    #finish.boc
    pass


def make_keys():
    '''make perm and temp keys'''
    print("")
    global VAR_A
    global VAR_B
    global ELECTION_DIR
    print("Making keys...")
    try:
        #validator-engine-console -a IP:9200 -k client -p server.pub -rc 'newkey'
        chain = validatorengine ["-a", CONNECT_STR_ENGINE_CONSOLE, "-k", "client", "-p", "server.pub", "-rc", "newkey"].run(retcode=None)
        #(echo[chain[1:3]] >> "log.log")()
        (echo[chain[1:3]] >> ELECTION_DIR / "log.log")()
        w = re.search(r"created new key [0-9a-fA-F]{64}", chain[2])
        #print(w.group())
        VAR_A = re.search(r"[0-9a-fA-F]{64}", w.group())
        VAR_A = VAR_A.group()
        print("VAR_A = " + VAR_A)

        #validator-engine-console -a IP:9200 -k client -p server.pub -rc 'exportpub VAR_A'
        chain = validatorengine ["-a", CONNECT_STR_ENGINE_CONSOLE, "-k", "client", "-p", "server.pub", "-rc", 'exportpub '+ VAR_A].run(retcode=None)
        (echo[chain[1:3]] >> ELECTION_DIR / "log.log")()
        #re.M to match end of string $
        x = re.search(r"got public key:\s.{48}$", chain[2], re.M)
        VAR_B = re.search(r"got public key:\s(.{48})$", x.group(),re.M)
        VAR_B = VAR_B.group(1)
        print("VAR_B = " + VAR_B)

        #validator-engine-console -a IP:9200 -k client -p server.pub -t 0.1 -rc 'addpermkey VAR_A START_ELECTION_PERIOD END_ELECTION_PERIOD'
        chain = validatorengine ["-a", CONNECT_STR_ENGINE_CONSOLE, "-k", "client", "-p", "server.pub", "-t", "0.1", "-rc", 'addpermkey '+VAR_A+' '+START_ELECTION_PERIOD+' '+ str(END_ELECTION_PERIOD)].run(retcode=None)
        #print(chain)
        (echo[chain[1:3]] >> ELECTION_DIR / "log.log")()
        #re.M to match start of string ^
        y = re.search(r"success", chain[2], re.M)
        #print(y.group())
        #print(y[0] if y else 'Not found')
        if y:
            print("Success = "+y.group())
        else:
            print("Maybe error on addpermkey")

            #return

        #validator-engine-console -a IP:9200 -k client -p server.pub -t 0.1 -rc 'addtempkey VAR_A VAR_A END_ELECTION_PERIOD'
        chain = validatorengine ["-a", CONNECT_STR_ENGINE_CONSOLE, "-k", "client", "-p", "server.pub", "-t", "0.1", "-rc", 'addtempkey '+VAR_A+' '+VAR_A+' '+str(END_ELECTION_PERIOD)].run(retcode=None)
        #print(chain)
        (echo[chain[1:3]] >> ELECTION_DIR / "log.log")()
        #re.M to match start of string ^
        z = re.search(r"success", chain[2], re.M)
        #print(z.group())
        #print(z[0] if y else 'Not found')
        if z:
            print("Success = "+z.group())
        else:
            print("Maybe error on addtempkey")
            #return
    except Exception as error:
        print(error, 'Failed on make_keys')



def make_keys_adnl():
    '''make adnl keys'''
    global VAR_C
    global ELECTION_DIR
    print("Making ADNL keys...")
    try:
        #validator-engine-console -a IP:9200 -k client -p server.pub -rc 'newkey'
        chain = validatorengine ["-a", CONNECT_STR_ENGINE_CONSOLE, "-k", "client", "-p", "server.pub", "-rc", 'newkey'].run(retcode=None)
        (echo[chain[1:3]] >> ELECTION_DIR / "log.log")()
        w = re.search(r"created new key [0-9a-fA-F]{64}", chain[2])
        #print(w.group())
        VAR_C = re.search(r"[0-9a-fA-F]{64}", w.group())
        VAR_C = VAR_C.group()
        print("VAR_C = " + VAR_C)

        #validator-engine-console -a IP:9200 -k client -p server.pub -t 0.1 -rc 'addadnl VAR_C 0'
        chain = validatorengine ["-a", CONNECT_STR_ENGINE_CONSOLE, "-k", "client", "-p", "server.pub", "-t", "0.1", "-rc", 'addadnl '+VAR_C+' 0'].run(retcode=None)
        #print(chain)
        (echo[chain[1:3]] >> ELECTION_DIR / "log.log")()
        #re.M to match end of string $
        x = re.search(r"success", chain[2], re.M)
        #print(x.group())
        if x:
            print("Success = "+x.group())
        else:
            print("Maybe error on addadnl")
            #return

        #validator-engine-console -a IP:9200 -k client -p server.pub -t 0.1 -rc 'addvalidatoraddr VAR_A VAR_C END_ELECTION_PERIOD'
        chain = validatorengine ["-a", CONNECT_STR_ENGINE_CONSOLE, "-k", "client", "-p", "server.pub", "-t", "0.1", "-rc", 'addvalidatoraddr '+VAR_A+" "+VAR_C+" "+str(END_ELECTION_PERIOD)].run(retcode=None)
        #print(chain)
        (echo[chain[1:3]] >> ELECTION_DIR / "log.log")()
        #re.M to match end of string $
        y = re.search(r"success", chain[2], re.M)
        #print(y.group())
        if y:
            print("Success = "+y.group())
        else:
            print("Maybe error on addvalidatoraddr")
            #return
    except Exception as error:
        print(error, 'Failed on make_keys_adnl')

def validator_elect_req():
    '''fift validator-elect-req'''
    global VAR_D
    print("Making validator request...")
    try:
        #fift  -s validator-elect-req.fif WALLET_ADDR  START_ELECTION_PERIOD MAX_FACTOR VAR_C [<validator-to-sign>] ==>>  validator-to-sign.bin
        chain = fift ["-s", "validator-elect-req.fif", WALLET_ADDR, START_ELECTION_PERIOD, MAX_FACTOR, VAR_C].run(retcode=None)
        (echo[chain[1:3]] >> ELECTION_DIR / "log.log")()
        w = re.search(r"^[0-9A-F]+$", chain[1],re.M)
        if w:
            VAR_D = w.group()
            print("VAR_D = " + VAR_D)

    except Exception as error:
        print(error, 'Failed on validator_elect_req')


def engine_console_sign():
    '''validator-engine-console sign VAR_A VAR_D'''
    global VAR_E
    print("Validator-engine-console sign...")
    try:
        #validator-engine-console -a IP:9200 -k client -p server.pub -t 0.1 -rc 'sign VAR_A VAR_D'
        SIGN_STR = 'sign '+VAR_A+" "+ VAR_D
        #use additional [ ] for normal brakets escaping 
        chain = validatorengine ["-a", CONNECT_STR_ENGINE_CONSOLE, "-k", "client", "-p", "server.pub", "-t", "0.1", "-rc", [SIGN_STR] ].run(retcode=None)
        #print(chain)
        (echo[chain[1:3]] >> ELECTION_DIR / "log.log")()
        #re.M to match end of string $
        x = re.search(r"^got signature\s(.+)$", chain[2],re.M)
        if x:
            VAR_E = x.group(1)
            print("VAR_E = " + VAR_E)
        else:
            print("Maybe error on engine_console_sign")
    except Exception as error:
        print(error, 'Failed on engine_console_sign')



def validator_elect_sign():
    '''fift validator-elect-signed'''
    print("Signing validator request...")
    try:
        #fift  -s validator-elect-signed.fif WALLET_ADDR  START_ELECTION_PERIOD MAX_FACTOR VAR_C VAR_B VAR_E [<validator-query>] ==>>  validator-query.boc
        chain = fift ["-s", "validator-elect-signed.fif", WALLET_ADDR, START_ELECTION_PERIOD, MAX_FACTOR, VAR_C, VAR_B, VAR_E].run(retcode=None)
        #print(chain)
        (echo[chain[1:3]] >> ELECTION_DIR / "log.log")()
        w = re.search(r"^[0-9A-F]+$", chain[1],re.M)
        if w:
            VAR_D = w.group()
            print("VAR_D = " + VAR_D)
    except Exception as error:
        print(error, 'Failed on validator_elect_sign')


def validator_wallet_sign():
    '''fift wallet.fif'''
    print("Signing validator request with our wallet...")
    try:
        print("CURRENT_SEQNO = " + CURRENT_SEQNO)
        #fift -s wallet.fif wallet_03_10_2019 -1:C7EAFBC106A7AA4BA3D16007C6AC64CAAC1078B4A43577339E246F466405E896 seqno 100001. -B validator-query.boc [<wallet-query>] ==>>  wallet-query.boc
        chain = fift ["-s", "wallet.fif", WALLET_FILENAME, "-1:"+ELECTOR_ADDR, CURRENT_SEQNO, STAKE, "-B", "validator-query.boc", "finish"].run(retcode=None)
        #print(chain)
        (echo[chain[1:3]] >> ELECTION_DIR / "log.log")()
        
        w = re.search(r"Saved to file", chain[1],re.I)
        if w:
            print("Generated finish.boc file")
        else:
            print("Some kind of error")
    except Exception as error:
        print(error, 'Failed on validator_wallet_sign')

def sendfile():
    '''liteclient sendfile'''
    print("Sending finish.boc to blockchain...")
    try:
        #lite-client -a IP:9300 -p liteserver.pub -rc ' sendfile validator-query-send.boc'
        chain = liteclient ["-a", CONNECT_STR_LITE_CLIENT, "-p", "liteserver.pub", "-rc", 'sendfile finish.boc'].run(retcode=None)
        (echo[chain[1:3]] >> ELECTION_DIR / "log.log")()
        x = re.search(r"sending query from file", chain[2])
        if x:
            print("Sendfile is OK")
            result = x.group()
            write_success()
        else:
            print("Some kind of error")
    except Exception as error:
        print(error, 'Failed on sendfile')


class Cli(cli.Application):
    """Small utility to automate validator requests as shown in
    https://test.ton.org/Validator-HOWTO.txt
    """
    VERSION = "1.0"
    def main(self):
        if not self.nested_command:
            print("Current DIR:  " + DIR)
            print("Current FIFTPATH:  " + FIFTPATH)
            get_elector_address()
            get_election_time()
            check_success()
            make_keys()
            make_keys_adnl()
            validator_elect_req()
            engine_console_sign()
            validator_elect_sign()
            get_seqno()
            validator_wallet_sign()
            sendfile()
            get_seqno()
            print("-------------------------")
            print("Variables : ")
            print(START_ELECTION_PERIOD)
            print(VAR_A)
            print(VAR_B)
            print(VAR_C)
            print(VAR_D)
            print(VAR_E)
            print(MAX_FACTOR)
            print(STAKE)
            print("-------------------------")
            #return 1   # error exit code

if __name__ == "__main__":
    Cli.run()