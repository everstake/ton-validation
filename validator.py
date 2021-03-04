#!/usr/bin/env python
import os, sys, re, time
from plumbum import local, cli, FG, BG, TF, TEE, ProcessExecutionError, colors
from plumbum.cmd import echo
from contextlib import contextmanager
from tinydb import TinyDB, Query, where
import pendulum
from loguru import logger
import base64
'''python --version
Tested on Ubuntu 18.04 with Python 3.6.8
set env variable in .bashrc file using export, here user=ton
export FIFTPATH=/home/ton/ton-sources/ton/crypto/fift/lib:/home/ton/ton-sources/ton/crypto/smartcont
export BETTER_EXCEPTIONS=1
sudo apt install python3-pip
sudo apt install python3-venv
python3 -m venv env
if you use bash -> source env/bin/activate
pip install -r requirements.txt
'''

# you can connect to external interfaces IP:9300 or localhost
CONNECT_STR_LITE_CLIENT = "127.0.0.1:3031"
CONNECT_STR_ENGINE_CONSOLE = "127.0.0.1:3030"

# wallet address = -1:36c519c430b548944972aed18cb5c94dff832fc4324b7340bb50cfcfc440e485
# Bounceable address (for later access)
WALLET_ADDR = "kf9cXSD9NCO2C56Yda3Lv8E5t-pgq75OOe1MKlgt50u2aQts"

# wallet address = -1:36c519c430b548944972aed18cb5c94dff832fc4324b7340bb50cfcfc440e485
# address for compute_returned_stake
WALLET_ADDR_C = "5c5d20fd3423b60b9e9875adcbbfc139b7ea60abbe4e39ed4c2a582de74bb669"


# For fift signing
# Wallet addr filename  validator.addr
# Wallet key  filename  validator.pk

# For tonos-cli signing with multisig
# Wallet addr filename  validator_1part.addr
# Wallet addr filename  validator_1part.keys.json

# in basename - without ext
WALLET_FILENAME = "wallet_19_11_2019"

# Use tonos-cli functions to sign and submit messages with msig keys
USE_MSIG=True

BALANCE = -1

# wallet seqno
CURRENT_SEQNO = -1

ELECTOR_ADDR = ""

RETURNED_STAKE = -1

REWARD = -1

# ACTIVE_ELECTION_ID = ""
START_ELECTION_PERIOD = -1

# START_ELECTION_PERIOD + 1 DAY
END_ELECTION_PERIOD = 0

# maximal stake factor with respect to the minimal stake 176947/65536 = 2.7
MAX_FACTOR = "3"

# Stake amount + extra 1 GRAM to cover fee
STAKE = "300001"

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

# validator public key
# lite-client getconfig 34 - current validators
# public_key: ed25519_pubkey pubkey:xVAL_PUBKEY
VAL_PUBKEY = ""

# Logfile that stores general messeges + some of exceptions
# PWD / G_LOGFILE
G_LOGFILE = "last.log"

# Logfile that stores messages about things related to specific elections
# PWD / ELECTION_DIR / E_LOGFILE
E_LOGFILE = "log.log"

def check_env():
    '''set env and executables'''
    #global FIFTPATH
    global DIR
    global fift
    global liteclient
    global validatorengine
    global tonos
    try:
        FIFTPATH = local.env["FIFTPATH"]
        if FIFTPATH:
            logger_general.info("Current FIFTPATH:  " + FIFTPATH)

        # Assign executables found in current dir
        DIR = local.path(__file__) / '..'   #PWD
        logger_general.info("Current DIR:  " + DIR)
        fift = local[DIR / 'fift']
        liteclient = local[DIR / 'lite-client']
        validatorengine = local[DIR / 'validator-engine-console']
        tonos = local[DIR / 'tonos-cli']
    except Exception as error:
        logger_general.opt(exception=True).debug('Failed on check_env')
        sys.exit()

def get_elector_address():
    '''get_elector_address then parse it'''
    global ELECTOR_ADDR
    logger_general.info("Getting ELECTOR_ADDR...")
    try:
        # lite-client -a IP:9300 -p liteserver.pub -t 0.1 -rc ' getconfig 1'
        # change .run to  & TEE(retcode = None) to execute command and output to stdout
        chain = liteclient ["-a", CONNECT_STR_LITE_CLIENT, "-p", "liteserver.pub", "-t", "0.1", "-rc", 'getconfig 1'].run(retcode=None)
        (echo[chain[1:3]] >> G_LOGFILE)()
        x = re.search(r"elector_addr:x([0-9a-fA-F]{64})", chain[1])
        if x:
            ELECTOR_ADDR = x.group(1)
            logger_general.info("ELECTOR_ADDR = " + ELECTOR_ADDR)
            return True
        else:
            logger_general.error("Some kind of error, maybe no elector found!")
            return False
    except Exception as error:
        logger_general.opt(exception=True).debug('Failed on get_elector_address')
        sys.exit()

def get_election_time():
    '''get_election_time then parse it'''
    global START_ELECTION_PERIOD
    global END_ELECTION_PERIOD
    global ELECTION_DIR
    logger_general.info("Getting ELECTION_TIME...")
    try:
        #lite-client -a IP:9300 -p liteserver.pub -t 0.1 -rc 'runmethod -1:C7EAFBC106A7AA4BA3D16007C6AC64CAAC1078B4A43577339E246F466405E896 active_election_id'
        chain = liteclient ["-a", CONNECT_STR_LITE_CLIENT, "-p", "liteserver.pub", "-t", "0.1", "-rc", 'runmethod -1:' + ELECTOR_ADDR + ' active_election_id'].run(retcode=None)
        x = re.search(r"result:\s\s\[\s\d+\s\]", chain[1])
        WORK_TIME = 1571749200 #Tuesday, October 22, 2019 4:00:00 PM GMT+03:00
        if x:
            y = re.search(r"\d+", x.group())
            START_ELECTION_PERIOD = int(y.group())
            if (START_ELECTION_PERIOD > WORK_TIME ):
                END_ELECTION_PERIOD = START_ELECTION_PERIOD+172800 # 2days
                p = local.path(DIR / "ELECTION_DIR" / str(START_ELECTION_PERIOD))
                if p.exists():
                    logger_general.info(p+" Already exists!")
                else:
                    p.mkdir()
                    logger_general.info(p+" Created this dir!")
                ELECTION_DIR = p

                logger.add(ELECTION_DIR / E_LOGFILE, backtrace=True, diagnose=True, filter=lambda record: record["extra"].get("name") == "elections")
                global logger_elections
                logger_elections = logger.bind(name="elections")
                logger_elections.info("START_ELECTION_PERIOD = " + str(START_ELECTION_PERIOD))

                (echo[chain[1:3]] >> ELECTION_DIR / E_LOGFILE)()
                return True
            else:
                (echo[chain[1:3]] >> G_LOGFILE)()
                logger_general.info("START_ELECTION_PERIOD = 0, exiting...")
        else:
            logger_general.error("Some kind of error")
            return False
    except Exception as error:
        logger_general.opt(exception=True).debug("Failed on get_election_time")

def get_seqno(q):
    '''get_seqno then parse it'''
    global CURRENT_SEQNO
    logger_general.info("Getting CURRENT_SEQNO...")
    try:
        #lite-client -a IP:9300 -p liteserver.pub -t 0.1 -rc 'runmethod kf82xRnEMLVIlElyrtGMtclN_4MvxDJLc0C7UM_PxEDkhV-B seqno'
        chain = liteclient ["-a", CONNECT_STR_LITE_CLIENT, "-p", "liteserver.pub", "-t", "0.1", "-rc", 'runmethod ' + WALLET_ADDR + ' seqno'].run(retcode=None)
        x = re.search(r"result:\s\s\[\s(\d+)\s\]", chain[1])
        if ( q and x):
            (echo[chain[1:3]] >> ELECTION_DIR / E_LOGFILE)()
            CURRENT_SEQNO = int(x.group(1))
            logger_elections.info("CURRENT_SEQNO = " + str(CURRENT_SEQNO))
        elif ( not q and x):
            (echo[chain[1:3]] >> G_LOGFILE)()
            CURRENT_SEQNO = int(x.group(1))
            logger_general.info("CURRENT_SEQNO = " + str(CURRENT_SEQNO))
        elif ( q and not x):
            (echo[chain[1:3]] >> ELECTION_DIR / E_LOGFILE)()
            logger_elections.error("Some kind of error with get_seqno")
        elif ( not q and not x):
            (echo[chain[1:3]] >> G_LOGFILE)()
            logger_general.error("Some kind of error with get_seqno")
    except Exception as error:
        logger_general.opt(exception=True).debug("Failed on get_seqno")

def check_success():
    '''check_success '''
    try:
        p = local.path(ELECTION_DIR / "success" )
        if p.is_file():
            logger_elections.info(p+" Success file already exists, so -> quit")
            return True
        else:
            logger_elections.info("Success file doesn't exist, so -> continue")
            return False
    except Exception as error:
        logger_elections.opt(exception=True).debug("Failed on check_success")

def write_success():
    '''write success file to prevent duplicates'''
    try:
        p = local.path(ELECTION_DIR / "success" )
        p.touch()
        if p.is_file():
            logger_elections.success("Success file created!")
        else:
            logger_elections.error("Some kind of error!")
    except Exception as error:
        logger_elections.opt(exception=True).debug("Failed on write_success")

def make_keys():
    '''make perm and temp keys'''
    global VAR_A
    global VAR_B
    logger_elections.info("Making keys...")
    try:
        #validator-engine-console -a IP:9200 -k client -p server.pub -t 0.1 -rc 'newkey'
        chain = validatorengine ["-a", CONNECT_STR_ENGINE_CONSOLE, "-k", "client", "-p", "server.pub", "-t", "0.1", "-rc", "newkey"].run(retcode=None)
        (echo[chain[1:3]] >> ELECTION_DIR / E_LOGFILE)()
        w = re.search(r"created new key ([0-9a-fA-F]{64})", chain[1])
        if w:
            VAR_A = w.group(1)
            logger_elections.info("VAR_A = " + VAR_A)
        else:
            logger_elections.error("Some kind of error with VAR_A")

        #validator-engine-console -a IP:9200 -k client -p server.pub -t 0.1 -rc 'exportpub VAR_A'
        chain = validatorengine ["-a", CONNECT_STR_ENGINE_CONSOLE, "-k", "client", "-p", "server.pub", "-t", "0.1", "-rc", 'exportpub '+ VAR_A].run(retcode=None)
        (echo[chain[1:3]] >> ELECTION_DIR / E_LOGFILE)()
        #re.M to match end of string $
        x = re.search(r"got public key:\s(.{48})$", chain[1], re.M)
        if x:
            VAR_B = x.group(1)
            logger_elections.info("VAR_B = " + VAR_B)
        else:
            logger_elections.error("Some kind of error with VAR_B")

        #validator-engine-console -a IP:9200 -k client -p server.pub -t 0.1 -rc 'addpermkey VAR_A START_ELECTION_PERIOD END_ELECTION_PERIOD'
        chain = validatorengine ["-a", CONNECT_STR_ENGINE_CONSOLE, "-k", "client", "-p", "server.pub", "-t", "0.1", "-rc", 'addpermkey '+VAR_A+' '+str(START_ELECTION_PERIOD)+' '+ str(END_ELECTION_PERIOD)].run(retcode=None)
        (echo[chain[1:3]] >> ELECTION_DIR / E_LOGFILE)()
        y = re.search(r"success", chain[1])
        if y:
            logger_elections.info("addpermkey")
        else:
            logger_elections.error("Some kind of error with addpermkey")

        #validator-engine-console -a IP:9200 -k client -p server.pub -t 0.1 -rc 'addtempkey VAR_A VAR_A END_ELECTION_PERIOD'
        chain = validatorengine ["-a", CONNECT_STR_ENGINE_CONSOLE, "-k", "client", "-p", "server.pub", "-t", "0.1", "-rc", 'addtempkey '+VAR_A+' '+VAR_A+' '+str(END_ELECTION_PERIOD)].run(retcode=None)
        (echo[chain[1:3]] >> ELECTION_DIR / E_LOGFILE)()
        z = re.search(r"success", chain[1])
        if z:
            logger_elections.info("addtempkey")
        else:
            logger_elections.error("Some kind of error with addtempkey")
    except Exception as error:
        logger_elections.opt(exception=True).debug("Failed on make_keys")

def make_keys_adnl():
    '''make adnl keys'''
    global VAR_C
    logger_elections.info("Making ADNL keys...")
    try:
        #validator-engine-console -a IP:9200 -k client -p server.pub -t 0.1 -rc 'newkey'
        chain = validatorengine ["-a", CONNECT_STR_ENGINE_CONSOLE, "-k", "client", "-p", "server.pub", "-t", "0.1", "-rc", 'newkey'].run(retcode=None)
        (echo[chain[1:3]] >> ELECTION_DIR / E_LOGFILE)()
        w = re.search(r"created new key ([0-9a-fA-F]{64})", chain[1])
        if w:
            VAR_C = w.group(1)
            logger_elections.info("VAR_C = " + VAR_C)
        else:
            logger_elections.error("Some kind of error with VAR_C")

        #validator-engine-console -a IP:9200 -k client -p server.pub -t 0.1 -rc 'addadnl VAR_C 0'
        chain = validatorengine ["-a", CONNECT_STR_ENGINE_CONSOLE, "-k", "client", "-p", "server.pub", "-t", "0.1", "-rc", 'addadnl '+VAR_C+' 0'].run(retcode=None)
        (echo[chain[1:3]] >> ELECTION_DIR / E_LOGFILE)()
        x = re.search(r"success", chain[1])
        if x:
            logger_elections.info("addadnl")
        else:
            logger_elections.error("Some kind of error with addadnl")

        #validator-engine-console -a IP:9200 -k client -p server.pub -t 0.1 -rc 'addvalidatoraddr VAR_A VAR_C END_ELECTION_PERIOD'
        chain = validatorengine ["-a", CONNECT_STR_ENGINE_CONSOLE, "-k", "client", "-p", "server.pub", "-t", "0.1", "-rc", 'addvalidatoraddr '+VAR_A+" "+VAR_C+" "+str(END_ELECTION_PERIOD)].run(retcode=None)
        (echo[chain[1:3]] >> ELECTION_DIR / E_LOGFILE)()
        y = re.search(r"success", chain[1])
        if y:
            logger_elections.info("addvalidatoraddr")
        else:
            logger_elections.error("Some kind of error with addvalidatoraddr")
    except Exception as error:
        logger_elections.opt(exception=True).debug("Failed on make_keys_adnl")

def validator_elect_req():
    '''fift validator-elect-req'''
    global VAR_D
    logger_elections.info("Making validator request...")
    try:
        #fift  -s validator-elect-req.fif WALLET_ADDR  START_ELECTION_PERIOD MAX_FACTOR VAR_C [<validator-to-sign>] ==>>  validator-to-sign.bin
        chain = fift ["-s", "validator-elect-req.fif", WALLET_ADDR, str(START_ELECTION_PERIOD), MAX_FACTOR, VAR_C].run(retcode=None)
        (echo[chain[1:3]] >> ELECTION_DIR / E_LOGFILE)()
        w = re.search(r"^([0-9A-F]+)$", chain[1],re.M)
        if w:
            VAR_D = w.group(1)
            logger_elections.info("VAR_D = " + VAR_D)
        else:
            logger_elections.error("Some kind of error with validator_elect_req")
    except Exception as error:
        logger_elections.opt(exception=True).debug("Failed on validator_elect_req")

def engine_console_sign():
    '''validator-engine-console sign VAR_A VAR_D'''
    global VAR_E
    logger_elections.info("Validator-engine-console sign...")
    try:
        #validator-engine-console -a IP:9200 -k client -p server.pub -t 0.1 -rc 'sign VAR_A VAR_D'
        SIGN_STR = 'sign '+VAR_A+" "+ VAR_D
        #use additional [ ] for normal brakets escaping
        chain = validatorengine ["-a", CONNECT_STR_ENGINE_CONSOLE, "-k", "client", "-p", "server.pub", "-t", "0.1", "-rc", [SIGN_STR] ].run(retcode=None)
        (echo[chain[1:3]] >> ELECTION_DIR / E_LOGFILE)()
        #re.M to match end of string $
        x = re.search(r"^got signature\s(.+)$", chain[1],re.M)
        if x:
            VAR_E = x.group(1)
            logger_elections.info("VAR_E = " + VAR_E)
        else:
            logger_elections.error("Some kind of error with engine_console_sign")
    except Exception as error:
        logger_elections.opt(exception=True).debug("Failed on engine_console_sign")

def validator_elect_sign():
    '''fift validator-elect-signed'''
    global VAL_PUBKEY
    logger_elections.info("Signing validator request...")
    try:
        #fift  -s validator-elect-signed.fif WALLET_ADDR  START_ELECTION_PERIOD MAX_FACTOR VAR_C VAR_B VAR_E [<validator-query>] ==>>  validator-query.boc
        chain = fift ["-s", "validator-elect-signed.fif", WALLET_ADDR, str(START_ELECTION_PERIOD), MAX_FACTOR, VAR_C, VAR_B, VAR_E].run(retcode=None)
        (echo[chain[1:3]] >> ELECTION_DIR / E_LOGFILE)()
        x = re.search(r"with validator public key ([0-9a-fA-F]{64})$", chain[1],re.M)
        if x:
            VAL_PUBKEY = x.group(1)
            logger_elections.info("VAL_PUBKEY = " + VAL_PUBKEY)
        else:
            logger_elections.error("Some kind of error with VAL_PUBKEY")
    except Exception as error:
        logger_elections.opt(exception=True).debug("Failed on validator_elect_sign")

def wallet_sign(amount, in_file, out_file, q):
    '''fift wallet.fif'''
    logger_general.info("Signing request with our wallet...")
    try:
        #fift -s wallet.fif wallet_19_11_2019 -B query.boc -- -1:3333333333333333333333333333333333333333333333333333333333333333 seqno amount [<wallet-query>] ==>>  wallet-query.boc
        chain = fift ["-s", "wallet.fif", WALLET_FILENAME,  "-B", in_file, "--", "-1:"+ELECTOR_ADDR, str(CURRENT_SEQNO), amount, out_file].run(retcode=None)
        w = re.search(r"Saved to file", chain[1],re.I)
        if ( q and w):
            (echo[chain[1:3]] >> ELECTION_DIR / E_LOGFILE)()
            logger_elections.info("Generated "+out_file+" file")
            return True
        elif ( not q and w):
            (echo[chain[1:3]] >> G_LOGFILE)()
            logger_general.info("Generated "+out_file+" file")
            return True
        elif ( q and not w):
            (echo[chain[1:3]] >> ELECTION_DIR / E_LOGFILE)()
            logger_elections.error("Some kind of error with wallet_sign")
        elif ( not q and not w):
            (echo[chain[1:3]] >> G_LOGFILE)()
            logger_general.error("Some kind of error with wallet_sign")
    except Exception as error:
        logger_general.opt(exception=True).debug("Failed on wallet_sign")


def wallet_sign_tonos(amount, in_file, q):
    '''tonos-cli call MSIG_ADDR submitTransaction'''
    logger_general.info("Signing request with our msig wallet...")
    try:
        with open(in_file, 'rb') as binary_file:
            binary_file_data = binary_file.read()
            base64_encoded_data = base64.b64encode(binary_file_data)
            base64_message = base64_encoded_data.decode('utf-8')

            if base64_message:  # this cathes ONLY that string is not empty (null)

                x = re.search("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$", base64_message) # cathes whitespaces and that it is possible to decode using base64
                if x :
                    chain = tonos ["callex", "submitTransaction", "-1:"+WALLET_ADDR_C, "SafeMultisigWallet.abi.json", WALLET_FILENAME+".keys.json", "--dest", "-1:"+ELECTOR_ADDR, "--value", amount+"T", "--bounce", "true", "--allBalance", "false", "--payload", base64_message].run(retcode=None,timeout=120)
                    w = re.search(r"Succeeded", chain[1],re.I)

                    if ( q and w):
                        (echo[chain[1:3]] >> ELECTION_DIR / E_LOGFILE)()
                        logger_elections.info("Signed and sent "+in_file+" to the network")
                        return True
                    elif ( not q and w):
                        (echo[chain[1:3]] >> G_LOGFILE)()
                        logger_general.info("Signed and sent "+in_file+" to the network")
                        return True
                    elif ( q and not w):
                        (echo[chain[1:3]] >> ELECTION_DIR / E_LOGFILE)()
                        logger_elections.error("Some kind of error with wallet_sign_tonos")
                    elif ( not q and not w):
                        (echo[chain[1:3]] >> G_LOGFILE)()
                        logger_general.error("Some kind of error with wallet_sign_tonos")
    except Exception as error:
        logger_general.opt(exception=True).debug("Failed on wallet_sign_tonos")



def sendfile(f, q):
    '''liteclient sendfile'''
    logger_general.info("Sending "+f+" to blockchain...")
    try:
        #lite-client -a IP:9300 -p liteserver.pub -t 0.1 -rc ' sendfile validator-query-send.boc'
        chain = liteclient ["-a", CONNECT_STR_LITE_CLIENT, "-p", "liteserver.pub", "-t", "0.1", "-rc", 'sendfile '+f].run(retcode=None)
        x = re.search(r"sending query from file", chain[2])
        if ( q and x):
            (echo[chain[1:3]] >> ELECTION_DIR / E_LOGFILE)()
            logger_elections.info("Sent "+f+" to blockchain")
            return True
        elif ( not q and x):
            (echo[chain[1:3]] >> G_LOGFILE)()
            logger_general.info("Sent "+f+" to blockchain")
            return True
        elif ( q and not x):
            (echo[chain[1:3]] >> ELECTION_DIR / E_LOGFILE)()
            logger_elections.error("Some kind of error with sendfile")
        elif ( not q and not x):
            (echo[chain[1:3]] >> G_LOGFILE)()
            logger_general.error("Some kind of error with sendfile")
    except Exception as error:
        logger_general.opt(exception=True).debug("Failed on sendfile")

def compute_returned_stake():
    '''compute_returned_stake then parse it'''
    global RETURNED_STAKE
    logger_general.info("Running compute_returned_stake...")
    try:
        #lite-client -a IP:9300 -p liteserver.pub -t 0.1 -rc ' runmethod -1:C7EAFBC106A7AA4BA3D16007C6AC64CAAC1078B4A43577339E246F466405E896 compute_returned_stake 0x36c519c430b548944972aed18cb5c94dff832fc4324b7340bb50cfcfc440e485'
        chain = liteclient ["-a", CONNECT_STR_LITE_CLIENT, "-p", "liteserver.pub", "-t", "0.1", "-rc", 'runmethod -1:' + ELECTOR_ADDR + ' compute_returned_stake 0x'+WALLET_ADDR_C].run(retcode=None)
        (echo[chain[1:3]] >> G_LOGFILE)()
        x = re.search(r"result:\s\s\[\s(\d+)\s\]", chain[1])
        if x:
            RETURNED_STAKE = int(x.group(1))
            if (RETURNED_STAKE > 0):
                logger_general.info("RETURNED_STAKE = " + str(RETURNED_STAKE))
                return True
            else:
                logger_general.info("RETURNED_STAKE = 0")
                return False
    except Exception as error:
        logger_general.opt(exception=True).debug("Failed on compute_returned_stake")

def get_balance():
    '''get_balance then parse it'''
    global BALANCE
    logger_general.info("Getting balance...")
    try:
        #lite-client -a IP:9300 -p liteserver.pub -t 0.1 -rc ' getaccount WALLET_ADDR'
        chain = liteclient ["-a", CONNECT_STR_LITE_CLIENT, "-p", "liteserver.pub", "-t", "0.1", "-rc", 'getaccount ' + WALLET_ADDR].run(retcode=None)
        (echo[chain[1:3]] >> G_LOGFILE)()
        x = re.search(r"^account balance is (\d+)ng$", chain[1],re.M)
        if x:
            BALANCE = int(x.group(1))
            logger_general.info("BALANCE = " + str(BALANCE))
            return True
    except Exception as error:
        logger_general.opt(exception=True).debug("Failed on get_balance")

class Cli(cli.Application):
    """Small utility to automate validator requests and get rewards as shown in
    https://test.ton.org/Validator-HOWTO.txt
    """
    VERSION = "1.4"
    def main(self):
        if not self.nested_command:
            logger.add(G_LOGFILE, backtrace=True, diagnose=True, filter=lambda record: record["extra"].get("name") == "general")
            global logger_general
            global REWARD
            logger_general = logger.bind(name="general")

            now = pendulum.now()
            success=False
            db = TinyDB('db.json')
            iter=len(db)+1
            logger_general.info("Starting script, iter = "+str(iter))
            check_env()
            get_balance()
            if not USE_MSIG:
                get_seqno(False)
            if not get_elector_address():
                sys.exit() # Exit when there is no elector found, cause we can't do anything
            if compute_returned_stake():
                if USE_MSIG :
                    if wallet_sign_tonos("1", "recover-query.boc", False) :
                        logger_general.info("Sleep for 3 minutes to confirm the transaction (msig)")
                        time.sleep(3)     #Test how much time it takes for "seqno" to change
                        #get_seqno(False)
                        try:
                            query=db.search(where('success')==True)[-2]['stake'] #get penultimate stake amount where success is True
                            if query:
                                REWARD=RETURNED_STAKE-query
                        except Exception as error:
                            logger_general.opt(exception=True).debug("Failed on reverse search on DB for previous records")
                else :
                    if wallet_sign("1.", "recover-query.boc", "return-stake",False) :
                        if sendfile("return-stake.boc",False):
                            logger_general.info("Sleep for 15 seconds to complete transaction")
                            time.sleep(15)     #Test how much time it takes for "seqno" to change
                            get_seqno(False)
                            try:
                                query=db.search(where('success')==True)[-2]['stake'] #get penultimate stake amount where success is True
                                if query:
                                    REWARD=RETURNED_STAKE-query
                            except Exception as error:
                                logger_general.opt(exception=True).debug("Failed on reverse search on DB for previous records")
            if get_election_time():
                if not check_success():
                    make_keys()
                    make_keys_adnl()
                    validator_elect_req()
                    engine_console_sign()
                    validator_elect_sign()
                    if USE_MSIG :
                        if wallet_sign_tonos(STAKE, "validator-query.boc",True) :
                            write_success()
                            success=True
                            logger_elections.info("Sleep for 3 minutes to confirm the transaction (msig)")
                            time.sleep(3)
                            #get_seqno(True)
                    else :
                        get_seqno(True)
                        if wallet_sign(STAKE, "validator-query.boc", "finish",True) :
                            if sendfile("finish.boc",True):
                                write_success()
                                success=True
                                logger_elections.info("Sleep for 15 seconds to complete transaction")
                                time.sleep(15)
                                get_seqno(True)
            stake=int(STAKE)*1000000000 #We scale all values to nanograms
            max_factor=int(MAX_FACTOR)
            db.insert({
                'id': iter,
                'time': now.int_timestamp,
                'election_time': START_ELECTION_PERIOD,
                'balance': BALANCE,
                'seqno': CURRENT_SEQNO,
                'returned': RETURNED_STAKE,
                'stake':stake,
                'reward':REWARD,
                'max_factor': max_factor,
                'success': success,
                'A':VAR_A,
                'B':VAR_B,
                'C':VAR_C,
                'D':VAR_D,
                'E':VAR_E,
                'validator_pubkey':VAL_PUBKEY,
                'elector':ELECTOR_ADDR
              })
            #return 1   # error exit code
if __name__ == "__main__":
    Cli.run()
