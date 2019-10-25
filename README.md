### Small utility to automate validator requests
Please refer to [Validator HOWTO Guide](https://test.ton.org/Validator-HOWTO.txt)

Tested on Ubuntu 18.04

**Required:**

* Python 2.7.15
* working Full-node that completed sync
* configured lite-client and validator-engine-console
* default keys (as shown in *Validator HOWTO Guide*) stored along with executables
* executables (fift, lite-client, validator-engine-console)
* configured FIFTPATH

**Installation steps:**
```
sudo apt install python-pip
pip install pendulum
pip install plumbum
#set env variable in .bashrc file using export, here user=ton
export FIFTPATH=/home/ton/ton-sources/ton/crypto/fift/lib:/home/ton/ton-sources/ton/crypto/smartcont
```

**How to run:**
Place validator.py in directory with executables
and run

***python validator.py***

We recommend you to check the output and the source code.
