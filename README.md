# nmeta2
Revised nmeta code that distributes some traffic classification functions to an auxiliary device called a Data Plane Auxiliary Engine (DPAE). Code is still being developed

## Install on Ubuntu:

### Ensure packages are up-to-date
```
sudo apt-get update
sudo apt-get upgrade
```

### Install Python pip
```
sudo apt-get install python-pip
```

### Install Ryu OpenFlow Controller
```
sudo pip install ryu
```

### Install test and dev tools
Install mock
```
sudo pip install -U mock
```

Install nosetests
```
sudo apt-get install python-nose
```

Install pytest
```
sudo apt-get install python-pytest
```

Install git:
```
sudo apt-get install git
```

### Install YAML
Install Python YAML ("YAML Ain't Markup Language") for parsing config and policy files:
```
sudo apt-get install python-yaml
```

### Install coloredlogs
Install coloredlogs to improve readability of terminal logs by colour-coding:
```
sudo pip install coloredlogs
```

### Install simplejson
```
sudo pip install simplejson
```

### Install MongoDB
Install MongoDB as per [their instructions](https://docs.mongodb.org/manual/tutorial/install-mongodb-on-ubuntu/)

import the MongoDB public GPG Key:
```
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv EA312927
```

Create a list file for MongoDB:
```
echo "deb http://repo.mongodb.org/apt/ubuntu trusty/mongodb-org/3.2 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.2.list
```

Reload local package database:
```
sudo apt-get update
```

Install MongoDB:
```
sudo apt-get install -y mongodb-org
```

Add pymongo for a Python API into MongoDB:
```
sudo apt-get install build-essential python-dev
sudo pip install pymongo
```

Turn on smallfiles to cope with small file system size:
```
sudo vi /etc/mongod.conf
```

Add this to the storage section of the config:
```
  mmapv1:
    smallFiles: true
```

Start MongoDB with:
```
sudo service mongod start
```


### Clone nmeta2
Clone nmeta2:
```
cd
git clone https://github.com/mattjhayes/nmeta2.git
```

### Set up Aliases
Set up alias in .bash_aliases. Sudo and edit the file by adding:
```
alias nm2="cd; cd ryu; PYTHONPATH=. ./bin/ryu-manager ../nmeta2/nmeta2/nmeta2.py --log-config-file ~/nmeta2/nmeta2/ryu_logging.conf"
alias nm2t="cd ~/nmeta2/test/; py.test"
```

## Test
```
nm2t
```

## Test
nm2t

## Run
```
nm2
```

## Notes
DPAE MAC addresses for registration can be set in the config file, but the defaults should be fine.
