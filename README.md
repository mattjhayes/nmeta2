# nmeta2
Revised nmeta code that distributes some traffic classification functions to an auxiliary device called a Data Plane Auxiliary Engine (DPAE). Code is still being developed

## Install on Ubuntu:

### Install Python pip
```
sudo apt-get install python-pip
```

### Install Ryu OpenFlow Controller
```
pip install ryu
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

### Clone nmeta2
Clone nmeta2:
```
cd
https://github.com/mattjhayes/nmeta2.git
```

### Set up Aliases
Set up alias in .bash_aliases. Sudo and edit the file by adding:
```
alias nm2="cd; cd ryu; PYTHONPATH=. ./bin/ryu-manager ../nmeta2/nmeta2/nmeta2.py --log-config-file ~/nmeta2/nmeta2/ryu_logging.conf"
alias nm2t="cd ~/nmeta2/test/; py.test tests_unit.py"
```

## Run
nm2
