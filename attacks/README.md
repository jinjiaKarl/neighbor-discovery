# Attack


***Attention: only support Linux now***


## passive sniff attack
```bash
cd traffic_sniff
sudo apt update
sudo apt install -y python3-pip python3-venv tshark


python3 -m venv .
source ./bin/activate 
pip3 install -r requirements.txt

sudo python3 sniff.py

# to deactivate the virtual environment, run the following command:
deactivate
```

## passive man in the middle attack
We need three vms, called vm1, atck and vm2.


On vm1, run the following command:
```bash
python3 -m venv .
source ./bin/activate 
pip3 install -r requirements.txt

python3 node.py vm1

# to deactivate the virtual environment, run the following command:
deactivate
```

If venv doesn't get set up use following command:
```
sudo  apt install python3.11-venv
```

On atck, run the following command:

```bash
python3 -m venv .
source ./bin/activate 
pip3 install -r requirements.txt

cd man_in_the_middle/src
python3 node.py atck

# to deactivate the virtual environment, run the following command:
deactivate
```

On vm2, run the following command:

```bash
python3 -m venv .
source ./bin/activate 
pip3 install -r requirements.txt

cd man_in_the_middle/src
python3 node.py vm2

# to deactivate the virtual environment, run the following command:
deactivate
```



If one node cannot directly connect to the access point because it is out of range. However, the attacker nodes can act as relays between the node and the access point, misleading them that they can communicate directly, and thus control the communication.