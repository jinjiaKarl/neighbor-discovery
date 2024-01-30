# How to run?

We need two VMs, called VM1 and VM2.

First, run the automation scripts to have the correct Wi-Fi configuration depending on which VM you work on. The following commands assume that you're in the `src` folder:

On VM1:

```bash
./automation_scripts/configure_wifi_vm1.sh
```

On VM2:

```bash
./automation_scripts/configure_wifi_vm2.sh
```

On VM1, run the following command:

```bash
python3 -m venv .venv
source ./bin/activate
pip3 install -r requirements.txt

RX_IPADDR={vm1_ip} TX_IPADDR={vm2_ip} python3 node.py vm1

# to deactivate the virtual environment, run the following command:
deactivate
```

If venv doesn't get set up use following command:

```bash
sudo apt install python3.11-venv
```

On VM2, run the following command:

```bash
python3 -m venv .venv
source ./bin/activate
pip3 install -r requirements.txt

RX_IPADDR={vm2_ip} TX_IPADDR={vm1_ip} python3 node.py vm2

# to deactivate the virtual environment, run the following command:
deactivate
```


If you want to see what the current neighbours are, go to `http://{vm_ip}:8000`.

## Performance Evaluation
To be able to run the tests, follow the steps below:
1. Pull the latest changes while you're in the `main` branch: `git pull`
2. In case you don't receive the remote branches, run the following command: `git fetch`
3. Switch to the corresponding branch. For example, run the following command if you need to run performance tests on the improved protocol: `git checkout performance-test-for-improved-protocol`
4. Make the automation scripts executable (if they're not already executable) when you're in the `src` folder: `chmod +x automation_script_for_vm1.sh` and `chmod +x automation_script_for_vm2.sh`
5. Run the following command on any terminal and get the IP address of the Ethernet network interface (`eth0`): `ip a`
6. Open the `automation_script_for_vm1.sh` folder and change the `TX_IPADDR` parameter with the address you obtained in the previous step.
7. Open the `automation_script_for_vm2.sh` folder and change the `RX_IPADDR` parameter with the address you obtained in step 5.
8. To test the automation script, you can tweak the `iteration` parameter in the automation scripts file. When you're ready for real tests, make sure that `iteration` parameter is set to `500` for each automation script.
9. Generate the key for execution of eccdh protocol using the command: `python3 generate_key.py ecc`.
10. Make the necessary changes in the code based on your task requirements.
11. Open two terminals and run the automation script files with the following commands respectively while you're in the `src` folder: `./automation_script_for_vm1.sh` and `./automation_script_for_vm2.sh`
12. If you have any questions, contact Berk or Ishani.



## References

- https://crypto.stackexchange.com/questions/5458/should-we-sign-then-encrypt-or-encrypt-then-sign
- https://stackoverflow.com/questions/65856980/python-rsa-message-encryption-plaintext-is-too-long
- https://crypto.stackexchange.com/questions/95629/using-aes-cbc-in-tls1-2
- https://stackoverflow.com/questions/8804574/aes-encryption-how-to-transport-iv

## Future work

- Define payload format
- nonce, `<node_name1, node_name2>`
- DH key exchange or ECDH key exchange https://github.com/pyca/cryptography/tree/main
