## How to create an ad-hoc netrowk

prerequisite
* 2 virtual machines
    * preferrably kali 2023.3 (tested on this version, most drivers are pre-installed)
* 2 wifi adapters
    * alfa awus036achm (tested on this adapter)

Now we have two vms, called vm1 and vm2.

To be able to add the devices to the VMs, follow the instructions below (VM Virtual Box) while your VM is not running:
* Choose USB Controller (for us, it was USB 3.0 (xHCI) Controller
* Add the device
    * Settings --> USB --> Adds new USB filter... --> Choose MediaTek Wifi

Check the USB is connected using:
```
 iwconfig  
 ```
Following should be visible:
```
wlan0     IEEE 802.11  ESSID:off/any  
          Mode:Managed  Access Point: Not-Associated   Tx-Power=17 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:off
```

In the vm1, execute the following command to create an ad-hoc network in the root mode
```bash
ifconfig wlan0 down
iwconfig wlan0 mode ad-hoc essid HELLO enc off channel 5
ifconfig wlan0 up
ifconfig wlan0 10.0.0.1 netmask 255.255.255.0
```

In the vm2, execute the following command to create an ad-hoc network in the root mode
```bash
ifconfig wlan0 down
iwconfig wlan0 mode ad-hoc essid HELLO enc off channel 5
ifconfig wlan0 up
ifconfig wlan0 10.0.0.2 netmask 255.255.255.0
```

Now we have two devices connected, and we can ping each other.
```bash
# this command will show the connected devices
iw dev wlan0 station dump

# ping 
vm1 > ping 10.0.0.2 -c 5
```

Let's try run a simple tcp server and client.
```
vm1 > git clone -b feat/ping-pong git@gits-15.sys.kth.se:project-6-snd-securitas/SND.git
vm1 > cd test_wifi_adapter && python3 echo_server.py


vm2 > git clone -b feat/ping-pong git@gits-15.sys.kth.se:project-6-snd-securitas/SND.git
vm2 > cd test_wifi_adapter && python3 echo_client.py
```

ToDo:
* Check AP mode for neighbor discovery

future plans:
* implement a p2p application to do neighbor discovery in the ad-hoc network
    * authentication
    * encryption (need or not)
    * time-based
    * location-based
    * time-location-based
* implement a attacker module to do some attack scenarios
    * intercept packets among the ad-hoc network
    * man-in-the-middle attack
* metrics
    * performance
        * processing dedays
        * communication distance 
        * channel conditions
        * different types of attacks
