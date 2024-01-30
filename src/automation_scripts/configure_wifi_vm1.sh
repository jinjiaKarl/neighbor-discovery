#!/bin/bash

# Turn off wlan0
sudo ifconfig wlan0 down

# Configure wlan0 in ad-hoc mode with the specified settings
sudo iwconfig wlan0 mode ad-hoc essid HELLO enc off channel 5

# Turn on wlan0
sudo ifconfig wlan0 up

# Assign IP address and netmask to wlan0
sudo ifconfig wlan0 10.0.0.1 netmask 255.255.255.0

# Print status
echo "Configuration of wlan0 complete."
