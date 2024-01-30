import rssi

ap1 = {
        "signalAttenuation": 3,
        "location": {
            "x": 1,
            "y": 1
        },
        "reference": {
            "distance": 50,
            "signal": -50
        },
        "name": "KTHOPEN"
    }

ap2 = {
        "signalAttenuation": 4,
        "location": {
            "x": 1,
            "y": 7
        },
        "reference": {
            "distance": 3,
            "signal": -41
        },
        "name": "eduroam"
    }

ap3 = {
        "signalAttenuation": 4,
        "location": {
            "x": 5,
            "y": 7
        },
        "reference": {
            "distance": 7,
            "signal": -70
        },
        "name": "secclo"
    }


accessPoints = [ ap1, ap2, ap3]

# caclulate position
ssids = ["KTHOPEN", "eduroam", "secclo"]
scanner = rssi.RSSI_Scan()
ap_info = scanner.getAPinfo(networks=ssids, sudo=True)
signal_strength = [ap['signal'] for ap in ap_info]
localizer  = rssi.RSSI_Localizer(accessPoints)
position = localizer.getNodePosition(signal_strength)
print(position)


# 知道对方的信息ap(自己的位置，编造一个)，以及signal_strength，就能知道距离；因此需要传输AP信息
# calculate distance from one access point
# because the connection is not stable, we can specify the signal strength


signal_strength = -50 
distance = localizer.getDistanceFromAP(ap1, signal_strength)
print(distance)
