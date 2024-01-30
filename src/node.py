# Import custom classes for the Receiver and Transmitter
from receiver import Receiver
from transmitter import Transmitter
from receiver_rsa import Receiver as ReceiverRsa
from transmitter_rsa import Transmitter as TransmitterRsa
from multiprocessing import set_start_method
import sys

from constant import *
from front_end.api import Web
import utils

def main():
    try: 
        # Check the number of command-line arguments
        if (len(sys.argv) != 2):
            print("Usage: python3 node.py <node_name>")
            sys.exit(1)

        if IS_CERTIFICATE is True and ECCDH is False:
            print("Certificate is only supported for ECCDH")
            sys.exit(1)

        # https://github.com/pytest-dev/pytest-flask/issues/104#issuecomment-577908228
        set_start_method("fork")

        # Create a list to keep track of running processes
        process_list = []
        if ECCDH:
            # generate certificate
            if IS_CERTIFICATE:
                utils.generate_certificate(sys.argv[1])

            # Initialize a Receiver instance with the given node name and start it
            rx = Receiver(sys.argv[1])
            rx.start()

            # Add the Receiver instance to the process list
            process_list.append(rx)

            # Initialize a Transmitter instance with the given node name and start it
            tx = Transmitter(sys.argv[1])
            tx.start()

            # Add the Transmitter instance to the process list
            process_list.append(tx)
        else:
            rx = ReceiverRsa(sys.argv[1])
            rx.start()
            process_list.append(rx)
            tx = TransmitterRsa(sys.argv[1])
            tx.start()
            process_list.append(tx)

        # Add the Web to view neighbors
        web = Web(sys.argv[1])
        web.start()

        process_list.append(web)

        # Wait for all processes to finish before exiting, 
        # This ensures that the script waits for all processes to finish their execution before exiting
        for i in process_list:
            i.join()
    except KeyboardInterrupt:
        print("\n[+] Exiting gracefully...")
        pass

if __name__ == '__main__':
    main()
