from Location_DH_atck_receiver import AtckReceiver
from atck_constant import *


def main():

    process_list = []
    rx = AtckReceiver(NODE_NAME)
    rx.start()
    process_list.append(rx)

    for i in process_list:
        i.join()

if __name__ == '__main__':
    main()
