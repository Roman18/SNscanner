import os
import sys

from threading import Thread
import time

from scanners import HostScanner

if __name__ == '__main__':
    if os.name != "nt":
        if os.getuid() != 0:
            sys.stderr.write('Need root permissions\n')
            sys.exit(1)

    try:
        h_scanner = HostScanner('<ip_of_your_machine>', 'subnet')
        time.sleep(5)
        thread = Thread(target=h_scanner.send_udp)
        thread.start()
        hosts = h_scanner.host_scan()
        #print(hosts)
    except Exception as e:
        sys.stderr.write('Something went wrong\n')
