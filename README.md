# SNscan tool

## Tool to find alive hosts in provided subnet

### Main idea
The way the scanner determines the active hosts is that it sends UDP
requests with a random MESSAGE to all hosts on the subnet. If the host is up, it responds with an ICMP 
frame and the following data: type 3 (Destination unreachable), code 3 (Port unreachable). Also, there is the a check
that ICMP frame contains MESSAGE from UDP to restrict it from other ICMP packages on the network.
So, it means the host is up

### Common usage

```commandline
python3 snscan.py comp_ip subnet
# Example
python3 snscan.py 192.168.0.20 192.168.0.0/24 
```

### TODO:
Once you have found all active hosts, run a port scanner for each host.