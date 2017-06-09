import hug
import socket
import time
from multiprocessing import Pool

def tcp_connect(ip, port_number):
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.settimeout(1) # If it takes longer than 1 second, is it worth it?
    try:
        tcp_sock.connect((ip, port_number))
        return True
    except:
        return False


@hug.get('/scans', examples='target=8.8.8.8&ports=21,22,23')
@hug.local()
def scans_get(target: hug.types.text, ports: hug.types.comma_separated_list, hug_timer=3):
    """Scans an IPv4 Address for open TCP Ports"""

    p = Pool(len(ports))
    scan_threads = [p.apply_async(tcp_connect, (target, port)) for port in ports]
    time.sleep(2)
    results = [result.get() for result in scan_threads]

    return {'target': '{}'.format(target),
            'ports': ports,
            'results': results,
            'took': float(hug_timer)}
