virt_ipv4
============

usage
------------

options: -h [host] -n [net] -u [user] -p [port](options default: 22)

    eg: sudo python virt_ipv4.py -h 127.0.0.1 -n 192.168.1.0/24 -u root -p 22

tips:
    you must run this with sudo, because of the nmap portscaner.


troubleshooting
------------

make sure you can connect to your host by SSH.

if you get error:

    libvirt connection error:
        internal error: received hangup event on socket

you should check the SSH and libvirtd services, and you would better to check your `.ssh/known_hosts`.

