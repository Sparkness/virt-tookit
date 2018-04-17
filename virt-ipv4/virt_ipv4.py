import sys
import getopt
import csv
import nmap
import libvirt

from xml.etree import ElementTree


class LibvirtConnector(object):
    def __init__(self, libvirtstring):
        # libvirtString format: {'libvirt_host': $, 'libvirt_connectionString': $, 'libvirt_credentials': [userid,
        # password],'libvirt_Guest': $}
        # if not isinstance(dict, libvirtstring):
        #     print('invalid parameter type: ' + 'libvirtstring')
        self.host = libvirtstring['libvirt_host']
        self.__connString = libvirtstring['libvirt_connectionString']
        self.__SASL_USER = libvirtstring['libvirt_credentials'][0]
        self.__SASL_PASS = libvirtstring['libvirt_credentials'][1]
        # self.__guest = libvirtstring['libvirt_Guest']
        self.__conn = self.__open_connection()

    def __open_connection(self):
        # auth = [[libvirt.VIR_CRED_USERNAME, libvirt.VIR_CRED_PASSPHRASE], self.__request_cred, None]
        # conn = libvirt.openAuth(self.__connString, auth, 0)
        conn = libvirt.openReadOnly(self.__connString)
        if conn is None:
            print('Failed to open connection to ' + str(self.__connString), file=sys.stderr)
            return 'Failed to open connection to libvirt host'
        return conn

    def __request_cred(self, credentials, user_data):
        for credential in credentials:
            if credential[0] == libvirt.VIR_CRED_USERNAME:
                credential[4] = self.__SASL_USER
            elif credential[0] == libvirt.VIR_CRED_PASSPHRASE:
                credential[4] = self.__SASL_PASS
        return 0

    def get_libvirt_conn(self):
        return self.__conn


def get_host_mac(net):
    nm = nmap.PortScanner()
    nm.scan(hosts=net, arguments='-sP')
    host_list = nm.all_hosts()
    mc = []
    for host in host_list:
        # print(nm[host]['addresses'])
        mc.append(nm[host]['addresses'])
    return mc


def writelisttocsv(csv_file, csv_columns, data_list):
    try:
        with open(csv_file, 'w') as csvfile:
            writer = csv.writer(csvfile, dialect='excel', quoting=csv.QUOTE_NONNUMERIC)
            writer.writerow(csv_columns)
            for data in data_list:
                writer.writerow(data)
    except IOError as e:
        #
        print('error')
    return


def get_guest_disks(dom):
    tree = ElementTree.fromstring(dom.XMLDesc())
    disk_list = tree.findall('devices/disk')
    diskinfo = []
    disks = ''
    for disk in disk_list:
        try:
            i = disk.find('source').get('file')
            name = disk.find('target').get('dev')
        except AttributeError:
            continue
        info = name + ' ' + i
        diskinfo.append(info)
    if len(diskinfo) > 1:
        for disk in diskinfo:
            disks += disk + ', '
    elif len(diskinfo) == 1:
        disks = diskinfo[0]
    else:
        print('error')
    return disks


def get_mrecord(host, net, user, port):
    try:
        libvirtstring = dict(libvirt_host=host,
                             libvirt_connectionString='qemu+ssh://' + user + '@' + host + ':' + port + '/system?socket=/var/run/libvirt/libvirt-sock',
                             libvirt_credentials=[user, 'password'])
        # print(libvirtstring)
        libvirtconnect = LibvirtConnector(libvirtstring)
    except libvirt.libvirtError as e:
        print('libvirt connection error:\n\t%s' % e)
        sys.exit(2)
    conn = libvirtconnect.get_libvirt_conn()
    ip_mac = get_host_mac(net)
    # for dom_id in conn.listDomainsID():
    #     dom_list.append(conn.lookupByID(dom_id))
    dom_list = map(conn.lookupByID, conn.listDomainsID())
    mrecord = []
    for dom in dom_list:
        tree = ElementTree.fromstring(dom.XMLDesc())
        ifaces = tree.findall('devices/interface/mac')
        i = ifaces[0].get('address').upper()
        diskinfo = get_guest_disks(dom)
        for row in ip_mac:
            name_mac = []
            try:
                mac = row['mac']
                # print(mac)
            except KeyError as e:
                # print('Invalid value %s' % e)
                continue
            if mac == i:
                # print(mac, i)
                name_mac.append(dom.name())
                name_mac.append(i)
                name_mac.append(row['ipv4'])
                name_mac.append(diskinfo)
                # print(name_mac)
                mrecord.append(name_mac)
                # print(mrecord)
                break
            else:
                # print(mac, i)
                continue
    return mrecord


def main(argv):
    cmd_help = 'options: -h <host> -n <net> -u <user> -p <port>(options default: 22)\n\teg: -h 127.0.0.1 -n 192.168.1.0/24 -u root'
    if not argv:
        print(cmd_help)
        sys.exit(2)
    try:
        opts, args = getopt.getopt(argv, "h:n:u:p:", ["help", "host=", "net=", "user=", "port="])
    except getopt.GetoptError:
        print(cmd_help)
        sys.exit(2)
    port = '22'
    for opt, arg in opts:
        if opt == '--help':
            sys.exit()
        elif opt in ("-h", "--host"):
            host = arg
        elif opt in ("-n", "--net"):
            net = arg
        elif opt in ("-u", "--user"):
            user = arg
        elif opt in ("-p", "--port"):
            port = arg
    # print(host, net, user)
    csv_data = get_mrecord(host, net, user, port)
    csv_column = ['name', 'mac', 'ipv4', 'disk']
    writelisttocsv('%s.csv' % host, csv_column, csv_data)
    print(host + ' guest info file: %s.csv' % host)


if __name__ == "__main__":
    main(sys.argv[1:])
