import sys
import zipfile
import optparse as opt
try:
    import cElementTree as ET
except:
    import xml.etree.cElementTree as ET

HEADER = '\033[95m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'

HOST_TYPE='./ListHost/Host'
NETWORK_TYPE='./ListNetwork/Network'
FAST_TYPE='./ListFast360/Fast360'
CLUSTER_TYPE='./ListCluster/Cluster'
NETGROUP_TYPE='./ListGroupNetObject/GroupNetObject'
SRVCGROUP_TYPE='./ListGroupService/GroupService'
SYSTEM_TCP_TYPE='./ListServiceSystemTcp/ServiceSystemTcp'
SYSTEM_UDP_TYPE='./ListServiceSystemUdp/ServiceSystemUdp'
SYSTEM_ICMP_TYPE='./ListServiceSystemIcmp/ServiceSystemIcmp'
SYSTEM_OTHER_TYPE='./ListServiceSystemOther/ServiceSystemOther'
USER_TCP_TYPE='./ListServiceUserTcp/ServiceUserTcp'
USER_UDP_TYPE='./ListServiceUserUdp/ServiceUserUdp'
USER_ICMP_TYPE='./ListServiceUserIcmp/ServiceUserIcmp'
USER_OTHER_TYPE='./ListServiceUserOther/ServiceUserOther'

TCP_PROTO=6
UDP_PROTO=17
ICMP_PROTO=1

hosts = {} 
networks = {} 
services = {}
fast360s = {} 
clusters = {} 
groups = {}
rules = [] 

class Host:
    def __init__(self, name, ip):
        self.name = name 
        self.ip = ip 

    def __repr__(self):
        r = self.name.encode(options.charset)
        if options.printmore:
            r += ' ('+printIP(self.ip)+')'
        return r

    def isHost(self, ip):
        if ip == self.ip or ip == 0:
            return True
        return False

    def getComplexity(self):
        return 1

class Network:
    def __init__(self, name, ip, mask):
        self.name = name 
        self.ip = ip 
        self.mask = 0xffffffff << (32 - mask)
        self.bitmask = mask

    def __repr__(self):
        r = self.name.encode(options.charset)
        if options.printmore is True:
            r += '('+printIP(self.ip)+'/'+str(self.bitmask)+')'
        return r

    def isInNetwork(self, ip):
        if ip == 0 or (ip & self.mask) == (self.ip & self.mask):
            return True
        return False

    def getComplexity(self):
        return 1

class Service:
    def __init__(self, name, proto, sportfrom, sportto, dportfrom, dportto):
        self.name = name
        self.proto = proto
        self.sportfrom = sportfrom
        self.sportto = sportto
        self.dportfrom = dportfrom
        self.dportto = dportto

    def __repr__(self):
        r = self.name.encode(options.charset)
        if options.printmore is True: 
            if self.dportfrom != self.dportto:
                r += '('+printProto(self.proto)+'/'+str(self.dportfrom)+'-->'+str(self.dportto)+')'
            else:
                r += '('+printProto(self.proto)+'/'+str(self.dportfrom)+')'
        return r

    def isService(self, proto, sport, dport):
        r = True
        if proto != 0 and proto != self.proto:
            r = False
        if sport != 0 and (sport < self.sportfrom or sport > self.sportto):
            r = False
        if dport != 0 and (dport < self.dportfrom or dport > self.dportto):
            r = False
        return r

    def getComplexity(self):
        return 1

class Group:
    def __init__(self, name):
        self.refs = set() 
        self.name = name

    def addRef(self, Guid):
        self.refs.add(Guid)

    def __repr__(self):
        return self.name.encode(options.charset)

    def isInGroup(self, ip, proto, sport, dport):
        r = False
        for ref in self.refs:
            if ref in hosts:
                r = hosts[ref].isHost(ip)
            elif ref in networks:
                r = networks[ref].isInNetwork(ip)
            elif ref in services:
                r = services[ref].isService(proto, sport, dport)
            elif ref in groups:
                r = groups[ref].isInGroup(ip, proto, sport, dport)
            else:
                r = False
            if r is True:
                return r 
        return False    

    def getComplexity(self):
        return getComp(self.refs)

class Rule:
    def __init__(self, element, name, Id, enabled, action, log):
        self.sources = []
        self.dests = []
        self.srvcs = []
        self.action = action 
        self.Id = Id 
        self.enabled = enabled 
        self.name = name 
        self.log = log
        self.comp = 1
        self.element = element

    def __repr__(self):
        r = str(self.Id)
        r += ' - ' + self.name.encode(options.charset)
        if isColumns('SRC') is True:
            r += ' Sources:'
            if len(self.sources) != 0:
                for s in self.sources:
                    r += printGuid(s)
                    if not s is self.sources[-1]:
                        r += ','
            else:
                r += 'All'

        if isColumns('DST') is True:
            r +=' Destinations:' 
            if len(self.dests) != 0:
                for d in self.dests:
                    r += printGuid(d)
                    if not d is self.dests[-1]:
                        r += ','
            else:
                r += 'All'

        if isColumns('SRV') is True:
            r+=' Services:' 
            if len(self.srvcs) != 0:
                for s in self.srvcs:
                    r += printGuid(s)
                    if not s is self.srvcs[-1]:
                        r += ','
            else:
                r += 'All'

        if isColumns('ACT') is True:
            r += ' Action:'+self.action
        if isColumns('LOG') is True:
            r += ' Log:'+self.log
        if isColumns('COMP') is True:
            r += ' Complexity:'+str(self.comp)
        return r
        
    def __cmp__(self, other):
        return self.Id - other.Id

    def addSource(self, src):
        self.sources.append(src)

    def addDest(self, dst):
        self.dests.append(dst)

    def addSrvc(self, srvc):
        self.srvcs.append(srvc)

    def setComplexity(self):
        self.comp = self.getComplexity()

    def match(self, collection, ip, proto, sport, dport):
        if len(collection) == 0:
            return True
        for e in collection:
            r = False
            if e in hosts:
                r = hosts[e].isHost(ip)
            elif e in networks:
                r = networks[e].isInNetwork(ip)
            if e in services:
                r = services[e].isService(proto, sport, dport)
            elif e in groups:
                r = groups[e].isInGroup(ip, proto, sport, dport)

            if r is True:
                return r
        return False

    def matchRule(self, src, dst, proto, sport, dport):
        if self.enabled is False:
            return False
        s = self.match(self.sources, src, 0, 0, 0)
        d = self.match(self.dests, dst, 0, 0, 0)
        sr = self.match(self.srvcs, 0, proto, sport, dport)
        return d and s and sr

    def getComplexity(self):
        sr = getComp(self.sources)
        dr = getComp(self.dests)
        ssr = getComp(self.srvcs)
        return sr*dr*ssr


def getHosts(root):
    hostlist = root.findall(HOST_TYPE)
    for hst in hostlist:
        ip = hst.find('./HostAddress/Address/Ip')
        if not ip is None and ip.attrib['Selected'] == 'true':
            hosts[hst.attrib['Guid']] = Host(hst.attrib['Name'], int(ip.attrib['Ip']))

def getNetworks(root):
    netlist = root.findall(NETWORK_TYPE)
    for net in netlist:
        addr = net.find('./NetworkParams/Address')
        if not addr is None :
            networks[net.attrib['Guid']] = Network(net.attrib['Name'], int(addr.attrib['Ip']), int(addr.attrib['Mask']))

def getGroups(root, gtype):
    netgroups = root.findall(gtype)
    for netgroup in netgroups:
        newGroup = Group(netgroup.attrib['Name'])
        groups[netgroup.attrib['Guid']] = newGroup 
        for ref in netgroup.findall('./Ref'):
            newGroup.addRef(ref.attrib['Ref'])

def getTypeOfService(root, Type, proto):
    srvs = root.findall(Type)
    for srv in srvs:
        dportfrom = 0
        dportto= 0
        sportfrom = 0
        sportto = 0
        sporten = 'false'
        if not srv.find('./General/Port') is None:
            dportfrom = int(srv.find('./General/Port').attrib['From'])
            dportto = int(srv.find('./General/Port').attrib['To'])
        if not srv.find('./General/Source') is None:
            sporten = srv.find('./General/Source').attrib['Enabled']
        protoelt = srv.find('./Protocol')
        uproto = proto
        if not protoelt is None:
            uproto = int(protoelt.text)
        if sporten == 'true' or sporten == '1':
            sportfrom = int(srv.find('./General/Source/Source').attrib['From'])
            sportto = int(srv.find('./General/Source/Source').attrib['To'])
        newService = Service(srv.attrib['Name'], proto, sportfrom, sportto, dportfrom, dportto)
        services[srv.attrib['Guid']] = newService

def getServices(root):
    getTypeOfService(root, USER_TCP_TYPE, TCP_PROTO)
    getTypeOfService(root, USER_UDP_TYPE, UDP_PROTO)
    getTypeOfService(root, USER_ICMP_TYPE, ICMP_PROTO)
    getTypeOfService(root, USER_OTHER_TYPE, 0)
    getTypeOfService(root, SYSTEM_TCP_TYPE, TCP_PROTO)
    getTypeOfService(root, SYSTEM_UDP_TYPE, UDP_PROTO)
    getTypeOfService(root, SYSTEM_ICMP_TYPE, ICMP_PROTO)
    getTypeOfService(root, SYSTEM_OTHER_TYPE, 0)

def getRules(root):
    rulesConf = root.findall('./ListRule/Rule')
    for ruleConf in rulesConf:
        sourcesGuid = ruleConf.findall('./Criteria/ListSource/Source')
        destsGuid = ruleConf.findall('./Criteria/ListDestination/Destination')
        servicesGuid = ruleConf.findall('./Criteria/ListService/Service')
        General = ruleConf.find('./General')
        Id = General.find('./SeqNum')
        Log = General.find('./Log')
        Block = ruleConf.find('./Action/Block')
        Reject = ruleConf.find('./Action/Reject')
        Accept = ruleConf.find('./Action/Accept')

        if Block.attrib['Selected'] == 'true':
            Action = 'Block'
        elif Reject.attrib['Selected'] == 'true':
            Action = 'Reject'
        else:
            Action = 'Accept'

        if General.attrib['Activated'] == '1' or General.attrib['Activated'] == 'true':
            Activated = True
        if General.attrib['Activated'] == '0' or General.attrib['Activated'] == 'false':
            Activated = False 

        newRule = Rule(ruleConf, ruleConf.attrib['Name'], int(Id.text), Activated, Action, Log.text)
        for sourceGuid in sourcesGuid:
            newRule.addSource(sourceGuid.attrib['Ref'])
        for destGuid in destsGuid:
            newRule.addDest(destGuid.attrib['Ref'])
        for serviceGuid in servicesGuid:
            newRule.addSrvc(serviceGuid.attrib['Ref'])
        newRule.setComplexity()
        rules.append(newRule)

def getComp(collection):
    r = 0 
    if len(collection) == 0:
        return 1
    for ref in collection:
        if ref in hosts:
            r += hosts[ref].getComplexity()
        elif ref in networks:
            r += networks[ref].getComplexity()
        elif ref in services:
            r += services[ref].getComplexity()
        elif ref in groups:
            r += groups[ref].getComplexity()
        else:
            r += 1
    return r

def parseIP(s):
    ip = 0
    sip = s.split('.')
    if len(sip) == 4:
        for o in sip:
            ip = (ip << 8) | int(o)
    return ip 

def printIP(ip):
    o = []
    for _ in xrange(4):
        o.insert(0, str(ip & 0xFF))
        ip >>= 8
    return '.'.join(o)

def printProto(proto):
    if proto == TCP_PROTO:
        return 'TCP'
    elif proto == UDP_PROTO:
        return 'UDP'
    elif proto == ICMP_PROTO:
        return 'ICMP'
    else:
        return str(proto)

def printGuid(Guid):
    if Guid in hosts:
        return str(hosts[Guid])
    elif Guid in networks:
        return str(networks[Guid])
    elif Guid in services:
        return str(services[Guid])
    elif Guid in groups:
        return str(groups[Guid])
    else:
        return Guid

def isColumns(ctype):
    optionlist = options.columns.split(',')
    if ctype in optionlist:
        return True
    return False

parser = opt.OptionParser()
fgroup = opt.OptionGroup(parser, "Filtering options", "Options used to filter rules")
ogroup = opt.OptionGroup(parser, "Output options", "Options used to print or write rules")
parser.add_option("-i", "--in-file", dest="infile",
        help="read configuration from FILE", metavar="FILE")
ogroup.add_option("-o", "--out-file", dest="outfile",
        help="wrtie result to FILE", metavar="FILE")
ogroup.add_option("-x", "--xml", action="store_true", dest="outxml",
        help="print or write in XML format", default=False)
parser.add_option("-p", "--print", action="store_true", dest="printrules", default=False,
        help="just print rules and exit (filtering options will be ignored)")
fgroup.add_option("-s", "--ip-src", dest="ipsrc", default="0.0.0.0", metavar="aaa.bbb.ccc.ddd",
        help="packet source IP")
fgroup.add_option("-d", "--ip-dst", dest="ipdst", default="0.0.0.0", metavar="aaa.bbb.ccc.ddd",
        help="packet destination IP")
fgroup.add_option("-P", "--ip-protocol", type="int", dest="ipproto", default=0, metavar="PROTOCOL",
        help="packet IP protocol number")
fgroup.add_option("-S", "--port-src", type="int", dest="portsrc", default=0, metavar="SOURCEPORT",
        help="packet source port number")
fgroup.add_option("-D", "--port-dst", type="int", dest="portdst", default=0, metavar="DESTPORT",
        help="packet destination port number")
fgroup.add_option("-1", "--first-match", action="store_true", dest="firstm", default=False,
        help="stop filtering after first match")
fgroup.add_option("-c", "--complexity", type="int", dest="compl", default=0, metavar="COMPLEXITY",
        help="rule complexity threshold")
ogroup.add_option("-C", "--sort-by-complexity", action="store_true", dest="sortcomp", default=False,
        help="sort Result by complexity")
ogroup.add_option("-e", "--encode", dest="charset", default="latin_1", metavar="CHARSET",
        help="sort Result by complexity")
ogroup.add_option("-t", "--show-columns", dest="columns", default="SRC,DST,SRV,ACT,LOG,COMP", metavar="SRC,DST,SRV,ACT,LOG,COMP",
        help="Choose columns to print (SRC,DST,SRV,ACT,LOG,COMP)")
ogroup.add_option("-m", "--print-more", dest="printmore", action="store_true", default=False,
        help="Print more information about Host, Network or Services")
fgroup.add_option("-a", "--all-rules", action="store_true", dest="disrules", default=False,
        help="show all rules (even disabled)")

parser.add_option_group(fgroup)
parser.add_option_group(ogroup)

(options, args) = parser.parse_args()

if options.infile is None:
    parser.error('Please enter a configuration name')

print HEADER+'Loading file '+options.infile+'...'+ENDC,
sys.stdout.flush()
try:
    if zipfile.is_zipfile(options.infile):
        zfile = zipfile.ZipFile(options.infile)
        znames = zfile.namelist()
        if len(znames) == 1:
            zfile.extract(znames[0])
            infile = znames[0]
        else:
            infile = options.infile
    else:
        infile = options.infile
    tree = ET.parse(infile)
except:
    print FAIL+"[failed]"+ENDC
    sys.exit(1)
print OKGREEN+'[done]'+ENDC

print HEADER+'Creating database...'+ENDC,
sys.stdout.flush()
root = tree.getroot()
getHosts(root)
getNetworks(root)
getGroups(root, NETGROUP_TYPE)
getGroups(root, SRVCGROUP_TYPE)
getServices(root)
# Rules must be called at the end to compute the right complexity
getRules(root)
rules = sorted(rules)
print OKGREEN,len(rules),'rules,',len(hosts),'hosts,',len(networks),'networks,',len(groups),'groups [done]'+ENDC

print HEADER+'Finding Rule...'+ENDC,
sys.stdout.flush()
sip = parseIP(options.ipsrc)
dip = parseIP(options.ipdst)
resrules = []
if options.printrules is True:
    resrules = rules
else:
    for rule in rules:
        if rule.matchRule(sip, dip, options.ipproto, options.portsrc, options.portdst) == True:
            resrules.append(rule)
            if options.firstm is True:
                break

if options.sortcomp is True:
    resrules.sort(key = lambda x:x.comp)
print OKGREEN+'[done]'+ENDC

outfile = None
if not options.outfile is None:
    try:
        if options.outxml is False:
            # Don't need to open file for ET.write
            outfile = open(options.outfile, 'w')
        else:
            outfile = options.outfile
    except:
        pass

if outfile is None:
    for rule in resrules:
        if rule.comp >= options.compl and (rule.enabled or options.disrules):
            if options.outxml is True:
                ET.dump(rule.element)
            else:
                print rule
elif options.outxml is True:
    print HEADER+'Creating output file '+outfile+' ...'+ENDC,
    sys.stdout.flush()
    outET = ET.ElementTree()
    outRoot = ET.Element('Rules')
    for rule in resrules:
        if rule.comp >= options.compl and (rule.enabled or options.disrules):
            outRoot.insert(-1, rule.element)
    outET._setroot(outRoot)
    outET.write(outfile)
    print OKGREEN+'[done]'+ENDC
else:
    print HEADER+'Creating output file '+outfile+' ...'+ENDC,
    sys.stdout.flush()
    for rule in resrules:
        if rule.comp >= options.compl and (rule.enabled or options.disrules):
            outfile.write(str(rule)+'\n')
    outfile.close()
    print OKGREEN+'[done]'+ENDC
