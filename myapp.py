import networkx as nx
from ryu import utils
import socket
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ipv4, vlan
from ryu.lib.packet import tcp
from ryu.ofproto import ofproto_v1_0, ofproto_v1_3, ofproto_v1_2
from ryu.lib.packet import packet
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import ethernet
import time
import random
from threading import Lock
from thread import start_new_thread
import struct
from ryu.ofproto.ofproto_v1_0 import OFPP_NONE
from ryu.topology import event,switches
from ryu.topology.api import get_switch,get_link


# Type varibale
ethernet_non_vlan = '0x0800'
# Define long term rate
long_term_rate = 10 # pke/sec
# Time interval
rate_interval = 3
request_interval = 2
STAT_INTERVAL = 5

# Threshold value
fd = 5
drop = 10

# Container for events
dpid2event = {}

# Container for topology
name2ovs = {}
name2sw = {}

#Relate parameters
ovscandidate = []
switchcandidate = []
hostcandidate = []

#Relate parameters
dpid2ovs= {}
dpid2switch= {}
dpid2mpls = {}
dpidplusport2vlandid = {}
ip2host={}
dpid
vlan2dpid= {}

# match variable
wildcards = ofproto_v1_0.OFPFW_ALL
dl_src = None
dl_dst = None
ip_src = None
ip_dst = None
tcp_src_port = None
tcp_dst_port = None
ethernet_type = None
ofproto = None
proto=None
in_port = None
data_device = None
vlan_id = None
vlan_pcp = None

## rate relate tuples
dpid_list = []
unique_port = {}
ovsdpid2time_size = {}

# Send specific packet out to the destination
def packet_out(msg,out_port):
    if out_port == None:
        return -1
    actions = [data_device.ofproto_parser.OFPActionOutput(out_port)]
    if msg == None:
        return -1
    out = data_device.ofproto_parser.OFPPacketOut(
        datapath=data_device, in_port=in_port, buffer_id=0xffffffff,
        actions=actions, data=msg.data)
    data_device.send_msg(out)
    return 0

# Change the str to integer
def listtosrt(list):
    str1 = ""
    for ele in list:
        str1 += ele
    return str1

def listtoint(list):
    int = 0
    for ele in list:
        int += ele
    return int


# Parse the packet and get the match variables
def parse_packet(msg):

    global in_port
    global dl_dst
    global dl_src
    global ip_dst
    global ip_src
    global ethernet_type
    global data_device
    global proto
    global tcp_src_port
    global tcp_dst_port
    global ofproto
    global vlan_id
    global vlan_pcp

    pkt = packet.Packet(msg.data)
    eth = pkt.get_protocol(ethernet.ethernet)
    tcp_instance = pkt.get_protocol(tcp.tcp)
    ip = pkt.get_protocol(ipv4.ipv4)
    vlan_pkf = pkt.get_protocol(vlan.vlan)


    if eth == None:
        return -2
    if ip == None:
        return -1
    if tcp_instance == None:
        return -3

    in_port = msg.in_port
    dl_dst = eth.dst
    dl_src = eth.src
    ip_dst = ip.dst
    ip_src = ip.src
    ethernet_type = eth.ethertype
    data_device = msg.datapath
    ofproto = data_device.ofproto
    proto = ip.proto
    tcp_src_port = tcp_instance.src_port
    tcp_dst_port = tcp_instance.dst_port

    if vlan_pkf != None:
        vlan_id = vlan_pkf.vid
        vlan_pcp = vlan_pkf.pcp
        ethernet_type =vlan_pkf.ethertype
        return 2

    return 0

# Deal with the normal flow and packet rate
def handle_normal_flow(msg):

    endhost = None
    switch = None
    out_port = -1
    dpid = None

    var = parse_packet(msg)

    if var==-1 or var ==-2 or var == -3:
        print("Wrong packet!")
        return -1

    dpid = data_device.id

    #Get end_host

    endhost = ip2host.get(ip_dst)

    #print(ip_dst)
    #print(ip2host)
    #print(endhost)
    #print(dpid)

    #Get datapath and out_port

    if dpid2ovs.get(dpid) == None:
        if dpid2switch.get(dpid) == None:
            print("Can not find the switch !")
            return -1
        else:
            switch = dpid2switch.get(dpid)
            dict = name2sw.get(switch)
            out_port_str = dict.get(endhost)
            if out_port_str == None:
                print("No out_put port!")
                return -1
            out_port = int(out_port_str)
    else:
        switch = dpid2ovs.get(dpid)
        dict = name2ovs.get(switch)
        out_port_str = dict.get(endhost)
        out_port = int(out_port_str)

        if out_port == -1:
            print("Wrong out_port!")
            return -1

    actions = [data_device.ofproto_parser.OFPActionOutput(out_port)]

    if var == 2:
        match = data_device.ofproto_parser.OFPMatch(
            in_port=in_port,
            dl_dst=haddr_to_bin(dl_dst), dl_src=haddr_to_bin(dl_src), dl_type=ethernet_type,
            nw_proto=proto, tp_src=tcp_src_port, tp_dst=tcp_dst_port,
            nw_dst=ip_dst, nw_src=ip_src,dl_vlan=vlan_id,dl_vlan_pcp=vlan_pcp)
    elif var ==0:
        match = data_device.ofproto_parser.OFPMatch(
            in_port=in_port,
            dl_dst=haddr_to_bin(dl_dst), dl_src=haddr_to_bin(dl_src),dl_type=ethernet_type,
            nw_proto=proto,tp_src=tcp_src_port,
            tp_dst=tcp_dst_port,nw_dst=ip_dst,nw_src=ip_src)

        #print("ip_src")
        #print(ip_src)
        #print("ip_dst")
        #print(ip_dst)
        #print("tcp_src_port")
        #print(tcp_src_port)
        #print("tcp_dst_port")
        #print(tcp_dst_port)
        #print(match)

    mod = data_device.ofproto_parser.OFPFlowMod(
        datapath=data_device, match=match, cookie=0,
        command=ofproto.OFPFC_ADD, idle_timeout=10000, hard_timeout=10000,
        priority=ofproto.OFP_DEFAULT_PRIORITY,
        flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
    data_device.send_msg(mod)

    if packet_out(msg,out_port) == -1:
        print("Packet out errors!")
        return -1
    return 0

# Randomly pick up an out_port for a software switch

def pickup_port(msg):

    out_port = None
    node = None
    target = None
    pick_dpid = None
    dict = None

    start_time = 0

    datapath = msg.datapath
    dpid = datapath.id
    node = dpid2switch[dpid]
    dict = name2sw[node]

    while 1:
        if start_time == 0:
            start_time = time.time()
        else:
            if time.time() - start_time > 1:
                return -2

        selected_dpid = random.sample(dpid_list,1)
        selected_dpid = listtoint(selected_dpid)

        while selected_dpid == dpid:
            selected_dpid = random.sample(dpid_list,1)
            selected_dpid = listtoint(selected_dpid)

        #print(dpid)
        #print(selected_dpid)


        if selected_dpid in dpid2ovs.keys():

            selected_node = dpid2ovs[selected_dpid]
            port_str = dict[selected_node]
            port_number = int(port_str)
            dict_port = unique_port[dpid+port_number]
            rate = dict_port["rate"]

            if rate > fd:
                continue
            else:
                out_port = port_number
                break
        elif selected_dpid in dpid2switch.keys():

            selected_node = dpid2switch[selected_dpid]
            #print(dict)
            port_str = dict[selected_node]
            port_number = int(port_str)
            dict_port = unique_port[dpid+port_number]
            rate = dict_port["rate"]

            if rate > fd:
                continue
            else:
                out_port = port_number
                break

    return out_port


# Add MPLS header, set_header fields and add forward rules
def add_vland_flow(msg):

    vlan_lable = None

    var = parse_packet(msg)

    if var == -1 or var == -2 or var == -3:
        return -1

    dpid = data_device.id
    key = dpid+in_port
    vlan_lable = dpidplusport2vlandid.get(key)
    out_port_str = pickup_port(msg)
    out_port= int(out_port_str)

    if vlan_lable == -1:
        print("Wrong Vlan")
        return -1
    if out_port == -1:
        print("Wrong out_port")
        return -1
    elif out_port == -2:
        print("Drop packet!")
        return -2

    # Deal with like normal flow
    if handle_normal_flow(msg) == -1:
        print("Normal flow packet errors!")
        return -1

    # Deal with the subsequent flows and packet
    actions = actions = [data_device.ofproto_parser.OFPActionVlanVid(vlan_lable),
               data_device.ofproto_parser.OFPActionOutput(out_port)]

    match = data_device.ofproto_parser.OFPMatch()

    #print(actions)
    #print(key)
    #print(dpid)
    #print(in_port)

    mod = data_device.ofproto_parser.OFPFlowMod(
        datapath=data_device, match=match, cookie=0,
        command=ofproto.OFPFC_ADD, idle_timeout=10000, hard_timeout=10000,
        priority=ofproto.OFP_DEFAULT_PRIORITY,
        flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

    data_device.send_msg(mod)

    return 0

def rate(self):

    pretime = None
    presize = None
    eventsize = None

    while 1:
        # physical switch rate calculation
        key_list = unique_port.keys()
        for key in key_list:
            dict = unique_port.get(key)
            pretime = dict.get("pretime")
            presize = dict.get("presize")
            eventsize = dict.get("eventsize")

            if pretime == 0:
                dict["pretime"] = time.time()
                dict["presize"] = eventsize
            else:
                current = time.time()
                if current - pretime > rate_interval:
                    diff = current -pretime
                    packet_rate = (eventsize -presize)/diff
                    dict["presize"] = eventsize
                    dict["pretime"] = current
                    if packet_rate < 0 :
                        packet_rate = 0
                    print("New packet rate from physical switch :" + str(key) )
                    print(packet_rate)
                    dict["rate"] = packet_rate

        # Software swtich rate calculation
        key_list = dpid2ovs.keys()
        for dpid in key_list:
            dict = ovsdpid2time_size[dpid]
            pretime = dict.get("pretime")
            presize = dict.get("presize")
            eventsize = dict.get("eventsize")

            if pretime == 0:
                dict["pretime"] = time.time()
                dict["presize"] = eventsize
            else:
                current = time.time()

                if current - pretime >= rate_interval:

                    diff = current - pretime
                    packet_rate = (eventsize - presize) / diff
                    dict["presize"] = eventsize
                    dict["pretime"] = current
                    if packet_rate < 0:
                        packet_rate = 0
                    print("New packet rate from software switch")
                    #print(dpid)
                    print(packet_rate)
                    dict["rate"] = packet_rate

        hub.sleep(rate_interval)

def request_porcess(dict, event, ovs):

    start_time = 0
    end_time = 0
    switch = True
    packet_drop = 0

    while dict.get("eventsize") != 0:

        if switch == True:

            start_time = time.time()
            switch = False
            end_time = time.time()

        if end_time - start_time > 0.5:

            hub.sleep(1)
            switch = True

        if dict["rate"] >= fd:
            if dict["rate"] <= drop:
                if ovs == True:
                    print("Packet dropped!")
                    event.pop()
                    dict["eventsize"] -= 1
                    print(dict["rate"])
                else:
                    ev = event[len(event)-1]
                    msg = ev.msg
                    print("Forwarding\n")
                    var =

(msg)

if var == 0:
                        #print("rate: ")
                        #print(dict["rate"])
                        event.pop()
                        dict["eventsize"] -= 1
                    elif var == -2:
                        print("Can not find next hub, packet has to be dropped !")
                        event.pop()
                        dict["eventsize"] -= 1
                    else:
                        print("Insert vlan is failed !\n")
                        continue
            else:
                print("rate: ")
                print(dict["rate"])

                if packet_drop > 20:
                    hub.sleep(0.5)
                    packet_drop = 0

                event.pop()
                dict["eventsize"] -= 1
                packet_drop = packet_drop+1
        else:
            #lock.acquire()
            print("Handle normal packet!")
            ev = event[len(event) - 1]
            msg = ev.msg
            if handle_normal_flow(msg) != 0:
                print("Normal Packet can not be handled")
            else:
                print("rate:")
                print(dict["rate"])
                event.pop()
                dict["eventsize"] -= 1
                print(dict["eventsize"])
            #lock.release()

def request(self):

    event = None
    ovs = False
    dict = None

    while 1:

        for dpid in dpid_list:

            if dpid2switch.get(dpid) != None:

                node = dpid2switch.get(dpid)
                dict_port = name2sw.get(node)
                value_list = dict_port.values()
                ovs = False

                for value in value_list:

                    print("Physical switch request from port :" + value)
                    value = int(value)
                    dict = unique_port[dpid+value]
                    event = dict["event"]
                    request_porcess(dict, event, ovs)
                    hub.sleep(request_interval)

            elif dpid2ovs.get(dpid) != None:

                print("Software switch request")
                ovs = True
                dict = ovsdpid2time_size[dpid]
                event = dict["event"]
                #print(ovs)
                request_porcess(dict, event, ovs)
                hub.sleep(request_interval)

            else:
                print("Can not find the node")
                hub.sleep(request_interval)
                continue

def send_flow_stat_request(self):

    while True:
        
        print("send flow stat request!")
        for dpid in dpid2ovs.keys():

            if dpid not in dpid2datapath.keys():
                continue
               
            datapath = dpid2datapath[dpid]
            ofproto = datapath.ofproto
            ofproto_parser = datapath.ofproto_parser

            match = ofproto_parser.OFPMatch(wildcards=ofproto.OFPFW_ALL)

            req = ofproto_parser.OFPFlowStatsRequest(
                datapath=datapath, flags=0,
                match=match,table_id=0,out_port=OFPP_NONE)

            datapath.send_msg(req)

        hub.sleep(STAT_INTERVAL)

class Threshold(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        first_ovs = 0
        first_sw = 0
        Mpls_label = 2
        vlan_label = 2
        super(Threshold, self).__init__(*args, **kwargs)
        self.x = ''
        self.x = raw_input('input config file path/filename\n')
        self.switch_list = {}
        self.grap = nx.Graph()

        f = open(self.x, 'r')
        if 'exit' not in self.x:
            for line in f:
                array = line.split(' ')
                if 'ovs' in array[0]:
                    ovscandidate.append(array[0])
                    ovs = {}
                    for member in array:
                        if "ovs" in member:
                            if first_ovs == 0:
                                first_ovs = first_ovs +1
                                continue
                        elif 'dpid' in member:

                            tuple = member.split(':')
                            tuple[1] = tuple[1].replace("\n", "")
                            tuple[1] = tuple[1].replace("\n", "d")
                            int_dpid = int(tuple[1], 16)
                            dpid2ovs[int_dpid] = array[0]
                            dpid_list.append(int_dpid)
                            ovsdpid2time_size[int_dpid] = {}
                            dict = ovsdpid2time_size[int_dpid]
                            dict["pretime"] = 0
                            dict["presize"] = 0
                            dict["eventsize"] =0
                            dict["rate"] =0
                            dict["event"] = []

                            if Mpls_label < 500:
                                dpid2mpls[int_dpid] = Mpls_label
                                Mpls_label = Mpls_label+1
                            else :
                                print("Mpls_lable out of range!")
                                exit(0)
                        else:
                            tuple = member.split(':')
                            tuple[1] = tuple[1].replace("\n", "")
                            ovs[tuple[0]] = tuple[1]
                    name2ovs[array[0]] = ovs
                if 'sw' in array[0]:
                    switchcandidate.append(array[0])
                    sw = {}
                    for member in array:
                        if "sw" in member:
                            if first_sw == 0 :
                                first_sw = first_sw+1
                                continue
                        elif 'dpid' in member:
                            tuple = member.split(':')
                            tuple[1] = tuple[1].replace("\n", "")
                            int_dpid = int(tuple[1],16)
                            dpid2switch[int_dpid] = array[0]
                            dpid_list.append(int_dpid)
                            if Mpls_label < 10000:
                                dpid2mpls[int_dpid] = Mpls_label
                                Mpls_label = Mpls_label+1
                            else :
                                print("Mpls_lable out of range!")
                                exit(0)
                        else:
                            tuple = member.split(':')
                            tuple[1] = tuple[1].replace("\n", "")
                            sw[tuple[0]] = tuple[1]
                            name2sw[array[0]] = sw
                if 'host' in array[0]:
                    array = line.split(' ')
                    array[1] = array[1].replace("\n", "")
                    hostcandidate.append(array[0])
                    for member in array:
                        if "host" in member:
                            continue
                        else:
                            member = member.replace("\n", "")
                            ip2host[member] = array[0]
                    continue
        else:
            exit(0)

        #Unique port mapping

        key_list = dpid2switch.keys()
        for dpid in key_list:
            node = dpid2switch.get(dpid)
            dict = name2sw.get(node)
            value_list = dict.values()
            for value in value_list:
                value = int(value)
                key = dpid + value
                unique_port[key] = {}
                list = unique_port[key]
                list["pretime"] = 0
                list["event"] = []
                list["presize"] = 0
                list["eventsize"] = 0
                list["rate"] = 0

        # Build vlan match for each port of individual datapath

        vlan_dp = 1
        for dpid in dpid2switch.keys():

            node_name = dpid2switch[dpid]
            dict = name2sw[node_name]

            for keys in name2sw[node_name].keys():
                if 'ovs' in keys:
                    continue
                elif 'host' in keys:
                    port_number = dict.get(keys)
                    port_number = int(port_number)
                    vlan_id = vlan_dp*100 + port_number
                    if vlan_id < 10000:
                        dpidplusport2vlandid[dpid+port_number] = vlan_id

            vlan2dpid[vlan_dp]=dpid
            vlan_dp += 1

        f.close()

        print(ovscandidate)
        print(hostcandidate)
        print(switchcandidate)
        print(name2sw)
        print(name2ovs)
        print(dpid2switch)
        print(dpid2ovs)
        print(dpid2mpls)
        print(dpidplusport2vlandid)
        print(ip2host)
        print(dpid_list)
        print(list)
        print(unique_port)
        print(ovsdpid2time_size)
        print(dpidplusport2vlandid)
        print(vlan2dpid)

        start_new_thread(request, (1,))
        start_new_thread(rate, (1,))
        start_new_thread(send_flow_stat_request, (1,))


    def add_flow(self, datapath, priority, match, actions,buffer_id=None):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id= buffer_id,
                                    priority=priority, match=match,
                                    actions=actions)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        print("Insert default rules")

        datapath = ev.msg.datapath
        dpid = datapath.id

        if dpid not in dpid2datapath.keys():
            dpid2datapath[dpid] = datapath

        #print(dpid2datapath)
        
        ofproto = datapath.ofproto
        match = datapath.ofproto_parser.OFPMatch()
        actions = [datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def forward(self, ev):

        event = None
        eventsize = None
        node = None

        pkt= packet.Packet(ev.msg.data)
        ip = pkt.get_protocol(ipv4.ipv4)

        if ip == None:
            return

        dpid = ev.msg.datapath.id
        in_port = ev.msg.in_port

        if dpid in dpid2switch.keys():

            dict = unique_port[dpid+in_port]
            event = dict["event"]
            eventsize = dict["eventsize"]

        else:

            dict = ovsdpid2time_size[dpid]
            event = dict["event"]
            eventsize = dict["eventsize"]

        if dict["rate"] < drop:

            if eventsize > 500:
                hub.sleep(3)

            #print(ip.dst)
            #print(ip.src)

            event.append(ev)
            dict["eventsize"] += 1
            print("Receive a packet from %d " %in_port)
            print("EventSize")
            print(dict["eventsize"])

        else:
            print("Packet Drop!")

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):

        #print("Statics reply!")

        msg = ev.msg
        datapath_ovs = msg.datapath
        ofproto = datapath_ovs.ofproto
        body = msg.body

        for stat in body:

            #print("print stats!")
            #print(stat)
            match = stat.match
            #print("match in stats")
            #print(match)

            vlan_id = match.dl_vlan

            if vlan_id == 0:
                continue

            duration_sec = stat.duration_sec
            in_packet = stat.packet_count
            packet_rate = in_packet/duration_sec

            if packet >= long_term_rate:

                dp_number = int(vlan_id/100)
                in_port = divmod(vlan_id,100)[1]
                dpid_phy = vlan2dpid[dp_number]
                dst_ip = match.nw_dst
                dst_ip_str = socket.inet_ntoa((struct.pack('I',socket.htonl(dst_ip))))
                wildcards = match.wildcards
                endhost_name = ip2host[dst_ip_str]
                phy_name = dpid2switch[dpid_phy]
                dict_phy = name2sw[phy_name]
                out_port_str = dict_phy[endhost_name]
                out_port = int(out_port_str)
                data_device = dpid2datapath[dpid_phy]
                dl_src = match.dl_src
                dl_dst = match.dl_dst
                ethernet_type = int(ethernet_non_vlan,0)
                ip_src = match.nw_src
                ip_dst = match.nw_dst
                tcp_src_port = match.tp_src
                tcp_dst_port = match.tp_dst
                proto = match.nw_proto
                actions = [data_device.ofproto_parser.OFPActionOutput(out_port)]
                #print(type(out_port))
                #print(out_port)

                match = data_device.ofproto_parser.OFPMatch(
                    in_port=in_port, wildcards= wildcards,
                    dl_dst=dl_dst, dl_src=dl_src, dl_type=ethernet_type,
                    nw_proto=proto, tp_src=tcp_src_port, tp_dst=tcp_dst_port, nw_dst=ip_dst, nw_src=ip_src)

                # Need to insert rules for the specific packets
                #print("match in reply")
                #print(match)
                mod = data_device.ofproto_parser.OFPFlowMod(
                    datapath=data_device, match=match, cookie=0,
                    command=ofproto.OFPFC_ADD, idle_timeout=10000, hard_timeout=10000,
                    priority=ofproto.OFP_DEFAULT_PRIORITY,
                    flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

                print(mod)
                data_device.send_msg(mod)
                print("Successflly migrate!")

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self,ev):
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        links_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        self.grap.add_nodes_from(switches)
        self.grap.add_edges_from(links)
    @set_ev_cls(event.EventLinkAdd)
    def get_topology_data(self,ev):
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        links_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        self.grap.add_nodes_from(switches)
        self.grap.add_edges_from(links)


