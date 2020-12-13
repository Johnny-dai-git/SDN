from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
import sys
import time
import thread
import random
import struct


fd = 70
drop = 200
packet_drop = 0
packet_fd = 0
total_packet = 0
non_fd = 0
event = []
presize = 0
pretime = 0
newsize = 0
eventsize = 0
rate = 0
# dictionary of dictionary
name2ovs = {}
name2sw = {}
name2host = {}
ovscandidate =[]
switchcandidate = []
hostcandidate = []
ovs = 'ovs'
host = 'host'
device = {}
wildcard = ofproto_v1_0.OFPFW_ALL
id2sw = {}


def pickup_ovs(self):
    target = random.sample(ovscandidate,1)
    name2ovs.get(target)
    port = target.get(ovs)
    return port

def add_ovs_drop(self,datapath,msg):
    ofproto = datapath.ofproto
    in_port = msg.in_port
    dst, src, eth_type,dl_vlan = struct.unpack_from('！6s6sHH',buffer(msg.data),0)

    match = datapath.ofproto_parser.OFPMatch{
        wildcard, in_port, src, dst,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
    }

    actions ={}

    mod = datapath.ofproto_parser.OFPFlowMod(
        datapath=datapath, match=match, cookie=0,
        command=ofproto.OFPFC_ADD, idle_timeout=5, hard_timeout=0,
        priority=ofproto.OFP_DEFAULT_PRIORITY,
        flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
    datapath.send_msg(mod)

def add_ovs_MPLS_flow(self,datapath, msg, actions):
    ofproto = datapath.ofproto
    in_port = msg.in_port
    dst, src, eth_type, dl_vlan = struct.unpack_from('!6s6sHH', buffer(msg.data), 0)
    match = datapath.ofproto_parser.OFPMatch(
        wildcard, in_port, src, dst,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
    )
    mod = datapath.ofproto_parser.OFPFlowMod(
        datapath=datapath, match=match, cookie=0,
        command=ofproto.OFPFC_ADD, idle_timeout=5, hard_timeout=0,
        priority=ofproto.OFP_DEFAULT_PRIORITY,
        flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
    datapath.send_msg(mod)

def add_normal_flow(datapath,msg,actions):
    dic = {}
    ofproto = datapth.ofproto
    in_port = msg.in_port
    dst, src, eth_type, dl_vlan = struct.unpack_from('!6s6sHH', buffer(msg.data), 0)
    match = datapth.ofproto_parser.OFPMatch(
        wildcard,in_port, src, dst,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
    )
    host_name = name2host.get(dst)
    dpid = datapath.dpid
    switch_name = id2sw.get(dpid)
    if name2sw.get(switch_name) == 0 :
        if name2ovs.get(switch_name) == 0 :
            print("Can not find the devices, we are looking for")
            exit(0)
        else :
            dic = name2ovs.get(switch_name)
    else :
        dic = name2sw.get(switch_name)
    out_port  = dic.get(host_name)
    new_match = datapath.ofproto_parser.OFPMatch()
    actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
    mod = datapath.ofproto_parser.OFPFlowMod(
        datapath=datapath, match=new_match, cookis=0,
        command=ofproto.OFPFC_ADD, idle_timeout=10, hard_timeout=0,
        priority=ofproto.OFP_DEFAULT_PRIORITY,
        flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
    datapath.send_msg(mod)


def rate(self):
    global presize
    global pretime
    global newsize
    global eventsize
    global rate
    while 1:
        while eventsize != 0:
            # print("rate running!")
            ev = event.get()
            msg = ev.msg
            datapath = msg.datapath
            ofproto = msg.datapath.ofproto
            ## unpack the packet with specific format
            ip_src, ip_dst = struct.unpack_from('!LL', buffer(msg.data), 12)
            print (ip_dst)
            print (ip_src)
            print(type(datapath))
            print(datapath)
            if pretime == 0:
                current = time.time()
                presize = eventsize
            else:
                current = time.time()
                if current - pretime >= 5:
                    diff = time.time() - pretime
                    rate = (eventsize - presize) / diff
                    presize = eventsize
                    pretime = current
                if rate >= fd:
                    ## if the rate is between the drop and the forward
                    ## Add rules for a specific flow, change the default rule to MPLS tunnel
                    if rate <= drop:
                        print("Detected forwarding packet scenario \n")
                        # out_port = pickup_ovs()
                        ## how to change a default rule ##
                        # new_match = datapath.ofproto_parser.OFPMatch()
                        # actions = [datapath.ofproto_parser.OFPActionPushMpls(out_port)]
                        # add_ovs_MPLS_flow(datapath,msg,actions)
                        # packet_fd = packet_fd+1
                    ## If the packet need to drop, then insert rules with no actions
                    if rate > drop:
                        print("Detected droping packet scenario \n")
                        # add_ovs_drop(datapath,msg)
                        # packet_drop = packet_drop+1
                else :
                    # insert what ? What rules should we insert
                    # dic = {}
                    # dpid = datapath.id
                    # name = device.get(dpid)
                    # if name2ovs.get(name) == 0:
                    #    if name2sw.get(name) == 0:
                    #        print('Can not find the devices')
                    #       exit(-1)
                    #    else :
                    #        dic = name2sw.get(name)
                    # else :
                    #   dic = name2ovs.get(name)
                    # host = hostcandidate.get(ip_dst)
                    # out_port = dic.get(host)
                    ## Insert flow mod ##
                    ## What does OFP match means and what should I do for it ?
                    # new_match = datapath.ofproto_parser.OFPMatch()
                    # actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                    # mod = datapath.ofproto_parser.OFPFlowMod(
                    #    datapath=datapath, match=new_match, cookis=0,
                    #    command=ofproto.OFPFC_ADD, idle_timeout=10, hard_timeout=0,
                    #    priority=ofproto.OFP_DEFAULT_PRIORITY,
                    #    flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
                    #datapath.send_msg(mod)

                    ## out = datapath.ofproto_parserO.OFPPacketout(
                    ##        datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                    ##        actions=actions)
                    ##datapath.send_msg(out)
                    #non_fd= non_fd + 1

class Threshold(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Threshold, self).__init__(*args, **kwargs)
        self.x = ''
        self.x = raw_input('input config fiel path/filename\n')
        print self.x
        f = open(self.x, 'r')
        if 'exit' not in self.x:
            configlist = f.readlines()
            print configlist
            for line in configlist:
                if "software" in line:
                    array = line.split(' ')
                    ovscandidate.append(array.index(0))
                    ovs = {}
                    for member in array :
                        if 'dpid' in member:
                            tuple = member.split(':')
                            id2sw[tuple[1]] = array[0]
                        tuple = member.split(':')
                        ovs[tuple[0]] = tuple[1]
                    name2ovs[array[0]]= ovs
                if "sw" in line:
                    array = line.split(' ')
                    switchcandidate.append(array.index(0))
                    sw = {}
                    for member in array:
                        if 'dpid' in member:
                                tuple = member.split(':')
                                id2sw[tuple[1]] = array[0]
                        tuple = member.split(':')
                        sw[tuple[0]] = tuple[1]
                    name2sw[array[0]] = sw
                if "host" in line and 'sw' not in line:
                    host ={}
                    array = line.split(' ')
                    host[array[1]] = array[0]
                    hostcandidate.add(array.index(0))
                    name2host[array[0]] = host
                if "device" in line:
                    array = line.split(' ')
                    for member in array:
                        tuple = member.split(':')
                        device[tuple.index(0)] = tuple.index(1)

        f.close()
        # print self.ovs
        # print self.switch
        # print self.link
        print(ovscandidate)
        print(hostcandidate)
        print(switchcandidate)
        print(name2host)
        print(name2sw)
        print(name2ovs)
        port = pickup_ovs()
        thread.start_new(rate, (1,))
        # print "work here 1\n"
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def forward(self, ev):
        global event
        event.append('ev')
        global  total_packet
        total_packet = total_packet + 1
        global eventsize
        eventsize += 1



