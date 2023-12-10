"""
Ryu Application，用于收集TCP、UDP以及Aggregate Traffic
"""
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib import hub
from datetime import datetime
import pandas as pd
import time
import copy
import os
import shutil


class Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.sampling_interval = 1
        self.monitor_switch = 1
        self.pre_packet_data = [0, 0, 0]  # tcp udp agg data
        self.pre_bytes_data = [0, 0, 0]  # tcp udp agg data
        self.monitor_thread = hub.spawn(self.monitor)
        self.datapaths = {}
        self.index = 0
        self.path = "./history"
        self.window_size = 5
        self.window_index = 0

        folder = os.path.exists(self.path)
        if not folder:                
            os.makedirs(self.path)

        if os.path.exists("./collection_tcp.csv"):
            shutil.move("collection_tcp.csv", 
                        os.path.join(self.path, "collection_tcp" + str(time.time()) + ".csv"))
        if os.path.exists("./collection_udp.csv"):
            shutil.move("collection_udp.csv",
                        os.path.join(self.path, "collection_udp" + str(time.time()) + ".csv"))
        if os.path.exists("./collection_agg.csv"):  
            shutil.move("collection_agg.csv",
                        os.path.join(self.path, "collection_agg" + str(time.time()) + ".csv"))

        file0 = open("collection_tcp.csv", "w")
        file0.write("index,type,packets,bytes\n")
        file0.close()

        file0 = open("collection_udp.csv", "w")
        file0.write("index,type,packets,bytes\n")
        file0.close()

        file0 = open("collection_agg.csv", "w")
        file0.write("index,type,packets,bytes\n")
        file0.close()

        if os.path.exists("./overlapped_tcp_window.csv"):
            shutil.move("overlapped_tcp_window.csv",
                        os.path.join(self.path, "overlapped_tcp_window" + str(time.time()) + ".csv"))
        if os.path.exists("./overlapped_udp_window.csv"):
            shutil.move("overlapped_udp_window.csv",
                        os.path.join(self.path, "overlapped_udp_window" + str(time.time()) + ".csv"))
        if os.path.exists("./overlapped_agg_window.csv"):
            shutil.move("overlapped_agg_window.csv",
                        os.path.join(self.path, "overlapped_agg_window" + str(time.time()) + ".csv"))

        file = open("overlapped_tcp_window.csv", "w")
        file.write("index,type,packets,bytes\n")
        file.close()

        file = open("overlapped_udp_window.csv", "w")
        file.write("index,type,packets,bytes\n")
        file.close()

        file = open("overlapped_agg_window.csv", "w")
        file.write("index,type,packets,bytes\n")
        file.close()


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto
            
                # if ICMP Protocol
                if protocol == in_proto.IPPROTO_ICMP:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, 
                                            ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol)
            
                #  if TCP Protocol
                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, 
                                            ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol,
                                            tcp_src=t.src_port, tcp_dst=t.dst_port,)
            
                #  If UDP Protocol 
                elif protocol == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, 
                                            ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, 
                                            udp_src=u.src_port, udp_dst=u.dst_port,)            

                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # Asynchronous message
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def monitor(self):
        while True:
            for dp in self.datapaths.values():
                if str(dp.id) == str(self.monitor_switch):
                    self.request_stats(dp)
            hub.sleep(self.sampling_interval)

    def request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)

        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        self.index += 1
        file0 = open("collection_tcp.csv", "a+")
        file1 = open("collection_udp.csv", "a+")
        file2 = open("collection_agg.csv", "a+")

        temp_packet_data = [0, 0, 0]
        temp_bytes_data = [0, 0, 0]

        body = ev.msg.body
        for stat in sorted([flow for flow in body if (flow.priority == 1)], key=lambda flow:
            (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):
        
            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            ip_proto = stat.match['ip_proto']

            temp_bytes_data[2] += stat.byte_count
            temp_packet_data[2] += stat.packet_count

            if stat.match['ip_proto'] == 6:
                temp_bytes_data[0] += stat.byte_count
                temp_packet_data[0] += stat.packet_count

            elif stat.match['ip_proto'] == 17:
                temp_bytes_data[1] += stat.byte_count
                temp_packet_data[1] += stat.packet_count
            else:
                pass

        file0.write("{},{},{},{}\n".format(self.index, "tcp", 
                                           str(temp_packet_data[0] - self.pre_packet_data[0]),
                                           str(temp_bytes_data[0] - self.pre_bytes_data[0])))
        file0.close()

        file1.write("{},{},{},{}\n".format(self.index, "udp",
                                           str(temp_packet_data[1] - self.pre_packet_data[1]),
                                           str(temp_bytes_data[1] - self.pre_bytes_data[1])))
        file1.close()

        file2.write("{},{},{},{}\n".format(self.index, "aggregate",
                                           str(temp_packet_data[2] - self.pre_packet_data[2]),
                                           str(temp_bytes_data[2] - self.pre_bytes_data[2])))
        file2.close()

        self.pre_bytes_data = copy.deepcopy(temp_bytes_data)
        self.pre_packet_data = copy.deepcopy(temp_packet_data)

        # Overlap Sliding Window
        df_tcp = pd.read_csv("collection_tcp.csv")
        df_udp = pd.read_csv("collection_udp.csv")
        df_agg = pd.read_csv("collection_agg.csv")

        if len(df_tcp) >= self.window_size:
            self.window_index += 1
            tcp_window = df_tcp.tail(self.window_size)  # 取出窗口里的值
            udp_window = df_udp.tail(self.window_size)
            agg_window = df_agg.tail(self.window_size)
            tmp_packets = [0, 0, 0]
            tmp_bytes = [0, 0, 0]
            for i in range(self.window_size):
                tmp_packets[0] += tcp_window.iloc[i]['packets']
                tmp_bytes[0] += tcp_window.iloc[i]['bytes']
                tmp_packets[1] += udp_window.iloc[i]['packets']
                tmp_bytes[1] += udp_window.iloc[i]['bytes']
                tmp_packets[2] += agg_window.iloc[i]['packets']
                tmp_bytes[2] += agg_window.iloc[i]['bytes']

            with open("overlapped_tcp_window.csv", "a+") as file:
                file.write("{},{},{},{}\n".format(self.window_index, "tcp",
                                                  str(tmp_packets[0]), str(tmp_bytes[0])))
            with open("overlapped_udp_window.csv", "a+") as file:
                file.write("{},{},{},{}\n".format(self.window_index, "udp",
                                                  str(tmp_packets[1]), str(tmp_bytes[1])))
            with open("overlapped_agg_window.csv", "a+") as file:
                file.write("{},{},{},{}\n".format(self.window_index, "agg",
                                                  str(tmp_packets[2]), str(tmp_bytes[2])))


