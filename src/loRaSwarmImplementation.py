from pygate import Pygate
from loRaSwarmProtocol import LoRaSwarmProtocol
from loRaSwarmTypes import LoRaSwarmTypes
from network import WLAN
import time
import machine
from machine import RTC
import pycom
import socket
import _thread
import uselect
import gc
import struct
import ujson
import json
import math
import ucollections as collections
import os
import queue
import statistics
import ucrypto as crypto

class LoRaSwarmImplementation:
    HEARTBEAT_SEND_SF = 12
    DEFAULT_SNR_TARGET = 12
    SNR_BIAS = 2

    NeighbourData = collections.namedtuple('NeighbourData','heartbeats applications extApps controls status lastAppPacketSent')
    # Stores metadata alongside packets
    Heartbeat = collections.namedtuple('Heartbeat','timestamp snr rssi heartbeatPacket')
    Application = collections.namedtuple('Application', 'timestamp snr rssi applicationPacket')
    ExtApplication = collections.namedtuple('ExtApplication', 'timestamp snr rssi extApplicationPacket')
    Control = collections.namedtuple('Control','timestamp snr rssi controlPacket')
    Status = collections.namedtuple('Status', 'timestamp status1 status2')

    IntermediateAppPack = collections.namedtuple('IntermediateAppPack','payload forwardHorizon forwardCount sf nid pid')

    SendQueueElement = collections.namedtuple('SendQueueElement','id autoSf sf packetType packet')
    LastSend = collections.namedtuple('LastSend','lastSend waitTimeMs')

    LastAppPacket = collections.namedtuple('LastAppPacket', 'seq timestamp')
    LastCtrlPacket = collections.namedtuple('LastCtrlPacket', 'seq timestamp')

    def __init__(self, nodeId, pygate, chrono, memoryStats=False):
        self.nodeId = nodeId

        self.pygate = pygate
        self.neighbours = {}
        self.senders = {}
        self.chrono = chrono
        self.running = True

        self.last_heartbeat = 0
        self.heartbeat_period_offset = self.generate_heartbeat_offset()
        self.heartbeat_period = 10 * 60 * 1000

        self.status1 = 0
        self.status2 = 0

        self.coordLat = 4.333
        self.coordLon = 3.222

        self.send_queue = queue.Queue(maxsize=30)
        self.last_send = self.LastSend(lastSend=0, waitTimeMs=0)
        self.current_packet_id = 0

        self.lastControlPacket = None

        # Queue holds new app packets which can be retrieved by user
        self.application_packet_queue = queue.Queue(maxsize=100)
        self.control_packet_queue = queue.Queue(maxsize=100)

        # debug only
        self.log_queue = queue.Queue(maxsize=100)

        self.memoryStats = memoryStats
        self.idleMode = False

    def enableIdleMode(self):
        self.idleMode = True

    def disableIdleMode(self):
        self.idleMode = False

    def generate_heartbeat_offset(self):
        randomBytes = crypto.getrandbits(32)
        rand = struct.unpack('h',randomBytes)[0] # max 32k min -32k
        return rand

    def receive_log(self):
        try:
            return self.log_queue.get(False)
        except OSError as e:
            return None

    def send(self, payload, forwardHorizon=0, neighbourListEnabled=True, sf=0):
        if sf != 0 and (sf < 7 or sf > 12):
            raise ValueError('SF must be between 7 and 12 inclusive')

        iap = self.IntermediateAppPack(payload=payload, forwardHorizon=forwardHorizon, forwardCount=0, sf=sf, nid=self.nodeId, pid=self.current_packet_id)
        self.current_packet_id += 1
        # header_bytes = LoRaSwarmProtocol.get_header_byte(self.nodeId, self.status1, self.status2)
        # if neighbourListEnabled:
        #     neighbours = self.get_heartbeat_neighbour_list()
        #     packetType = LoRaSwarmProtocol.EXTENDED_APPLICATION_PACKET
        #     packet = LoRaSwarmProtocol.get_ext_app_packet(header_bytes, neighbours, self.nodeId, self.current_packet_id, forwardHorizon, 0, payload)
        # else:
        #     packet = LoRaSwarmProtocol.get_application_packet(header_bytes, self.nodeId, self.current_packet_id, forwardHorizon, 0, payload)
        #     packetType = LoRaSwarmProtocol.APPLICATION_PACKET
        # self.current_packet_id += 1
        if neighbourListEnabled:
            packetType = LoRaSwarmProtocol.EXTENDED_APPLICATION_PACKET
        else:
            packetType = LoRaSwarmProtocol.APPLICATION_PACKET
        self.add_to_send_queue(packetType, iap, sf)

    def sendControl(self, payload, sf=0):
        current_time = self.chrono.read_ms()
        if sf != 0 and (sf < 7 or sf > 12):
            raise ValueError('SF must be between 7 and 12 inclusive')

        # Send with incremented send seq
        if self.lastControlPacket == None:
            seq = 0
        else:
            seq = self.lastControlPacket.seq + 1
        self.lastControlPacket = self.LastCtrlPacket(seq=seq, timestamp=current_time)

        # Now send control packet
        header_bytes = LoRaSwarmProtocol.get_header_byte(self.nodeId, self.status1, self.status2)
        ctrl_bytes = LoRaSwarmProtocol.get_control_packet(header_bytes, seq, payload)

        # Add to send queue
        self.add_to_send_queue(LoRaSwarmProtocol.CONTROL_PACKET, ctrl_bytes, sf)

    def receive(self):
        try:
            return self.application_packet_queue.get(False)
        except OSError as e:
            return (None, None)

    def receiveControl(self):
        try:
            return self.control_packet_queue.get(False)
        except OSError as e:
            return None

    def receive_packet(self, header, payload):
        try:
            if not header is None:
                current_time = self.chrono.read_ms()
                # Print all bytes
                formatString = ""
                for b in payload:
                    formatString += "0x{:02x} ".format(b)
                print("Packet bytes: ", formatString)
                # Strip header
                packetHeader, content = LoRaSwarmProtocol.parse_packet_header(payload)
                # Ignore
                if packetHeader.nodeId == self.nodeId:
                    return

                # Add to neighbour list or update status
                statusEntry = LoRaSwarmImplementation.Status(timestamp=current_time, status1=packetHeader.status1, status2=packetHeader.status2)
                neighbourId = packetHeader.nodeId
                if neighbourId in self.neighbours:
                    # Then update this neighbour
                    self.neighbours[neighbourId].status.append(statusEntry)
                else:
                    # Create a new neighbour data object
                    data = self.create_neighbour_data()
                    data.status.append(statusEntry)
                    self.neighbours[neighbourId] = data

                if packetHeader.packetType == LoRaSwarmProtocol.HEARTBEAT_PACKET:
                    # Process heartbeat packet
                    heartbeatPacket = LoRaSwarmProtocol.parse_heartbeat_packet(content)
                    self.process_heartbeat(header, packetHeader, heartbeatPacket)

                elif packetHeader.packetType == LoRaSwarmProtocol.APPLICATION_PACKET:
                    # Process application packet
                    applicationPacket = LoRaSwarmProtocol.parse_application_packet(content)
                    self.process_app_packet(header, packetHeader, applicationPacket)

                elif packetHeader.packetType == LoRaSwarmProtocol.EXTENDED_APPLICATION_PACKET:
                    # Process extended application packet
                    extAppPacket = LoRaSwarmProtocol.parse_ext_application_packet(content)
                    self.process_ext_app_packet(header,packetHeader,extAppPacket)

                elif packetHeader.packetType == LoRaSwarmProtocol.CONTROL_PACKET:
                    # Process control packet
                    controlPacket = LoRaSwarmProtocol.parse_control_packet(content)
                    self.process_ctrl_packet(header,packetHeader,controlPacket)

        except ValueError as e:
            print(e)

    def process_ctrl_packet(self,header,packetHeader,controlPacket):
        current_time = self.chrono.read_ms()
        if not self.lastControlPacket is None and controlPacket.sequence <= self.lastControlPacket.seq:
            # Ignore this packet
            print('Ignore packet')
            return

        controlPacketEntry = self.Control(timestamp=current_time, snr=header['snr'], rssi=header['rssi'], controlPacket=controlPacket)
        # Add control packet to queue
        self.control_packet_queue.put(controlPacket, block=False)
        # Forward control packet
        header_bytes = LoRaSwarmProtocol.get_header_byte(self.nodeId,self.status1, self.status2)
        ctrl_bytes = LoRaSwarmProtocol.get_control_packet(header_bytes,controlPacket.sequence,controlPacket.payload)
        # We should add to neighbour for SNR usage
        neighbourId = packetHeader.nodeId
        if neighbourId in self.neighbours:
            # Then update this neighbour
            self.neighbours[neighbourId].controls.append(controlPacketEntry)
        # add to TX queue
        print('Forwarding Control Packet')
        self.add_to_send_queue(LoRaSwarmProtocol.CONTROL_PACKET, ctrl_bytes)
        # Update last control packet
        self.lastControlPacket = self.LastCtrlPacket(seq=controlPacket.sequence, timestamp=current_time)


    def process_ext_app_packet(self, header, packetHeader, extAppPacket):
        # Process app packet contained within ext packet
        print('Extended application packet received')
        current_time = self.chrono.read_ms()
        neighbourId = packetHeader.nodeId
        extAppPacketEntry = LoRaSwarmImplementation.ExtApplication(timestamp=current_time, snr=header['snr'], rssi=header['rssi'], extApplicationPacket=extAppPacket)
        # We should add to neighbour for SNR usage
        if neighbourId in self.neighbours:
            # Then update this neighbour
            self.neighbours[neighbourId].extApps.append(extAppPacketEntry)

        logLine = "{},{},{},{},{},{},\n".format(packetHeader.nodeId, extAppPacket.applicationPacket.sender, extAppPacket.applicationPacket.payload, header['snr'], header['rssi'], header['datr'])
        try:
            self.log_queue.put(logLine, block=False)
        except Exception as e:
            print(e)
        print(logLine)
        self.process_app_packet_content(header, packetHeader, extAppPacket.applicationPacket,current_time)

    # Check if the rolling sequence number is valid
    def check_valid_seq(self, lastSeq,newSeq):
      bound = (lastSeq - 135) % 256
      d_last = (newSeq - lastSeq - 1) % 256
      d_bound = (bound - newSeq - 1) % 256
      if d_last + d_bound == 119:
        return True
      else:
        return False

    def create_neighbour_data(self):
        return self.NeighbourData([],[],[],[],[],(0,0))

    def process_app_packet(self, header, packetHeader, appPacket):
        current_time = self.chrono.read_ms()
        neighbourId = packetHeader.nodeId
        appPacketEntry = LoRaSwarmImplementation.Application(timestamp=current_time, snr=header['snr'], rssi=header['rssi'], applicationPacket=appPacket)
        # We should add to neighbour for SNR usage
        if neighbourId in self.neighbours:
            # Then update this neighbour
            self.neighbours[neighbourId].applications.append(appPacketEntry)

        self.process_app_packet_content(header, packetHeader, appPacket,current_time)

    def process_app_packet_content(self, header, packetHeader, appPacket,current_time):
        # Check if we have previously received a packet with this seq and sender
        sId = appPacket.sender
        seq = appPacket.sequence

        if sId == self.nodeId:
            print('Ignore packet')
            return

        if sId in self.senders:
            last_send = self.senders[sId]
            # if in last 10 mins and invalid
            if current_time - last_send.timestamp <= 10 * 60 * 1000 and not self.check_valid_seq(last_send.seq,seq):
                print('Ignore packet')
                return
            else:
                self.senders[sId] = self.LastAppPacket(seq=seq,timestamp=current_time)
        else:
            self.senders[sId] = self.LastAppPacket(seq=seq,timestamp=current_time)


        print('Application packet received from ',packetHeader.nodeId)
        # Forwarding...
        self.forward_app_packet(appPacket)
        # Add to app packet queue for user
        self.application_packet_queue.put((header,appPacket), block=False)

    def forward_app_packet(self, appPacket):
        # Establish whether it needs forwarding
        fh = appPacket.forwardHorizon
        fc = appPacket.forwardCount

        if fh > fc:
            # We should forward this packet
            # Potentially introduce more intelligent sensing as to whether
            # forwarding is worthwhile
            # TODO: check sending queue is not large - otherwise don't bother
            # sending
            # Packet forwards should not be sent with a neighbour list to
            # minimise overhead
            fc += 1
            header_bytes = LoRaSwarmProtocol.get_header_byte(self.nodeId,self.status1, self.status2)
            app_bytes = LoRaSwarmProtocol.get_application_packet(header_bytes,appPacket.sender,appPacket.sequence,fh,fc,appPacket.payload)

            iap = self.IntermediateAppPack(payload=appPacket.payload, forwardHorizon=fh, forwardCount=fc, sf=0, nid=appPacket.sender, pid=appPacket.sequence)

            print('Forwarding packet')
            # add to TX queue
            self.add_to_send_queue(LoRaSwarmProtocol.APPLICATION_PACKET, iap)

    def process_heartbeat(self, header, packetHeader, heartbeatPacket):
        print('Heartbeat received from ',packetHeader.nodeId)
        #logLine = "Heartbeat received from,{},\n".format(packetHeader.nodeId)
        #self.log_queue.put(logLine)
        current_time = self.chrono.read_ms()
        neighbourId = packetHeader.nodeId
        heartbeatEntry = LoRaSwarmImplementation.Heartbeat(timestamp=current_time, snr=header['snr'], rssi=header['rssi'], heartbeatPacket=heartbeatPacket)

        if neighbourId in self.neighbours:
            # Then update this neighbour
            self.neighbours[neighbourId].heartbeats.append(heartbeatEntry)

    def get_heartbeat_neighbour_list(self):
        # Get current time to compare against
        maxAge = 5 * 60 * 1000 # 5 minutes
        current_time = self.chrono.read_ms()

        neighbour_list = []
        for nId in self.neighbours:
            # ID is key
            neighbour = self.neighbours[nId]
            p = [len(neighbour.controls) - 1, len(neighbour.applications) - 1, len(neighbour.extApps) - 1, len(neighbour.heartbeats) - 1]
            snrs = []

            # Only use at most 5 SNR readings to ensure the data rate adapts quickly

            finished = False
            while not finished and len(snrs) <= 5:
                maxTs = 0
                maxIdx = -1

                if p[0] >= 0:
                    cts = neighbour.controls[p[0]].timestamp
                    if cts > maxTs and current_time - cts <= maxAge:
                        maxIdx = 0
                        snrToAdd = neighbour.controls[p[0]].snr

                if p[1] >= 0:
                    ats = neighbour.applications[p[1]].timestamp
                    if ats > maxTs and current_time - ats <= maxAge:
                        maxIdx = 1
                        snrToAdd = neighbour.applications[p[1]].snr

                if p[2] >= 0:
                    ets = neighbour.extApps[p[2]].timestamp
                    if ets > maxTs and current_time - ets <= maxAge:
                        maxIdx = 2
                        snrToAdd = neighbour.extApps[p[2]].snr

                if p[3] >= 0:
                    hts = neighbour.heartbeats[p[3]].timestamp
                    if hts > maxTs and current_time - hts <= maxAge:
                        maxIdx = 3
                        snrToAdd = neighbour.heartbeats[p[3]].snr

                if maxIdx >= 0:
                    # Now decrement counter and add snr to list
                    snrs.append(snrToAdd)
                    p[maxIdx] -= 1
                else:
                    # When max idx is -1, it means either there are no more
                    # elements in the lists OR there are but they are too old
                    finished = True

            # Take min of snr
            if len(snrs) > 0:
                #snr = math.floor(statistics.weighted_square_mean(snrs))
                snr = min(snrs)
                # Now append to neighbour list
                # Now count number of packets received in last 10 mins
                received = self.count_packets_received(neighbour,current_time)
                neighbourElem = LoRaSwarmTypes.Neighbour(nodeId=nId, snr=snr, received=received)
                #neighbourElem = LoRaSwarmTypes.Neighbour(nodeId=nId, snr=-14, received=30)
                neighbour_list.append(neighbourElem)

        return neighbour_list

    def count_packets_received(self,neighbour,current_time):
        maxAge = 10 * 60 * 1000
        # Count Exts, Apps, Ctrls, Hbs
        #NeighbourData = collections.namedtuple('NeighbourData','heartbeats applications extApps controls status lastAppPacketSent')
        cutoff = current_time - maxAge
        count = 0
        # Every packet received appends to the status list so this can be used to
        # count number of received packets
        for p in reversed(neighbour.status):
            if p.timestamp < cutoff:
                # we're done
                break
            # Increment count
            count += 1
        return count

    def get_snr_from_neighbour_list(self, neighbourList):
        for n in neighbourList:
            if n.nodeId == self.nodeId:
                # This is us - return snr
                return n.snr
        return None

    def send_heartbeat(self, sf=0):
        # Get header bytes
        print('Sending heartbeat')
        header_bytes = LoRaSwarmProtocol.get_header_byte(self.nodeId, self.status1, self.status2)
        neighbours = self.get_heartbeat_neighbour_list()
        heartbeatBytes = LoRaSwarmProtocol.get_heartbeat_packet(header_bytes, self.coordLat, self.coordLon, neighbours)
        print("Neighbours: ", neighbours)
        self.add_to_send_queue(LoRaSwarmProtocol.HEARTBEAT_PACKET, heartbeatBytes, sf)

    def add_to_send_queue(self, packetType, bytes, sf=0):
        if sf == 0:
            elem = self.SendQueueElement(id=self.current_packet_id, autoSf=True, sf=0, packetType=packetType, packet=bytes)
        else:
            elem = self.SendQueueElement(id=self.current_packet_id, autoSf=False, sf=sf, packetType=packetType, packet=bytes)
        self.current_packet_id += 1
        # Don't block if queue is full - will raise full exception
        self.send_queue.put(elem, False)

    # This function will pick a random channel to send on
    def gw_send(self, sf,bytes, current_time):
        rand_ch = os.urandom(1)[0] % 8
        # Set LoRa send time and wait time (set wait time to be very high until ToA is received)
        self.last_send = self.LastSend(lastSend=current_time, waitTimeMs=10000000)
        self.pygate.send_ch(sf,rand_ch,bytes)

    def send_packets(self, current_time):
        # Check the queue and send if necessary
        try:
            # Return if time has not elapsed
            if current_time - self.last_send.lastSend < self.last_send.waitTimeMs:
                return

            elem = self.send_queue.get(False)
            if not elem is None:
                pType = elem.packetType
                if pType == LoRaSwarmProtocol.HEARTBEAT_PACKET:
                    if elem.autoSf:
                        # Send with heartbeat SF
                        sf = self.HEARTBEAT_SEND_SF
                    else:
                        sf = elem.sf
                    self.gw_send(sf, elem.packet, current_time)
                elif pType == LoRaSwarmProtocol.APPLICATION_PACKET:
                    pData = elem.packet
                    header_bytes = LoRaSwarmProtocol.get_header_byte(self.nodeId, self.status1, self.status2)
                    packet = LoRaSwarmProtocol.get_application_packet(header_bytes, pData.nid, pData.pid, pData.forwardHorizon, pData.forwardCount, pData.payload)
                    if elem.autoSf:
                        sf = self.pick_optimum_sf(self.neighbours, current_time)
                    else:
                        sf = elem.sf
                    self.gw_send(sf, packet, current_time)
                elif pType == LoRaSwarmProtocol.EXTENDED_APPLICATION_PACKET:
                    pData = elem.packet
                    header_bytes = LoRaSwarmProtocol.get_header_byte(self.nodeId, self.status1, self.status2)
                    neighbours = self.get_heartbeat_neighbour_list()
                    packet = LoRaSwarmProtocol.get_ext_app_packet(header_bytes, neighbours, pData.nid, pData.pid, pData.forwardHorizon, pData.forwardCount, pData.payload)
                    if elem.autoSf:
                        sf = self.pick_optimum_sf(self.neighbours, current_time)
                    else:
                        sf = elem.sf
                    self.gw_send(sf, packet, current_time)
                else:
                    # ext, ctrl or app
                    if elem.autoSf:
                        # Send with auto sf
                        print('Picking optimum SF')
                        sf = self.pick_optimum_sf(self.neighbours, current_time)
                    else:
                        sf = elem.sf
                    self.gw_send(sf, elem.packet, current_time)
                # Send packet


        except OSError as e:
            return

    def pick_optimum_sf(self, neighbours, current_time):
        # Given the neighbour list, determines the optimum SF to send at
        # We need not consider any packets older than 20 minutes since we would expect a heartbeat in the mean time
        maxAge = 20 * 60 * 1000
        snrs = []
        for nId in neighbours:
            # neighbours is dict
            n = neighbours[nId]

            hTs = 0 # Timestamp of Heartbeat packet
            eTs = 0 # Timestamp of Extended application packet

            # Pick most recent of exts or heartbeats
            pHeartbeats = len(n.heartbeats) - 1
            pExts = len(n.extApps) - 1

            if pHeartbeats >= 0:
                hTs = n.heartbeats[pHeartbeats].timestamp

            if pExts >= 0:
                eTs = n.extApps[pExts].timestamp

            # Choose which is greater (presuming at least one is set)
            if (hTs > (current_time - maxAge) or eTs > (current_time - maxAge)) and (pHeartbeats >= 0 or pExts >= 0):
                if hTs > eTs:
                    # Use heartbeat packet
                    heartbeatPacket = n.heartbeats[pHeartbeats]
                    snr = self.get_snr_from_neighbour_list(heartbeatPacket.heartbeatPacket.neighbours)
                else:
                    # Use ext app packet
                    extAppPacket = n.extApps[pExts]
                    snr = self.get_snr_from_neighbour_list(extAppPacket.extApplicationPacket.neighbours)

                if not snr is None:
                    # add this SNR
                    snrs.append(snr)
        print(snrs)
        # Get SF based on target SNR
        targetSnr = self.calculate_target_snr(snrs)
        sf = self.get_sf_from_snr(targetSnr)
        print('Target SNR: ', targetSnr)
        print('SF        : ', sf)
        return sf

    def calculate_target_snr(self, snrs):
        if len(snrs) == 0:
            return self.DEFAULT_SNR_TARGET
        mu = statistics.mean(snrs)
        std = statistics.pstdev(snrs,mu)
        #return mu - 1.75 * std
        return min(snrs)

    def get_sf_from_snr(self, snr):
        # Gets based on threshold
        snr = abs(snr) + self.SNR_BIAS
        sf = math.floor(snr / 2) + 4
        if sf > 12:
            return 12
        if sf < 8:
            return 8 # set 8 as new lower limit
        return sf

    def run(self):
        last_mem_info_dump = 0
        mem_info_dump_period = 10000

        # Run protocol
        print("This is node ", self.nodeId)
        print("LoRa Swarm Protocol Began. Sending heartbeat...")
        # Immediately send a heartbeat packet
        self.send_heartbeat()
        while(self.running):
            current_time = self.chrono.read_ms()

            # Try and receive a pygate packet
            header, payload = self.pygate.receive_lora()
            self.receive_packet(header,payload)

            # Receive stat packet and set ToA
            toa = self.pygate.receive_stat()
            if toa > 0:
                # Set wait time
                waitTimeMs = toa / 0.01
                self.last_send = self.LastSend(lastSend=self.last_send.lastSend,waitTimeMs=waitTimeMs)
                print(self.last_send)

            # Send heartbeat packet
            if current_time - self.last_heartbeat > self.heartbeat_period + self.heartbeat_period_offset:
                #  To ensure multiple Pygates do not end up in phase. Have a random period offset
                self.heartbeat_period_offset = self.generate_heartbeat_offset()
                self.last_heartbeat = current_time
                self.send_heartbeat()

            # If in idle mode then add heartbeat to send queue if it is empty
            if self.idleMode and self.send_queue.empty() and current_time - self.last_send.lastSend > self.last_send.waitTimeMs:
                self.send_heartbeat()

            # Attempt to send any pending packets from queue
            self.send_packets(current_time)
            time.sleep(1)

            if current_time - last_mem_info_dump > mem_info_dump_period:
                gc.collect()
                if self.memoryStats:
                    print('{} KB Memory Free'.format(gc.mem_free() / 1000))
                last_mem_info_dump = current_time
                # Will have a function to clear up old packets
