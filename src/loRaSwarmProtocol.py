import ucollections as collections
import math
import struct

class LoRaSwarmProtocol:
    PROTOCOL_ID = 0x52
    HEARTBEAT_PACKET = 0x10
    APPLICATION_PACKET = 0x11
    CONTROL_PACKET = 0x12
    EXTENDED_APPLICATION_PACKET = 0x21

    @staticmethod
    def get_ext_app_packet(header_bytes, neighbours, sender,sequence,forward_horizon, forward_count, payload):
        # Basic check of header bytes
        if len(header_bytes) != 4:
            raise ValueError('Header bytes not correct')
        buf = bytearray()
        # Append header
        for x in header_bytes:
            buf.append(x)

        # Append packet packet
        buf.append(LoRaSwarmProtocol.EXTENDED_APPLICATION_PACKET)
        # Add neighbour list
        buf = LoRaSwarmProtocol.append_neighbour_list(buf, neighbours)
        # Now append normal applicationPacket bytes
        buf = LoRaSwarmProtocol.append_app_packet_info(buf, sender, sequence, forward_horizon, forward_count, payload) #buf, sender, sequence, forward_horizon, forward_count, payload
        # done
        return buf

    @staticmethod
    def parse_ext_application_packet(p):
        ExtApplicationPacket = collections.namedtuple('ExtApplicationPacket','neighbours applicationPacket')
        Neighbour = collections.namedtuple('Neighbour','nodeId snr received')

        noNeighbours = p[0]
        # Parse list of neighbours
        neighbours = []
        for i in range(noNeighbours):
            pos = 1 + i * 2
            neighbourId, infoByte = struct.unpack_from('BB',p,pos)
            snr, received = LoRaSwarmProtocol.extract_neighbour_info(infoByte)
            neighbours.append(Neighbour(nodeId=neighbourId, snr=snr, received=received))

        appPacket = LoRaSwarmProtocol.parse_application_packet(p[1 + 2 * noNeighbours:])
        return ExtApplicationPacket(neighbours=neighbours, applicationPacket=appPacket)

    @staticmethod
    def get_header_byte(nodeId, status1, status2):
        # Validate node address
        if nodeId > 0xFF or nodeId < 0:
            raise ValueError('Node ID must be between 0 and 255 inclusive')
        if status1 > 0xFF or status1 < 0:
            raise ValueError('Status1 must be a single byte')
        if status2 > 0xFF or status2 < 0:
            raise ValueError('Status2 must be a single byte')

        buf = bytearray()

        # Write packet ID
        buf.append(LoRaSwarmProtocol.PROTOCOL_ID)
        # Write Node address
        buf.append(nodeId)
        # Write status bytes
        buf.append(status1)
        buf.append(status2)
        return buf

    @staticmethod
    def parse_packet_header(p):
        PacketHeader = collections.namedtuple('PacketHeader','nodeId status1 status2 packetType')
        protocolId, nodeId, status1, status2, packetType = struct.unpack('BBBBB', p)
        if protocolId != LoRaSwarmProtocol.PROTOCOL_ID:
            raise ValueError('Packet malformed')

        packetContent = p[5:]
        return (PacketHeader(nodeId=nodeId, status1=status1, status2=status2, packetType=packetType), packetContent)

    @staticmethod
    def snr_to_nibble(snr):
        corrected_snr = -5 - snr
        if corrected_snr >= 16:
            return 0xF
        if corrected_snr < 0:
            return 0x0
        return corrected_snr

    @staticmethod
    def no_received_to_nibble(n):
        val = math.ceil(n / 4)
        if val > 15:
            return 0xF
        else:
            return val

    @staticmethod
    def extract_neighbour_info(b):
        # Uncorrected snr
        snr_byte = (b >> 4) & 0xF
        snr = -5 - snr_byte
        # Get raw received
        received = b & 0xF
        return (snr, received)

    @staticmethod
    def append_neighbour_list(buf,neighbours):
        buf.append(len(neighbours))
        # Write each neighbour to list
        for neighbour in neighbours:
            buf.append(neighbour.nodeId)
            # First nibble is SNR
            snr_nibble = LoRaSwarmProtocol.snr_to_nibble(neighbour.snr)
            # Second nibble is no. received packets
            no_received_nibble = LoRaSwarmProtocol.no_received_to_nibble(neighbour.received)
            # Construct byte
            info_byte = (snr_nibble << 4) | no_received_nibble
            buf.append(info_byte)
        return buf

    @staticmethod
    def get_heartbeat_packet(header_bytes, coord_lat, coord_lon, neighbours):
        if len(header_bytes) != 4:
            raise ValueError('Header bytes not correct')
        buf = bytearray()
        # Append header
        for x in header_bytes:
            buf.append(x)

        # Add packet ID
        buf.append(LoRaSwarmProtocol.HEARTBEAT_PACKET)
        # Write coordinates (2 4 byte floats) and the number of neighbours (len neighbours)
        buf.extend(struct.pack('ffB', coord_lat, coord_lon, len(neighbours)))

        # Write each neighbour to list
        for neighbour in neighbours:
            buf.append(neighbour.nodeId)
            # First nibble is SNR
            snr_nibble = LoRaSwarmProtocol.snr_to_nibble(neighbour.snr)
            # Second nibble is no. received packets
            no_received_nibble = LoRaSwarmProtocol.no_received_to_nibble(neighbour.received)
            # Construct byte
            info_byte = (snr_nibble << 4) | no_received_nibble
            buf.append(info_byte)
        return bytes(buf) # Convert from byte array to bytes

    @staticmethod
    def parse_heartbeat_packet(bytes):
        HeartbeatPacket = collections.namedtuple('HeartbeatPacket','coordLat coordLon neighbours')
        Neighbour = collections.namedtuple('Neighbour','nodeId snr received')
        coordLat, coordLon, noNeighbours = struct.unpack('ffB', bytes)

        # Parse list of neighbours
        neighbours = []
        for i in range(noNeighbours):
            # 4 + 4 + 1
            pos = 9 + i * 2
            neighbourId, infoByte = struct.unpack_from('BB',bytes,pos)
            snr, received = LoRaSwarmProtocol.extract_neighbour_info(infoByte)
            neighbours.append(Neighbour(nodeId=neighbourId, snr=snr, received=received))
        return HeartbeatPacket(coordLat=coordLat, coordLon=coordLon, neighbours=neighbours)

    @staticmethod
    def test_heartbeat():
        header_bytes = LoRaSwarmProtocol.get_header_byte(255, 0x00, 0x00)

        # test neighbour list
        Neighbour = collections.namedtuple('Neighbour', 'ID snr received neighbours')

        neighbour_list = []
        neighbour_list.append(Neighbour(ID=0xFA, snr=-14, received=9, neighbours=[]))
        neighbour_list.append(Neighbour(ID=0xFB, snr=4, received=0, neighbours=[]))

        heartbeat_packet_bytes = LoRaSwarmProtocol.get_heartbeat_packet(header_bytes, 3.2222, 3.4033, neighbour_list)
        # Try and parse the bytes
        header, content = LoRaSwarmProtocol.parse_packet_header(heartbeat_packet_bytes)
        heartbeatPacket = LoRaSwarmProtocol.parse_heartbeat_packet(content)

    @staticmethod
    def get_forwarding_byte(forward_horizon, forward_count):
        # Get forward horizon nibble
        # 0xF is max meaning no limit to forwarding
        if forward_horizon > 15:
            forward_horizon = 0xF
        if forward_horizon < 0:
            raise ValueError('Forwarding horizon must be positive')

        # Forward count - max 15
        if forward_count > 15:
            forward_count = 0xF
        if forward_count < 0:
            raise ValueError('Forward count must be positive')
        # 7-4: Forward horizon    3-0: Forward count
        return (forward_horizon << 4) | forward_count

    @staticmethod
    def decompose_forwarding_byte(byte):
        forwardHorizon = (byte >> 4) & 0xF
        forwardCount = byte & 0xF
        return (forwardHorizon, forwardCount)

    @staticmethod
    def append_app_packet_info(buf, sender, sequence, forward_horizon, forward_count, payload):
        buf.append(sender)
        buf.append(sequence)
        # Write forwarding byte
        buf.append(LoRaSwarmProtocol.get_forwarding_byte(forward_horizon, forward_count))
        buf.append(len(payload))
        for b in payload:
            buf.append(b)
        return buf

    @staticmethod
    def get_application_packet(header_bytes,sender,sequence,forward_horizon, forward_count, payload):
        if len(header_bytes) != 4:
            raise ValueError('Header bytes not correct')
        buf = bytearray()
        # Append header
        for x in header_bytes:
            buf.append(x)

        # Write packet type
        buf.append(LoRaSwarmProtocol.APPLICATION_PACKET)
        # Write sender ID and packet sequence (ID)
        buf.append(sender)
        buf.append(sequence)
        # Write forwarding byte
        buf.append(LoRaSwarmProtocol.get_forwarding_byte(forward_horizon, forward_count))
        # Write payload length todo: error checking here...
        # assumes payload is an array of bytes
        # App packet header length
        app_header_len = len(buf) + 1
        if len(payload) > (255 - app_header_len):
            raise ValueError("Payload too large. Maximum payload size is: {}".format(255 - app_header_len))
        buf.append(len(payload))
        for b in payload:
            buf.append(b)
        return buf

    @staticmethod
    def parse_application_packet(bytes):
        # We assume the protocol header has already been stripped
        ApplicationPacket = collections.namedtuple('ApplicationPacket','sender sequence forwardHorizon forwardCount payloadLength payload')
        senderId, seq, forwardingByte, payloadLength = struct.unpack('BBBB', bytes)
        forwardHorizon, forwardCount = LoRaSwarmProtocol.decompose_forwarding_byte(forwardingByte)
        payload = bytes[4:4 + payloadLength]
        return ApplicationPacket(sender=senderId, sequence=seq, forwardHorizon=forwardHorizon, forwardCount=forwardCount, payloadLength=payloadLength, payload=payload)

    @staticmethod
    def test_app_packet():
        header_bytes = LoRaSwarmProtocol.get_header_byte(255, 0x00, 0x00)
        payload = b"Hello 1,2,3"
        app_pack_bytes = LoRaSwarmProtocol.get_application_packet(header_bytes, 255, 0, 1, 0, payload)

        # Try and parse the bytes
        header, content = LoRaSwarmProtocol.parse_packet_header(app_pack_bytes)
        applicationPacket = LoRaSwarmProtocol.parse_application_packet(content)
        print(header)
        print(applicationPacket)

    @staticmethod
    def get_control_packet(header_bytes, sequence,payload):
        if len(header_bytes) != 4:
            raise ValueError('Header bytes not correct')
        buf = bytearray()
        # Append header
        for x in header_bytes:
            buf.append(x)

        # Write packet type
        buf.append(LoRaSwarmProtocol.CONTROL_PACKET)
        # Sequence is now ushort
        seq = struct.pack('H',sequence)
        buf.extend(seq)
        control_header_len = len(buf) + 1
        if len(payload) > (255 - control_header_len):
            raise ValueError("Payload too large. Maximum payload size is: {}".format(255 - control_header_len))
        buf.append(len(payload))
        for b in payload:
            buf.append(b)
        return buf

    @staticmethod
    def parse_control_packet(bytes):
        ControlPacket = collections.namedtuple('ControlPacket', 'sequence payloadLength payload')
        sequence, payloadLength = struct.unpack('HB', bytes)
        payload = bytes[3:3 + payloadLength]
        return ControlPacket(sequence=sequence, payloadLength=payloadLength, payload=payload)

    @staticmethod
    def test_control_packet():
        header_bytes = LoRaSwarmProtocol.get_header_byte(255, 0x00, 0x00)
        payload = b"Hello 1,2,3"
        control_packet_bytes = LoRaSwarmProtocol.get_control_packet(header_bytes, 0, payload)
        # Try and parse the bytes
        header, content = LoRaSwarmProtocol.parse_packet_header(control_packet_bytes)
        controlPacket = LoRaSwarmProtocol.parse_control_packet(content)
        print(header)
        print(controlPacket)
