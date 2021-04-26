import ucollections as collections
class LoRaSwarmTypes:
    Neighbour = collections.namedtuple('Neighbour','nodeId snr received')
