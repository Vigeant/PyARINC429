#!/usr/bin/env python3

#import arinc429
import argparse
import sys
from scapy.all import *


parser = argparse.ArgumentParser(description='Parses a pcap containing arinc628 data.')
parser.add_argument('infilepcap')
args = parser.parse_args()

pcap = rdpcap(args.infilepcap)

def airplaneFlightModeData(payload):
    print("parsing airplaneFlightModeData")

def airplaneNavigationData(payload):
    print("parsing airplaneNavigationData")

def cms2ifeDiscretes(payload):
    print("parsing cms2ifeDiscretes")

    

def ife2cmsDiscretes(payload):
    print("parsing ife2cmsDiscretes: %r" % payload)

    dataLen = struct.unpack(">H" ,payload[:2])[0]
    print("dataLen: %d" % dataLen)

    channel1kl_vpa = payload[2] & 0x3
    print("channel1kl_vpa: 0x%X" % channel1kl_vpa)

    channel8kl_bgm = (payload[3] & 0xC0) >> 6
    print("channel8kl_bgm: 0x%X" % channel8kl_bgm)

    channel7kl_pram = (payload[3] & 0x30) >> 4
    print("channel7kl_pram: 0x%X" % channel7kl_pram)

    noPED = (payload[4] & 0xC0) >> 6
    print("noPED: 0x%X" % noPED)
    
    channel10kl = (payload[4] & 0x30) >> 4
    print("channel10kl: 0x%X" % channel10kl)

    videoInUse = (payload[4] & 0x0C) >> 2
    print("vidoeInUse: 0x%X" % videoInUse)

    wifiActive = (payload[13] & 0x0C) >> 2
    print("wifiActive: 0x%X" % wifiActive)

    keyXchResponse = (payload[13] & 0x03) 
    print("keyXchResponse: 0x%X" % keyXchResponse)


for session in pcap.sessions():
    for packet in pcap.sessions()[session]:
        try:
            if packet[UDP].dport == 60700:
                #print(packet[UDP].payload)
                #continue
                payload = packet[UDP].payload.raw_packet_cache
                #import IPython; IPython.embed()
                protocolID = payload[0]
                if protocolID == 0x22:
                    msc = payload[1]
                    command = payload[2]
                    #import IPython; IPython.embed(); quit()
                    if command  == 0x80:
                        continue
                        airplaneFlightModeData(payload[3:])
                    elif command == 0xab:
                        continue
                        airplaneNavigationData(payload[3:])
                    elif command == 0x07:
                        cms2ifeDiscretes(payload[3:])
                    elif command == 0x1b:
                        continue
                        ife2cmsDiscretes(payload[3:]) 

        except IndexError:
           pass


