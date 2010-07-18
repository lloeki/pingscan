#!/usr/bin/env python

import os
import sys
import re
import time
import random
import threading
from threading import Thread


## token management

_bucket = None

class Bucket:
    def __init__(self, token_count):
        self.tokens = 50

    def take(self):
        while self.tokens < 0:
            time.sleep(1)
        self.tokens = self.tokens - 1

    def give(self):
        self.tokens = self.tokens + 1

    @staticmethod
    def get_bucket():
        global _bucket
        if _bucket == None:
            _bucket = Bucket(30)
        return _bucket

## safe-ify files WRT threads

tls = threading.local()

class ThreadSafeFile(object):
  def __init__(self, f):
    self.f = f
    self.lock = threading.RLock()
    self.nesting = 0

  def _getlock(self):
    self.lock.acquire()
    self.nesting += 1

  def _droplock(self):
    nesting = self.nesting
    self.nesting = 0
    for i in range(nesting):
      self.lock.release()

  def __getattr__(self, name):
    if name == 'softspace':
      return tls.softspace
    else:
      raise AttributeError(name)

  def __setattr__(self, name, value):
    if name == 'softspace':
      tls.softspace = value
    else:
      return object.__setattr__(self, name, value)

  def write(self, data):
    self._getlock()
    self.f.write(data)
    if data == '\n':
      self._droplock()

## functional threading

class FunctionThread(Thread):
    def __init__(self, function, *args, **kwargs):
        Thread.__init__(self)
        self.function = function
        self.args = args
        self.kwargs = kwargs

    def run(self):
        self.function(*self.args, **self.kwargs)

def test(message):
    time.sleep(random.random())
    print message

## pinger

def ping(ip, on_start, on_completion):
    on_start(ip)
    lifeline = re.compile(r"(\d) packets received")
    pingaling = os.popen("ping -q -W1 -c2 %s 2> /dev/null" % ip,"r")
    while True:
        line = pingaling.readline()
        if not line:
            break
        igot = re.findall(lifeline, line)
        if igot:
            on_completion(ip, int(igot[0]))

## ip tools

def ipv4_to_int(string):
    ipv4 = re.compile(r"(\d+).(\d+).(\d+).(\d+)")
    values = re.findall(ipv4, string)[0]
    address = (int(values[0])*256**3 +
               int(values[1])*256**2 +
               int(values[2])*256 +
               int(values[3]))
    return address

def int_to_ipv4(address):
    blocks = [ ]
    blocks.append(address & 0x000000FF)
    blocks.append((address & 0x0000FF00) / 256)
    blocks.append((address & 0x00FF0000) / 256**2)
    blocks.append((address & 0xFF000000) / 256**3)
    return "%d.%d.%d.%d" % (blocks[3], blocks[2], blocks[1], blocks[0])
    
def cidr_mask(bits):
    mask_bits = [ 1 for i in range(32-bits, 32)] + [ 0 for i in range(0, 32-bits) ]
    mask = sum([mask_bits[i]*2**(31-i) for i in range(0,32)])
    return mask

def cidr_range(address, bits, width=32):
    mask = cidr_mask(bits)
    start = mask & address
    end = start | ~mask & 2**width-1
    return (start, end)

def ipv4_xrange(cidr_net):
    cidr = re.compile(r"([^/]+)/(\d+)")
    cidr_values = re.findall(cidr, cidr_net)[0]
    address = ipv4_to_int(cidr_values[0])
    slash = int(cidr_values[1])
    (start, end) = cidr_range(address, slash)
    for address in xrange(start+1, end-1):
        yield address
    raise StopIteration

## threaded range pinger

def start_ping(ip):
    #print "%s: pinging..." % ip
    Bucket.get_bucket().take()

def give_result(ip, replies):
    Bucket.get_bucket().give()
    if replies > 0:
        result = "alive (%s)" % replies
    else:
        result = "no reply"
        return
    print "%s: %s" % (ip, result)

def ping_range(cidr):
    pingers = []
    for ip in ipv4_xrange(cidr):
        pinger = FunctionThread(ping, int_to_ipv4(ip), start_ping, give_result)
        pinger.start()
        pingers.append(pinger)
        time.sleep(0.1)
    
    for pinger in pingers:
        pinger.join()

## main

if __name__ == "__main__":
    # sanitize stdout
    sys.stdout = ThreadSafeFile(sys.stdout)
    
    print "Starting pinging %s..." % sys.argv[1]
    ping_range(sys.argv[1])
    print "Done!"
