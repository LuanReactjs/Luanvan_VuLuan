import struct
import time
import sys
import argparse
import requests
from Crypto.Cipher import AES
try:
    from Queue import Queue, Empty
except ImportError:
    from queue import Queue, Empty
from bluepy.btle import Peripheral, DefaultDelegate, ADDR_TYPE_RANDOM
from constants import UUIDS, AUTH_STATES, ALERT_TYPES, QUEUE_TYPES
''' TODO
Key should be generated and stored during init
'''
BASE = "0000%s-0000-1000-8000-00805f9b34fb"
SERVICE_HEART_RATE = BASE % '180d'

SERVICE_MIBAND1 = BASE % 'fee0'
UUID_SVC_MIBAND2 = "0000fee100001000800000805f9b34fb"
UUID_CHAR_AUTH = "00000009-0000-3512-2118-0009af100700"
UUID_SVC_ALERT = "0000180200001000800000805f9b34fb"
UUID_CHAR_ALERT = "00002a0600001000800000805f9b34fb"
UUID_SVC_HEART_RATE = "0000180d00001000800000805f9b34fb"
UUID_CHAR_HRM_MEASURE = "00002a3700001000800000805f9b34fb"
UUID_CHAR_HRM_CONTROL = "00002a3900001000800000805f9b34fb"
CHARACTERISTIC_STEPS = "00000007-0000-3512-2118-0009af100700"
CHARACTERISTIC_HEART_RATE_MEASURE = "00002a37-0000-1000-8000-00805f9b34fb"
CHARACTERISTIC_HEART_RATE_CONTROL = "00002a39-0000-1000-8000-00805f9b34fb"
NOTIFICATION_DESCRIPTOR = 0x2902
HRM_COMMAND = 0x15
HRM_MODE_SLEEP      = 0x00
HRM_MODE_CONTINUOUS = 0x01
HRM_MODE_ONE_SHOT   = 0x02

CCCD_UUID = 0x2902

class AuthenticationDelegate(DefaultDelegate):

    """ Xac thuc."""
    def __init__(self, device):
        DefaultDelegate.__init__(self)
        self.device = device

    def handleNotification(self, hnd, data):
        # Debug purposes
        
        if hnd == self.device.char_auth.getHandle():
            if data[:3] == b'\x10\x01\x01':
                self.device.req_rdn()
            elif data[:3] == b'\x10\x01\x04':
                self.device.state = "ERROR: Key Sending failed"
            elif data[:3] == b'\x10\x02\x01':
                random_nr = data[3:]
                self.device.send_enc_rdn(random_nr)
            elif data[:3] == b'\x10\x02\x04':
                self.device.state = "ERROR: Something wrong when requesting the random number..."
            elif data[:3] == b'\x10\x03\x01':
                print("Authenticated!")
                self.device.state = "AUTHENTICATED"
            elif data[:3] == b'\x10\x03\x04':
                print("Encryption Key Auth Fail, sending new key...")
                self.device.send_key()
            
            else:
                self.device.state = "ERROR: Auth failed"
        elif hnd == self.device.char_hrm.getHandle():
            self.device.queue.put(('heart', data))
            #print("Auth Response: " + str(data.encode("hex")))
      
class MiBand2(Peripheral):
    _KEY = b'\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x40\x41\x42\x43\x44\x45'
    _send_key_cmd = struct.pack('<18s', b'\x01\x08' + _KEY)
    _send_rnd_cmd = struct.pack('<2s', b'\x02\x08')
    _send_enc_key = struct.pack('<2s', b'\x03\x08')

    def __init__(self, addr):
        Peripheral.__init__(self, addr, addrType=ADDR_TYPE_RANDOM)
        print("Connected")
        self.queue = Queue()
        self.svc_1 = self.getServiceByUUID(UUIDS.SERVICE_MIBAND1)
        svc = self.getServiceByUUID(UUID_SVC_MIBAND2)
        self.char_auth = svc.getCharacteristics(UUID_CHAR_AUTH)[0]
        self.cccd_auth = self.char_auth.getDescriptors(forUUID=CCCD_UUID)[0]
        self.svc_heart = self.getServiceByUUID(SERVICE_HEART_RATE)
        self.svc_heart = self.getServiceByUUID(UUIDS.SERVICE_HEART_RATE)
        svc = self.getServiceByUUID(UUID_SVC_ALERT)
        self.char_alert = svc.getCharacteristics(UUID_CHAR_ALERT)[0]
        self.heart_measure_callback = None
        svc = self.getServiceByUUID(UUID_SVC_HEART_RATE)
        self.char_hrm_ctrl = svc.getCharacteristics(UUID_CHAR_HRM_CONTROL)[0]
        self.char_hrm = svc.getCharacteristics(CHARACTERISTIC_HEART_RATE_MEASURE)[0]
        self.cccd_hrm = self.char_hrm.getDescriptors(forUUID=CCCD_UUID)[0]
        self.svc_1 = self.getServiceByUUID(SERVICE_MIBAND1)
        self.timeout = 5.0
        self.state = None
        self.auth_notif(True)
        self.waitForNotifications(0.1) 
    def init_after_auth(self):
        self.cccd_hrm.write(b"\x01\x00", True)

    def encrypt(self, message):
        aes = AES.new(self._KEY, AES.MODE_ECB)
        return aes.encrypt(message)

    def auth_notif(self, status):
        if status:
            print("Enabling Auth Service notifications status...")
            self.cccd_auth.write(b"\x01\x00", True)
        elif not status:
            print("Disabling Auth Service notifications status...")
            self.cccd_auth.write(b"\x00\x00", True)
        else:
            print("Something went wrong while changing the Auth Service notifications status...")

    def send_key(self):
        print(" send k...")
        self.char_auth.write(self._send_key_cmd)
        self.waitForNotifications(self.timeout)

    def req_rdn(self):
        print("Requesting random number...")
        self.char_auth.write(self._send_rnd_cmd)
        self.waitForNotifications(self.timeout)

    def send_enc_rdn(self, data):
        print("Sending encrypted random number")
        cmd = self._send_enc_key + self.encrypt(data)
        send_cmd = struct.pack('<18s', cmd)
        self.char_auth.write(send_cmd)
        self.waitForNotifications(self.timeout)

    def initialize(self):
        self.setDelegate(AuthenticationDelegate(self))
        self.send_key()

        while True:
            self.waitForNotifications(0.1)
            if self.state == "AUTHENTICATED":
                return True
            elif self.state:
                return False

    def authenticate(self):
        self.setDelegate(AuthenticationDelegate(self))
        self.req_rdn()

        while True:
            self.waitForNotifications(0.1)
            if self.state == "AUTHENTICATED":
                return True
            elif self.state:
                return False

    def _parse_queue(self):
        while True:
            try:
                res = self.queue.get(False)
                _type = res[0]
                if self.heart_measure_callback and _type == QUEUE_TYPES.HEART:
                    self.heart_measure_callback(struct.unpack('bb', res[1])[1])
                
            except Empty:
                break
    
    def start_heart_rate_realtime(self, heart_measure_callback):
        char_m = self.svc_heart.getCharacteristics(CHARACTERISTIC_HEART_RATE_MEASURE)[0]
        char_d = char_m.getDescriptors(forUUID=NOTIFICATION_DESCRIPTOR)[0]
        char_ctrl = self.svc_heart.getCharacteristics(CHARACTERISTIC_HEART_RATE_CONTROL)[0]

        self.heart_measure_callback = heart_measure_callback

        # stop heart monitor continues & manual
        char_ctrl.write(b'\x15\x02\x00', True)
        char_ctrl.write(b'\x15\x01\x00', True)
        # enable heart monitor notifications
        char_d.write(b'\x01\x00', True)
        # start hear monitor continues
        char_ctrl.write(b'\x15\x01\x01', True)
        t = time.time()
        while True:
            self.waitForNotifications(0.5)
            self._parse_queue()
            # send ping request every 12 sec
            if (time.time() - t) >= 12:
                char_ctrl.write(b'\x16', True)
                t = time.time()
    def get_steps(self):
        char = self.svc_1.getCharacteristics(UUIDS.CHARACTERISTIC_STEPS)[0]
        a = char.read()
        steps = struct.unpack('h', a[1:3])[0] if len(a) >= 3 else None
        meters = struct.unpack('h', a[5:7])[0] if len(a) >= 7 else None
        fat_gramms = struct.unpack('h', a[2:4])[0] if len(a) >= 4 else None
        # why only 1 byte??
        
        callories = struct.unpack('b', a[9:10])[0] if len(a) >= 10 else None
        return {
           steps 
           
        }
    def get_calo(self):
        char = self.svc_1.getCharacteristics(UUIDS.CHARACTERISTIC_STEPS)[0]
        a = char.read()
        steps = struct.unpack('h', a[1:3])[0] if len(a) >= 3 else None
        meters = struct.unpack('h', a[5:7])[0] if len(a) >= 7 else None
        fat_gramms = struct.unpack('h', a[2:4])[0] if len(a) >= 4 else None
        # why only 1 byte??
        callories = struct.unpack('b', a[9:10])[0] if len(a) >= 10 else None
        return {
            
            callories
        }
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('host', action='store', help='MAC of BT device')
    parser.add_argument('-t', action='store', type=float, default=3.0,help='duration of each notification')
    parser.add_argument('-s', '--standard',  action='store_true',help='Shows device information')
    parser.add_argument('--init', action='store_true', default=False)
    parser.add_argument('-n', '--notify', action='store_true', default=False)
    parser.add_argument('-l', '--live',  action='store_true',help='Measures live heart rate')
    arg = parser.parse_args(sys.argv[1:])
    
    print('Connecting to ' + arg.host)
    band = MiBand2(arg.host)
    
    band.setSecurityLevel(level="medium")
  
  
   

    
    def l(x):
        print ('nhip tim:', x)
        payload = {'heart': x,'step': band.get_steps(),'calo':band.get_calo()}
        r = requests.get("http://127.0.0.1:3000/update", params = payload)        

    if arg.live:
        band.initialize()
        
     
     
    
        band.authenticate()

        band.init_after_auth()
        band.start_heart_rate_realtime(heart_measure_callback=l)
    
    band.disconnect()   

if __name__ == "__main__":
    main()
