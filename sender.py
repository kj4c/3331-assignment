#!/usr/bin/env python3
"""
URP Sender Implementation
Implements UDP-based Reliable Protocol (URP) with sliding window, 
packet loss/corruption emulation, and reliable file transfer.
"""

import socket
import struct
import random
import time
import threading
import sys
import os

# constants
MSS = 1000
HEADER_SIZE = 6
MAX_SEQ = 65536 # is 2^16
MSL = 1.0

# segment types
SEG_DATA = 0
SEG_ACK = 1
SEG_SYN = 2
SEG_FIN = 3

class URPSegment:
    """URP Segment representation"""
    
    @staticmethod
    def create_header(seq_num, seg_type, checksum=0):
        """Create URP segment header (6 bytes)"""
        # sequence number (16 bits)
        # reserved (13 bits) + control bits (3 bits)
        flags = 0
        if seg_type == SEG_ACK:
            flags = 0b001  # ack bit
        elif seg_type == SEG_SYN:
            flags = 0b010  # syn bit
        elif seg_type == SEG_FIN:
            flags = 0b100  # fin bit
        # data has flags = 0
     
        header = struct.pack('>HBBH', seq_num, 0, flags, checksum)
        return header
    
    @staticmethod
    def parse_header(header):
        """Parse URP segment header"""
        if len(header) < HEADER_SIZE:
            return None
        
        try:
            seq_num, _, flags_byte, checksum = struct.unpack('>HBBH', header[:HEADER_SIZE])
        except struct.error:
            return None
        
        seg_type = SEG_DATA
        if flags_byte & 0b001:  # ack
            seg_type = SEG_ACK
        elif flags_byte & 0b010:  # syn
            seg_type = SEG_SYN
        elif flags_byte & 0b100:  # fin
            seg_type = SEG_FIN
        
        return {
            'seq_num': seq_num,
            'seg_type': seg_type,
            'checksum': checksum
        }
    
    @staticmethod
    def calculate_checksum(segment):
        """Calculate 16-bit ones' complement checksum."""
        if len(segment) < HEADER_SIZE:
            return 0
        
        data = bytearray(segment)
        data[4:6] = b'\x00\x00'
        
        total = sum(int.from_bytes(data[i:i + 2], 'big') for i in range(0, len(data), 2))
        total = (total & 0xFFFF) + (total >> 16)
        total = (total & 0xFFFF) + (total >> 16)
        
        checksum = (~total) & 0xFFFF
        return checksum or 0xFFFF
    
    @staticmethod
    def create_segment(seq_num, seg_type, data=b''):
        """Create complete URP segment"""
        header = URPSegment.create_header(seq_num, seg_type, 0)
        segment = header + data
        checksum = URPSegment.calculate_checksum(segment)
        # replace checksum in header
        segment = header[:4] + struct.pack('>H', checksum) + data
        return segment
    
    @staticmethod
    def verify_checksum(segment):
        """Verify segment checksum"""
        if len(segment) < HEADER_SIZE:
            return False
        calculated = URPSegment.calculate_checksum(segment)
        received = struct.unpack('>H', segment[4:6])[0]
        return calculated == received


class PLC:
    """Packet Loss and Corruption module"""
    
    def __init__(self, flp, rlp, fcp, rcp, log_file):
        self.flp = flp  
        self.rlp = rlp
        self.fcp = fcp
        self.rcp = rcp
        self.log_file = log_file
        
        # statistics
        self.forward_dropped = 0
        self.forward_corrupted = 0
        self.reverse_dropped = 0
        self.reverse_corrupted = 0
    
    def process_outgoing(self, segment, seg_type, seq_num, payload_len, start_time):
        """Process outgoing segment (forward direction)"""
        def timestamp_ms():
            return ((time.time() - start_time) * 1000) if start_time else 0

        # check for drop
        if random.random() < self.flp:
            self.forward_dropped += 1
            self.log('snd', 'drp', timestamp_ms(), seg_type, seq_num, payload_len)
            return None
        
        # check for corruption
        corrupted = False
        if random.random() < self.fcp:
            corrupted = True
            self.forward_corrupted += 1
            # flip a bit in a random byte (excluding first 4 header bytes)
            if len(segment) > 4:
                byte_idx = random.randint(4, len(segment) - 1)
                bit_idx = random.randint(0, 7)
                byte_val = segment[byte_idx]
                segment = segment[:byte_idx] + bytes([byte_val ^ (1 << bit_idx)]) + segment[byte_idx + 1:]
        
        status = 'cor' if corrupted else 'ok'
        self.log('snd', status, timestamp_ms(), seg_type, seq_num, payload_len)
        
        # send possible corrupted segment
        return segment
    
    def process_incoming(self, segment, start_time):
        """Process incoming segment (reverse direction)"""
        def timestamp_ms():
            return ((time.time() - start_time) * 1000) if start_time else 0
        # parse header to get info for logging
        header_info = URPSegment.parse_header(segment)
        if header_info is None:
            return None
        
        seg_type_str = ['DATA', 'ACK', 'SYN', 'FIN'][header_info['seg_type']]
        seq_num = header_info['seq_num']
        
        # check for drop
        if random.random() < self.rlp:
            self.reverse_dropped += 1
            self.log('rcv', 'drp', timestamp_ms(), seg_type_str, seq_num, 0)
            return None
        
        # check for corruption
        corrupted = False
        if random.random() < self.rcp:
            corrupted = True
            self.reverse_corrupted += 1
            # corrupt: flip a bit in a random byte (excluding first 4 header bytes)
            if len(segment) > 4:
                byte_idx = random.randint(4, len(segment) - 1)
                bit_idx = random.randint(0, 7)
                byte_val = segment[byte_idx]
                segment = segment[:byte_idx] + bytes([byte_val ^ (1 << bit_idx)]) + segment[byte_idx + 1:]
        
        status = 'cor' if corrupted else 'ok'
        self.log('rcv', status, timestamp_ms(), seg_type_str, seq_num, 0)
        return segment
    
    def log(self, direction, status, time_ms, seg_type, seq_num, payload_len):
        """Write log entry"""
        seg_type_str = seg_type if isinstance(seg_type, str) else ['DATA', 'ACK', 'SYN', 'FIN'][seg_type]
        with open(self.log_file, 'a') as f:
            f.write(f"{direction} {status} {time_ms:.2f} {seg_type_str} {seq_num} {payload_len}\n")


class Sender:
    """expects sender_port, receiver_port, txt_file_to_send, max_win, rto, flp, rlp, fcp, rcp"""
    
    def __init__(self, sender_port, receiver_port, txt_file, max_win, rto, flp, rlp, fcp, rcp):
        self.sender_port = int(sender_port)
        self.receiver_port = int(receiver_port)
        self.txt_file = txt_file

        # max amount of data bytes can stransmit  >= 1000 bytes

        if (int(max_win) < 1000):
            print("max_win must be >= 1000 bytes")
            sys.exit(1)

        self.max_win = int(max_win)

        # retransmission timeout in milliseconds (store ms and seconds)
        self.rto_ms = int(rto)
        self.rto_seconds = self.rto_ms / 1000.0
        
        # initialize plc
        self.log_file = 'sender_log.txt'
        # clear log file
        open(self.log_file, 'w').close()

        if (flp < 0 or flp > 1 or rlp < 0 or rlp > 1 or fcp < 0 or fcp > 1 or rcp < 0 or rcp > 1):
            print("flp, rlp, fcp, rcp must be between 0 and 1")
            sys.exit(1)

        self.plc = PLC(flp, rlp, fcp, rcp, self.log_file)
        
        # socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # create socket and bind to sender port
        self.sock.bind(('127.0.0.1', self.sender_port))
        self.sock.settimeout(0.1)
        
        # protocol state
        # beginning state should be syn_sent
        self.state = 'SYN_SENT'

        # generate a random initial sequence number
        self.isn = random.randint(0, MAX_SEQ - 1)

        # right edge of the window
        self.next_seq = (self.isn + 1) % MAX_SEQ

        # left edge of the window
        self.base = self.isn + 1
        self.file_pos = 0
        
        # buffers
        self.unacked_segments = {}  # seq_num -> (segment, payload_len, send_order)
        self.send_order_counter = 0
        self.file_data = None
        
        # timer
        self.timer_running = False
        self.timer_lock = threading.Lock()
        self.timer_thread = None
        
        # statistics
        self.original_data_sent = 0
        self.total_data_sent = 0
        self.original_segments_sent = 0
        self.total_segments_sent = 0
        self.timeout_retransmissions = 0
        self.fast_retransmissions = 0
        self.duplicate_acks_received = 0
        self.corrupted_acks_discarded = 0
        
        # duplicate ack tracking
        self.last_ack = None
        self.dup_ack_count = 0
        
        # timing
        self.start_time = None
        
        # file handling
        self.file_handle = None
        
        # threading
        self.running = True
        self.receive_thread = None
    
    def start_timer(self):
        """Start retransmission timer"""
        with self.timer_lock:
            if not self.timer_running:
                self.timer_running = True
                if self.timer_thread is None or not self.timer_thread.is_alive():
                    # loops for rto milliseconds
                    self.timer_thread = threading.Thread(target=self.timer_thread_loop, daemon=True)
                    self.timer_thread.start()
    
    def stop_timer(self):
        """Stop retransmission timer"""
        with self.timer_lock:
            self.timer_running = False
    
    def timer_thread_loop(self):
        """Timer thread function"""
        while self.running:
            if self.timer_running:
                time.sleep(self.rto_seconds)
                should_handle = False
                with self.timer_lock:
                    if self.timer_running and self.running:
                        should_handle = True
                if should_handle:
                    # timeout occurred
                    self.handle_timeout()
            else:
                time.sleep(0.01)
    
    def handle_timeout(self):
        """Handle timeout from rto, retransmit the SYN or FIN"""
        if not self.unacked_segments:
            self.stop_timer()
            return
        
        # find oldest unacknowledged segment using send order
        oldest_seq, (segment, payload_len, _) = min(
            self.unacked_segments.items(),
            key=lambda item: item[1][2]
        )
        
        # retransmit
        seg_type = SEG_DATA
        
        # if the state is syn_sent, retransmit the SYN
        if self.state == 'SYN_SENT':
            seg_type = SEG_SYN
        # if the state is fin_wait, retransmit the FIN
        elif self.state == 'FIN_WAIT':
            seg_type = SEG_FIN
        
        self.send_segment(segment, seg_type, oldest_seq, payload_len, is_retransmission=True)
        self.timeout_retransmissions += 1
        
        # restart timer
        self.start_timer()
    
    def send_segment(self, segment, seg_type, seq_num, payload_len, is_retransmission=False):
        """Send segment through PLC and socket"""
        if not is_retransmission:
            self.original_segments_sent += 1
            if seg_type == SEG_DATA:
                self.original_data_sent += payload_len
                self.total_data_sent += payload_len
        else:
            if seg_type == SEG_DATA:
                self.total_data_sent += payload_len
        
        self.total_segments_sent += 1
        
        # process through plc
        processed_segment = self.plc.process_outgoing(
            segment, seg_type, seq_num, payload_len, self.start_time
        )
        
        if processed_segment is not None:
            # send through socket
            self.sock.sendto(processed_segment, ('127.0.0.1', self.receiver_port))
    
    def receive_thread_func(self):
        """Thread to receive ACKs"""
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
                
                # process through plc
                processed_data = self.plc.process_incoming(data, self.start_time)
                
                if processed_data is None:
                    continue
                
                # verify checksum
                if not URPSegment.verify_checksum(processed_data):
                    self.corrupted_acks_discarded += 1
                    continue
                
                # parse ack
                header_info = URPSegment.parse_header(processed_data)
                if header_info is None or header_info['seg_type'] != SEG_ACK:
                    continue
                
                ack_num = header_info['seq_num']
                self.handle_ack(ack_num)
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"Error receiving ACK: {e}")
    
    def seq_compare(self, seq1, seq2):
        """Compare sequence numbers accounting for wrap-around"""
        # return true if seq1 >= seq2
        diff = (seq1 - seq2) % MAX_SEQ
        return diff < MAX_SEQ // 2
    
    def handle_ack(self, ack_num):
        """Handle received ACK"""
        # check if duplicate ack
        if self.last_ack is not None and ack_num == self.last_ack:
            self.dup_ack_count += 1
            self.duplicate_acks_received += 1
            
            # fast retransmit on 3 duplicate acks
            if self.dup_ack_count == 3 and self.state == 'ESTABLISHED':
                if self.unacked_segments:
                    oldest_seq, (segment, payload_len, _) = min(
                        self.unacked_segments.items(),
                        key=lambda item: item[1][2]
                    )
                    self.send_segment(segment, SEG_DATA, oldest_seq, payload_len, is_retransmission=True)
                    self.fast_retransmissions += 1
                    self.dup_ack_count = 0
                    self.start_timer()
            return
        
        is_new_ack = False
        if self.last_ack is None:
            is_new_ack = True
        elif self.seq_compare(ack_num, self.last_ack) and ack_num != self.last_ack:
            is_new_ack = True
        
        if is_new_ack:
            # update base
            if self.state == 'SYN_SENT':
                # for intitial connection move base forward after
                # syn is acknowledged
                if ack_num == self.next_seq:
                    self.unacked_segments.pop(self.isn, None)
                    self.state = 'ESTABLISHED'
                    self.base = self.next_seq
                    self.stop_timer()
                    self.dup_ack_count = 0
            elif self.state == 'ESTABLISHED':
                # remove acknowledged segments
                to_remove = []
                for seq in list(self.unacked_segments.keys()):
                    segment, payload_len, _ = self.unacked_segments[seq]
                    seg_end = (seq + payload_len) % MAX_SEQ
                    
                    # check if segment is fully acknowledged
                    # ack num is the next expected byte, so if ack_num > seg_end, segment is acked
                    if self.seq_compare(ack_num, seg_end):
                        to_remove.append(seq)
                
                for seq in to_remove:
                    del self.unacked_segments[seq]
                
                # update base
                if self.seq_compare(ack_num, self.base):
                    self.base = ack_num
                
                # if there are unacked segments
                if self.unacked_segments:
                    self.start_timer()
                else:
                    self.stop_timer()
                
                self.dup_ack_count = 0
            elif self.state == 'FIN_WAIT':
                if ack_num == self.next_seq:
                    # fin acknowledged
                    fin_seq = (ack_num - 1) % MAX_SEQ
                    self.unacked_segments.pop(fin_seq, None)
                    self.state = 'CLOSED'
                    self.stop_timer()
                    self.running = False
                    return
            
            self.last_ack = ack_num
    
    def get_window_size(self):
        """Calculate current window size"""
        if self.state != 'ESTABLISHED':
            return 0
        
        # calculate unacked data
        unacked_data = 0
        for seq, (_, payload_len, _) in self.unacked_segments.items():
            unacked_data += payload_len
        
        available = self.max_win - unacked_data
        return max(0, available)
    
    def read_file_data(self, num_bytes):
        """Read data from file"""
        if self.file_handle is None:
            self.file_handle = open(self.txt_file, 'rb')
        
        data = self.file_handle.read(num_bytes)
        return data
    
    def close_file(self):
        """Close file handle"""
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None
    
    def run(self):
        """Main sender logic"""
        if self.start_time is None:
            self.start_time = time.time()
        
        # start receive thread
        self.receive_thread = threading.Thread(target=self.receive_thread_func, daemon=True)
        self.receive_thread.start()
        
        # begin sending SYN by creating a segement in urp
        # track in unacked map so it can be retransmitted on timeout
        syn_segment = URPSegment.create_segment(self.isn, SEG_SYN)
        self.send_order_counter += 1
        self.unacked_segments[self.isn] = (syn_segment, 0, self.send_order_counter)
        self.send_segment(syn_segment, SEG_SYN, self.isn, 0)

        # start the timer to retransmit the segment if it is not acknowledged
        self.start_timer()
        
        # wait for connection establishment
        while self.state == 'SYN_SENT' and self.running:
            time.sleep(0.01)
        
        if not self.running:
            return
        
        # data transmission phase
        file_size = os.path.getsize(self.txt_file)
        
        while self.file_pos < file_size or self.unacked_segments:
            # send data while window allows
            while self.file_pos < file_size:
                window_size = self.get_window_size()
                if window_size < MSS:
                    break
                
                # read data
                bytes_to_read = min(MSS, file_size - self.file_pos, window_size)
                data = self.read_file_data(bytes_to_read)
                
                if not data:
                    break
                
                # create data segment
                segment = URPSegment.create_segment(self.next_seq, SEG_DATA, data)
                payload_len = len(data)
                
                # store in unacked buffer with send order
                self.send_order_counter += 1
                self.unacked_segments[self.next_seq] = (segment, payload_len, self.send_order_counter)
                
                # send segment
                self.send_segment(segment, SEG_DATA, self.next_seq, payload_len)
                
                # update sequence number and file position
                self.file_pos += payload_len
                self.next_seq = (self.next_seq + payload_len) % MAX_SEQ
                
                # start timer if not running
                if not self.timer_running:
                    self.start_timer()
            
            # wait a bit before checking again
            time.sleep(0.01)
        
        # close file
        self.close_file()
        
        # wait for all data to be acknowledged
        while self.unacked_segments and self.running:
            time.sleep(0.01)
        
        if not self.running:
            return
        
        # done sending data, send FIN
        self.state = 'CLOSING'
        fin_segment = URPSegment.create_segment(self.next_seq, SEG_FIN)
        self.send_order_counter += 1
        self.unacked_segments[self.next_seq] = (fin_segment, 0, self.send_order_counter)
        self.send_segment(fin_segment, SEG_FIN, self.next_seq, 0)
        self.next_seq = (self.next_seq + 1) % MAX_SEQ

        # start the timer to retransmit the FIN if it is not acknowledged
        self.state = 'FIN_WAIT'
        self.start_timer()
        
        # wait for fin ack
        while self.state == 'FIN_WAIT' and self.running:
            time.sleep(0.01)
        
        # write statistics
        self.write_statistics()
    
    def write_statistics(self):
        """Write statistics to log file"""
        with open(self.log_file, 'a') as f:
            f.write(f"\nOriginal data sent: {self.original_data_sent}\n")
            f.write(f"Total data sent: {self.total_data_sent}\n")
            f.write(f"Original segments sent: {self.original_segments_sent}\n")
            f.write(f"Total segments sent: {self.total_segments_sent}\n")
            f.write(f"Timeout retransmissions: {self.timeout_retransmissions}\n")
            f.write(f"Fast retransmissions: {self.fast_retransmissions}\n")
            f.write(f"Duplicate acks received: {self.duplicate_acks_received}\n")
            f.write(f"Corrupted acks discarded: {self.corrupted_acks_discarded}\n")
            f.write(f"PLC forward segments dropped: {self.plc.forward_dropped}\n")
            f.write(f"PLC forward segments corrupted: {self.plc.forward_corrupted}\n")
            f.write(f"PLC reverse segments dropped: {self.plc.reverse_dropped}\n")
            f.write(f"PLC reverse segments corrupted: {self.plc.reverse_corrupted}\n")


def main():
    if len(sys.argv) != 10:
        print("Usage: python3 sender.py sender_port receiver_port txt_file_to_send max_win rto flp rlp fcp rcp")
        sys.exit(1)
    
    sender_port = sys.argv[1]
    receiver_port = sys.argv[2]
    txt_file = sys.argv[3]
    max_win = sys.argv[4]
    rto = sys.argv[5]
    flp = float(sys.argv[6])
    rlp = float(sys.argv[7])
    fcp = float(sys.argv[8])
    rcp = float(sys.argv[9])
    
    sender = Sender(sender_port, receiver_port, txt_file, max_win, rto, flp, rlp, fcp, rcp)
    try:
        sender.run()
        sender.running = False
    except Exception as e:
        print(f"Connection reset: {e}")
        sender.running = False
    finally:
        sender.sock.close()


if __name__ == '__main__':
    main()

