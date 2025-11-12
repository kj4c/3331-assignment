#!/usr/bin/env python3
"""
URP Receiver Implementation
Receives data from URP Sender and writes to file.
"""

import socket
import struct
import time
import threading
import sys

# constants
HEADER_SIZE = 6
MAX_SEQ = 65536  # 2^16
MSL = 1.0  # maximum segment lifetime in seconds

# segment types
SEG_DATA = 0
SEG_ACK = 1
SEG_SYN = 2
SEG_FIN = 3


class URPSegment:
    """URP Segment representation (same as sender)"""
    
    @staticmethod
    def create_header(seq_num, seg_type, checksum=0):
        """Create URP segment header (6 bytes)"""
        flags = 0
        if seg_type == SEG_ACK:
            flags = 0b001
        elif seg_type == SEG_SYN:
            flags = 0b010
        elif seg_type == SEG_FIN:
            flags = 0b100
        
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


class Receiver:
    """URP Receiver implementation"""
    
    def __init__(self, receiver_port, sender_port, txt_file, max_win):
        self.receiver_port = int(receiver_port)
        self.sender_port = int(sender_port)
        self.txt_file = txt_file
        self.max_win = int(max_win)
        
        # log file
        self.log_file = 'receiver_log.txt'
        open(self.log_file, 'w').close()
        
        # socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(1.0) # todo: remove later
        self.sock.bind(('127.0.0.1', self.receiver_port))
        
        # begin state
        self.state = 'LISTEN'
        self.expected_seq = None  # next expected byte
        self.isn = None
        
        # receive buffer: seq_num -> data
        self.receive_buffer = {}
        
        # file handle
        self.file_handle = None
        
        # timing
        self.start_time = None
        
        # statistics
        self.original_data_received = 0
        self.total_data_received = 0
        self.original_segments_received = 0
        self.total_segments_received = 0
        self.corrupted_segments_discarded = 0
        self.duplicate_segments_received = 0
        self.total_acks_sent = 0
        self.duplicate_acks_sent = 0
        
        # track received sequence numbers for duplicates
        self.received_seqs = set()
        
        print("starting receiver")
        self.running = True
    
    def log(self, direction, status, time_ms, seg_type, seq_num, payload_len):
        """Write log entry"""
        seg_type_str = seg_type if isinstance(seg_type, str) else ['DATA', 'ACK', 'SYN', 'FIN'][seg_type]
        with open(self.log_file, 'a') as f:
            f.write(f"{direction} {status} {time_ms:.2f} {seg_type_str} {seq_num} {payload_len}\n")
    
    def send_ack(self, ack_num):
        """Send ACK segment"""
        ack_segment = URPSegment.create_segment(ack_num, SEG_ACK)
        self.sock.sendto(ack_segment, ('127.0.0.1', self.sender_port))
        
        time_ms = (time.time() - self.start_time) * 1000 if self.start_time else 0
        self.log('snd', 'ok', time_ms, 'ACK', ack_num, 0)
        self.total_acks_sent += 1
    
    def write_in_order_data(self):
        """Write all in-order data from buffer to file"""
        if self.file_handle is None:
            self.file_handle = open(self.txt_file, 'wb')
        
        # write data in order
        while self.expected_seq in self.receive_buffer:
            data = self.receive_buffer.pop(self.expected_seq)
            self.file_handle.write(data)
            
            # update expected sequence number
            self.expected_seq = (self.expected_seq + len(data)) % MAX_SEQ
    
    def handle_syn(self, seq_num):
        """Handle SYN segment"""
        if self.state == 'LISTEN':
            # first SYN received
            self.isn = seq_num
            self.expected_seq = (seq_num + 1) % MAX_SEQ

            # swap to ESTABLISHED state and send ack back.
            self.state = 'ESTABLISHED'
            self.send_ack(self.expected_seq)
        elif self.state == 'ESTABLISHED':
            # duplicate SYN
            self.send_ack(self.expected_seq)
            self.duplicate_acks_sent += 1
    
    def handle_data(self, seq_num, data):
        """Handle DATA segment"""
        if self.state != 'ESTABLISHED':
            return
        
        payload_len = len(data)
        
        # check if duplicate
        is_duplicate = seq_num in self.received_seqs
        
        if not is_duplicate:
            self.original_segments_received += 1
            self.original_data_received += payload_len
            self.total_data_received += payload_len
            self.received_seqs.add(seq_num)
        else:
            self.duplicate_segments_received += 1
            # count duplicate data only if it's within the receive window
            # (i.e., we haven't written it yet or it's buffered)
            window_start = self.expected_seq
            window_end_seq = (self.expected_seq + self.max_win) % MAX_SEQ
            
            in_window = False
            if window_end_seq < window_start:  # wrapped around
                if seq_num >= window_start or seq_num < window_end_seq:
                    in_window = True
            else:
                if seq_num >= window_start and seq_num < window_end_seq:
                    in_window = True
            
            # also check if it's in the buffer
            if seq_num in self.receive_buffer:
                in_window = True
            
            if in_window:
                self.total_data_received += payload_len
        
        self.total_segments_received += 1
        
        # check if in order
        if seq_num == self.expected_seq:
            # in order - write immediately (if not duplicate)
            if not is_duplicate:
                if self.file_handle is None:
                    self.file_handle = open(self.txt_file, 'wb')
                self.file_handle.write(data)
                self.expected_seq = (self.expected_seq + payload_len) % MAX_SEQ
                
                # write any buffered in-order data
                self.write_in_order_data()
        else:
            # out of order - buffer if within window and not duplicate
            if not is_duplicate:
                # check if sequence number is within receive window
                window_start = self.expected_seq
                window_end_seq = (self.expected_seq + self.max_win) % MAX_SEQ
                
                # handle wrap-around: check if seq_num is between expected_seq and expected_seq + max_win
                in_window = False
                if window_end_seq < window_start:  # wrapped around
                    if seq_num >= window_start or seq_num < window_end_seq:
                        in_window = True
                else:
                    if seq_num >= window_start and seq_num < window_end_seq:
                        in_window = True
                
                if in_window:
                    if seq_num not in self.receive_buffer:
                        self.receive_buffer[seq_num] = data
        
        # send ack (cumulative)
        self.send_ack(self.expected_seq)
        
        # check if duplicate ack
        if is_duplicate:
            self.duplicate_acks_sent += 1
    
    def handle_fin(self, seq_num):
        """Handle FIN segment"""
        if self.state == 'ESTABLISHED':
            self.write_in_order_data()
            
            # close file
            if self.file_handle:
                self.file_handle.close()
                self.file_handle = None
            
            # send ack
            expected_after_fin = (seq_num + 1) % MAX_SEQ
            self.send_ack(expected_after_fin)
            
            # move to time_wait
            self.state = 'TIME_WAIT'
            
            # start timer thread for time_wait
            timer_thread = threading.Thread(target=self.time_wait_timer, daemon=True)
            timer_thread.start()
        elif self.state == 'TIME_WAIT':
            # duplicate fin - resend ack
            expected_after_fin = (seq_num + 1) % MAX_SEQ
            self.send_ack(expected_after_fin)
            self.duplicate_acks_sent += 1
    
    def time_wait_timer(self):
        """Timer for TIME_WAIT state (2 * MSL)"""
        time.sleep(2 * MSL)
        if self.state == 'TIME_WAIT':
            self.state = 'CLOSED'
            self.running = False
            self.write_statistics()
    
    def run(self):
        """Main receiver logic"""
        # wait for first segment (syn)
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
                
                if self.start_time is None:
                    self.start_time = time.time()
                
                time_ms = (time.time() - self.start_time) * 1000
                
                # verify checksum
                if not URPSegment.verify_checksum(data):
                    self.corrupted_segments_discarded += 1
                    self.total_segments_received += 1
                    
                    # log corrupted segment (try to parse for logging)
                    header_info = URPSegment.parse_header(data)
                    if header_info:
                        seg_type_str = ['DATA', 'ACK', 'SYN', 'FIN'][header_info['seg_type']]
                        self.log('rcv', 'cor', time_ms, seg_type_str, header_info['seq_num'], 0)
                    continue
                
                # parse header
                header_info = URPSegment.parse_header(data)
                if header_info is None:
                    continue
                
                seq_num = header_info['seq_num']
                seg_type = header_info['seg_type']
                payload = data[HEADER_SIZE:]
                
                # handle segment based on type
                if seg_type == SEG_SYN:
                    self.log('rcv', 'ok', time_ms, 'SYN', seq_num, 0)
                    self.handle_syn(seq_num)
                elif seg_type == SEG_DATA:
                    self.log('rcv', 'ok', time_ms, 'DATA', seq_num, len(payload))
                    self.handle_data(seq_num, payload)
                elif seg_type == SEG_FIN:
                    self.log('rcv', 'ok', time_ms, 'FIN', seq_num, 0)
                    self.handle_fin(seq_num)
                
            except socket.timeout:
                # timeout occurred, check if we should continue running
                continue
            except Exception as e:
                if self.running:
                    print(f"Connection reset: {e}")
                    self.running = False
                    break
    
    def write_statistics(self):
        """Write statistics to log file"""
        with open(self.log_file, 'a') as f:
            f.write(f"\nOriginal data received: {self.original_data_received}\n")
            f.write(f"Total data received: {self.total_data_received}\n")
            f.write(f"Original segments received: {self.original_segments_received}\n")
            f.write(f"Total segments received: {self.total_segments_received}\n")
            f.write(f"Corrupted segments discarded: {self.corrupted_segments_discarded}\n")
            f.write(f"Duplicate segments received: {self.duplicate_segments_received}\n")
            f.write(f"Total acks sent: {self.total_acks_sent}\n")
            f.write(f"Duplicate acks sent: {self.duplicate_acks_sent}\n")


def main():
    if len(sys.argv) != 5:
        print("Usage: python3 receiver.py receiver_port sender_port txt_file_received max_win")
        sys.exit(1)
    
    receiver_port = sys.argv[1]
    sender_port = sys.argv[2]
    txt_file = sys.argv[3]
    max_win = sys.argv[4]
    
    receiver = Receiver(receiver_port, sender_port, txt_file, max_win)
    try:
        receiver.run()
    except KeyboardInterrupt:
        receiver.running = False
    except Exception as e:
        print(f"Connection reset: {e}")
        receiver.running = False
    finally:
        receiver.sock.close()
        if receiver.file_handle:
            receiver.file_handle.close()


if __name__ == '__main__':
    main()

