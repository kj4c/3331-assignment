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

# Constants
MSS = 1000  # Maximum Segment Size (payload only)
HEADER_SIZE = 6
MAX_SEQ = 65536  # 2^16
MSL = 1.0  # Maximum Segment Lifetime in seconds

# Segment types
SEG_DATA = 0
SEG_ACK = 1
SEG_SYN = 2
SEG_FIN = 3

class URPSegment:
    """URP Segment representation"""
    
    @staticmethod
    def create_header(seq_num, seg_type, checksum=0):
        """Create URP segment header (6 bytes)"""
        # Sequence number (16 bits)
        # Reserved (13 bits) + Control bits (3 bits)
        flags = 0
        if seg_type == SEG_ACK:
            flags = 0b001  # ACK bit
        elif seg_type == SEG_SYN:
            flags = 0b010  # SYN bit
        elif seg_type == SEG_FIN:
            flags = 0b100  # FIN bit
        # DATA has flags = 0
        
        # # Pack: sequence number (H = unsigned short, big-endian)
        # header = struct.pack('>H', seq_num)
        # # Pack flags byte: reserved (13 bits = 0) + flags (3 bits)
        # header += struct.pack('B', flags)
        # # Pack checksum (H = unsigned short, big-endian)
        # header += struct.pack('>H', checksum)
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
        if flags_byte & 0b001:  # ACK
            seg_type = SEG_ACK
        elif flags_byte & 0b010:  # SYN
            seg_type = SEG_SYN
        elif flags_byte & 0b100:  # FIN
            seg_type = SEG_FIN
        
        return {
            'seq_num': seq_num,
            'seg_type': seg_type,
            'checksum': checksum
        }
    
    @staticmethod
    def calculate_checksum(segment):
        """Calculate 16-bit checksum (ones' complement sum)"""
        if len(segment) < HEADER_SIZE:
            return 0
        
        # Create segment with checksum field set to 0
        segment_without_checksum = segment[:4] + b'\x00\x00' + segment[6:]
        
        # Calculate ones' complement sum
        total = 0
        # Process 16-bit words
        for i in range(0, len(segment_without_checksum), 2):
            if i + 1 < len(segment_without_checksum):
                word = (segment_without_checksum[i] << 8) + segment_without_checksum[i + 1]
            else:
                word = (segment_without_checksum[i] << 8)
            total += word
        
        # Add carry bits
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        
        # Ones' complement
        checksum = (~total) & 0xFFFF
        return checksum if checksum != 0 else 0xFFFF
    
    @staticmethod
    def create_segment(seq_num, seg_type, data=b''):
        """Create complete URP segment"""
        header = URPSegment.create_header(seq_num, seg_type, 0)
        segment = header + data
        checksum = URPSegment.calculate_checksum(segment)
        # Replace checksum in header
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
        self.flp = flp  # Forward loss probability
        self.rlp = rlp  # Reverse loss probability
        self.fcp = fcp  # Forward corruption probability
        self.rcp = rcp  # Reverse corruption probability
        self.log_file = log_file
        
        # Statistics
        self.forward_dropped = 0
        self.forward_corrupted = 0
        self.reverse_dropped = 0
        self.reverse_corrupted = 0
    
    def process_outgoing(self, segment, seg_type, seq_num, payload_len, start_time):
        """Process outgoing segment (forward direction)"""
        # Check for drop
        if random.random() < self.flp:
            self.forward_dropped += 1
            self.log('snd', 'drp', time.time() - start_time, seg_type, seq_num, payload_len)
            return None
        
        # Check for corruption
        corrupted = False
        if random.random() < self.fcp:
            corrupted = True
            self.forward_corrupted += 1
            # Corrupt: flip a bit in a random byte (excluding first 4 header bytes)
            if len(segment) > 4:
                byte_idx = random.randint(4, len(segment) - 1)
                bit_idx = random.randint(0, 7)
                byte_val = segment[byte_idx]
                segment = segment[:byte_idx] + bytes([byte_val ^ (1 << bit_idx)]) + segment[byte_idx + 1:]
        
        status = 'cor' if corrupted else 'ok'
        self.log('snd', status, time.time() - start_time, seg_type, seq_num, payload_len)
        return segment
    
    def process_incoming(self, segment, start_time):
        """Process incoming segment (reverse direction)"""
        # Parse header to get info for logging
        header_info = URPSegment.parse_header(segment)
        if header_info is None:
            return None
        
        seg_type_str = ['DATA', 'ACK', 'SYN', 'FIN'][header_info['seg_type']]
        seq_num = header_info['seq_num']
        
        # Check for drop
        if random.random() < self.rlp:
            self.reverse_dropped += 1
            self.log('rcv', 'drp', time.time() - start_time, seg_type_str, seq_num, 0)
            return None
        
        # Check for corruption
        corrupted = False
        if random.random() < self.rcp:
            corrupted = True
            self.reverse_corrupted += 1
            # Corrupt: flip a bit in a random byte (excluding first 4 header bytes)
            if len(segment) > 4:
                byte_idx = random.randint(4, len(segment) - 1)
                bit_idx = random.randint(0, 7)
                byte_val = segment[byte_idx]
                segment = segment[:byte_idx] + bytes([byte_val ^ (1 << bit_idx)]) + segment[byte_idx + 1:]
        
        status = 'cor' if corrupted else 'ok'
        self.log('rcv', status, time.time() - start_time, seg_type_str, seq_num, 0)
        return segment
    
    def log(self, direction, status, time_ms, seg_type, seq_num, payload_len):
        """Write log entry"""
        seg_type_str = seg_type if isinstance(seg_type, str) else ['DATA', 'ACK', 'SYN', 'FIN'][seg_type]
        with open(self.log_file, 'a') as f:
            f.write(f"{direction} {status} {time_ms:.2f} {seg_type_str} {seq_num} {payload_len}\n")


class Sender:
    """URP Sender implementation"""
    
    def __init__(self, sender_port, receiver_port, txt_file, max_win, rto, flp, rlp, fcp, rcp):
        self.sender_port = int(sender_port)
        self.receiver_port = int(receiver_port)
        self.txt_file = txt_file
        self.max_win = int(max_win)
        self.rto = int(rto)  # RTO in seconds
        
        # Initialize PLC
        self.log_file = 'sender_log.txt'
        # Clear log file
        open(self.log_file, 'w').close()
        self.plc = PLC(flp, rlp, fcp, rcp, self.log_file)
        
        # Socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', self.sender_port))
        self.sock.settimeout(0.1)  # Small timeout for checking
        
        # Protocol state
        self.state = 'SYN_SENT'  # Start by sending SYN
        self.isn = random.randint(0, MAX_SEQ - 1)
        self.next_seq = (self.isn + 1) % MAX_SEQ
        self.base = self.isn + 1  # First unacknowledged byte
        self.file_pos = 0
        
        # Buffers
        self.unacked_segments = {}  # seq_num -> (segment, payload_len, is_retransmission)
        self.file_data = None
        
        # Timer
        self.timer_running = False
        self.timer_lock = threading.Lock()
        self.timer_thread = None
        
        # Statistics
        self.original_data_sent = 0
        self.total_data_sent = 0
        self.original_segments_sent = 0
        self.total_segments_sent = 0
        self.timeout_retransmissions = 0
        self.fast_retransmissions = 0
        self.duplicate_acks_received = 0
        self.corrupted_acks_discarded = 0
        
        # Duplicate ACK tracking
        self.last_ack = None
        self.dup_ack_count = 0
        
        # Timing
        self.start_time = None
        
        # File handling
        self.file_handle = None
        
        # Threading
        self.running = True
        self.receive_thread = None
    
    def start_timer(self):
        """Start retransmission timer"""
        with self.timer_lock:
            if not self.timer_running:
                self.timer_running = True
                if self.timer_thread is None or not self.timer_thread.is_alive():
                    self.timer_thread = threading.Thread(target=self._timer_thread, daemon=True)
                    self.timer_thread.start()
    
    def stop_timer(self):
        """Stop retransmission timer"""
        with self.timer_lock:
            self.timer_running = False
    
    def _timer_thread(self):
        """Timer thread function"""
        while self.running:
            if self.timer_running:
                time.sleep(self.rto)
                with self.timer_lock:
                    if self.timer_running and self.running:
                        # Timeout occurred
                        self._handle_timeout()
            else:
                time.sleep(0.01)
    
    def _handle_timeout(self):
        """Handle timeout - retransmit oldest unacknowledged segment"""
        if not self.unacked_segments:
            self.stop_timer()
            return
        
        # Find oldest unacknowledged segment
        oldest_seq = min(self.unacked_segments.keys())
        segment, payload_len, _ = self.unacked_segments[oldest_seq]
        
        # Retransmit
        seg_type = SEG_DATA
        if self.state == 'SYN_SENT':
            seg_type = SEG_SYN
        elif self.state == 'FIN_WAIT':
            seg_type = SEG_FIN
        
        self._send_segment(segment, seg_type, oldest_seq, payload_len, is_retransmission=True)
        self.timeout_retransmissions += 1
        
        # Restart timer
        self.start_timer()
    
    def _send_segment(self, segment, seg_type, seq_num, payload_len, is_retransmission=False):
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
        
        # Process through PLC
        processed_segment = self.plc.process_outgoing(
            segment, seg_type, seq_num, payload_len, self.start_time
        )
        
        if processed_segment is not None:
            # Send through socket
            self.sock.sendto(processed_segment, ('127.0.0.1', self.receiver_port))
    
    def _receive_thread(self):
        """Thread to receive ACKs"""
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
                
                # Process through PLC
                processed_data = self.plc.process_incoming(data, self.start_time)
                
                if processed_data is None:
                    continue  # Dropped by PLC
                
                # Verify checksum
                if not URPSegment.verify_checksum(processed_data):
                    self.corrupted_acks_discarded += 1
                    continue
                
                # Parse ACK
                header_info = URPSegment.parse_header(processed_data)
                if header_info is None or header_info['seg_type'] != SEG_ACK:
                    continue
                
                ack_num = header_info['seq_num']
                self._handle_ack(ack_num)
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"Error receiving ACK: {e}")
    
    def _seq_compare(self, seq1, seq2):
        """Compare sequence numbers accounting for wrap-around"""
        # Return True if seq1 >= seq2
        diff = (seq1 - seq2) % MAX_SEQ
        return diff < MAX_SEQ // 2
    
    def _handle_ack(self, ack_num):
        """Handle received ACK"""
        # Check if duplicate ACK
        if self.last_ack is not None and ack_num == self.last_ack:
            self.dup_ack_count += 1
            self.duplicate_acks_received += 1
            
            # Fast retransmit on 3 duplicate ACKs
            if self.dup_ack_count == 3 and self.state == 'ESTABLISHED':
                # Retransmit oldest unacknowledged DATA segment
                if self.unacked_segments:
                    oldest_seq = min(self.unacked_segments.keys())
                    segment, payload_len, _ = self.unacked_segments[oldest_seq]
                    self._send_segment(segment, SEG_DATA, oldest_seq, payload_len, is_retransmission=True)
                    self.fast_retransmissions += 1
                    self.dup_ack_count = 0
                    self.start_timer()
            return
        
        # New ACK - check if it advances the window
        is_new_ack = False
        if self.last_ack is None:
            is_new_ack = True
        elif self._seq_compare(ack_num, self.last_ack) and ack_num != self.last_ack:
            is_new_ack = True
        
        if is_new_ack:
            # Update base
            if self.state == 'SYN_SENT':
                if ack_num == self.next_seq:
                    self.state = 'ESTABLISHED'
                    self.base = self.next_seq
                    self.stop_timer()
                    self.dup_ack_count = 0
            elif self.state == 'ESTABLISHED':
                # Remove acknowledged segments
                to_remove = []
                for seq in list(self.unacked_segments.keys()):
                    segment, payload_len, _ = self.unacked_segments[seq]
                    seg_end = (seq + payload_len) % MAX_SEQ
                    
                    # Check if segment is fully acknowledged
                    # ACK num is the next expected byte, so if ack_num > seg_end, segment is acked
                    if self._seq_compare(ack_num, seg_end):
                        to_remove.append(seq)
                
                for seq in to_remove:
                    del self.unacked_segments[seq]
                
                # Update base
                if self._seq_compare(ack_num, self.base):
                    self.base = ack_num
                
                # Restart timer if there are unacked segments
                if self.unacked_segments:
                    self.start_timer()
                else:
                    self.stop_timer()
                
                self.dup_ack_count = 0
            elif self.state == 'FIN_WAIT':
                if ack_num == self.next_seq:
                    # FIN acknowledged
                    self.state = 'CLOSED'
                    self.stop_timer()
                    self.running = False
                    return
            
            self.last_ack = ack_num
    
    def _get_window_size(self):
        """Calculate current window size"""
        if self.state != 'ESTABLISHED':
            return 0
        
        # Calculate bytes in flight (unacknowledged data)
        bytes_in_flight = 0
        for seq, (_, payload_len, _) in self.unacked_segments.items():
            bytes_in_flight += payload_len
        
        available = self.max_win - bytes_in_flight
        return max(0, available)
    
    def _read_file_data(self, num_bytes):
        """Read data from file"""
        if self.file_handle is None:
            self.file_handle = open(self.txt_file, 'rb')
        
        data = self.file_handle.read(num_bytes)
        return data
    
    def _close_file(self):
        """Close file handle"""
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None
    
    def run(self):
        """Main sender logic"""
        self.start_time = time.time()
        
        # Start receive thread
        self.receive_thread = threading.Thread(target=self._receive_thread, daemon=True)
        self.receive_thread.start()
        
        # Connection setup: Send SYN
        syn_segment = URPSegment.create_segment(self.isn, SEG_SYN)
        self._send_segment(syn_segment, SEG_SYN, self.isn, 0)
        self.start_timer()
        
        # Wait for connection establishment
        while self.state == 'SYN_SENT' and self.running:
            time.sleep(0.01)
        
        if not self.running:
            return
        
        # Data transmission phase
        file_size = os.path.getsize(self.txt_file)
        
        while self.file_pos < file_size or self.unacked_segments:
            # Send data while window allows
            while self.file_pos < file_size:
                window_size = self._get_window_size()
                if window_size < MSS:
                    break
                
                # Read data
                bytes_to_read = min(MSS, file_size - self.file_pos, window_size)
                data = self._read_file_data(bytes_to_read)
                
                if not data:
                    break
                
                # Create DATA segment
                segment = URPSegment.create_segment(self.next_seq, SEG_DATA, data)
                payload_len = len(data)
                
                # Store in unacked buffer
                self.unacked_segments[self.next_seq] = (segment, payload_len, False)
                
                # Send segment
                self._send_segment(segment, SEG_DATA, self.next_seq, payload_len)
                
                # Update sequence number and file position
                self.file_pos += payload_len
                self.next_seq = (self.next_seq + payload_len) % MAX_SEQ
                
                # Start timer if not running
                if not self.timer_running:
                    self.start_timer()
            
            # Wait a bit before checking again
            time.sleep(0.01)
        
        # Close file
        self._close_file()
        
        # Wait for all data to be acknowledged
        while self.unacked_segments and self.running:
            time.sleep(0.01)
        
        if not self.running:
            return
        
        # Connection teardown: Send FIN
        self.state = 'CLOSING'
        fin_segment = URPSegment.create_segment(self.next_seq, SEG_FIN)
        self._send_segment(fin_segment, SEG_FIN, self.next_seq, 0)
        self.unacked_segments[self.next_seq] = (fin_segment, 0, False)
        self.next_seq = (self.next_seq + 1) % MAX_SEQ
        self.state = 'FIN_WAIT'
        self.start_timer()
        
        # Wait for FIN ACK
        while self.state == 'FIN_WAIT' and self.running:
            time.sleep(0.01)
        
        # Write statistics
        self._write_statistics()
    
    def _write_statistics(self):
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
        print("starting sender")
        sender.run()
        sender.running = False
    except Exception as e:
        print(f"Connection reset: {e}")
        sender.running = False
    finally:
        sender.sock.close()


if __name__ == '__main__':
    main()

