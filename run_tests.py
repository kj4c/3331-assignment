#!/usr/bin/env python3
"""
Comprehensive test suite for URP implementation
Tests all scenarios from the marking policy
"""

import subprocess
import time
import os
import shutil
import filecmp
from pathlib import Path

# Test configuration
BASE_PORT = 50000
TEST_DIR = "test_results"
TEST_FILES = {
    "small.txt": "A" * 500,  # 500 bytes - single segment
    "medium.txt": "B" * 2500,  # 2500 bytes - multiple segments
    "large.txt": "C" * 5000,  # 5000 bytes - many segments
}

def create_test_files():
    """Create test files"""
    for filename, content in TEST_FILES.items():
        with open(filename, 'w') as f:
            f.write(content)
    print("Created test files")

def cleanup():
    """Clean up test artifacts"""
    for filename in TEST_FILES.keys():
        if os.path.exists(filename):
            os.remove(filename)
    if os.path.exists("received.txt"):
        os.remove("received.txt")
    if os.path.exists("sender_log.txt"):
        os.remove("sender_log.txt")
    if os.path.exists("receiver_log.txt"):
        os.remove("receiver_log.txt")

def run_test(test_name, receiver_port, sender_port, test_file, max_win, rto, flp, rlp, fcp, rcp):
    """Run a single test"""
    print(f"\n{'='*60}")
    print(f"Running: {test_name}")
    print(f"{'='*60}")
    
    # Clean up previous run
    cleanup()
    create_test_files()
    
    # Prepare output directory
    output_dir = os.path.join(TEST_DIR, test_name.replace(" ", "_"))
    os.makedirs(output_dir, exist_ok=True)
    
    # Start receiver
    receiver_cmd = [
        "python3", "receiver.py",
        str(receiver_port), str(sender_port),
        "received.txt", str(max_win)
    ]
    
    print(f"Starting receiver: {' '.join(receiver_cmd)}")
    receiver = subprocess.Popen(
        receiver_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Give receiver time to start
    time.sleep(0.5)
    
    # Start sender
    sender_cmd = [
        "python3", "sender.py",
        str(sender_port), str(receiver_port),
        test_file, str(max_win), str(rto),
        str(flp), str(rlp), str(fcp), str(rcp)
    ]
    
    print(f"Starting sender: {' '.join(sender_cmd)}")
    sender = subprocess.Popen(
        sender_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Wait for sender to complete (with timeout)
    try:
        sender.wait(timeout=60)
    except subprocess.TimeoutExpired:
        print("WARNING: Sender timed out after 60 seconds")
        sender.kill()
    
    # Wait a bit for receiver to finish
    time.sleep(2)
    
    # Terminate receiver if still running
    if receiver.poll() is None:
        receiver.terminate()
        try:
            receiver.wait(timeout=5)
        except subprocess.TimeoutExpired:
            receiver.kill()
    
    # Collect outputs
    sender_stdout, sender_stderr = sender.communicate()
    receiver_stdout, receiver_stderr = receiver.communicate()
    
    # Save all outputs
    with open(os.path.join(output_dir, "sender_stdout.txt"), "wb") as f:
        f.write(sender_stdout)
    
    with open(os.path.join(output_dir, "sender_stderr.txt"), "wb") as f:
        f.write(sender_stderr)
    
    with open(os.path.join(output_dir, "receiver_stdout.txt"), "wb") as f:
        f.write(receiver_stdout)
    
    with open(os.path.join(output_dir, "receiver_stderr.txt"), "wb") as f:
        f.write(receiver_stderr)
    
    # Copy logs
    if os.path.exists("sender_log.txt"):
        shutil.copy("sender_log.txt", os.path.join(output_dir, "sender_log.txt"))
    
    if os.path.exists("receiver_log.txt"):
        shutil.copy("receiver_log.txt", os.path.join(output_dir, "receiver_log.txt"))
    
    # Compare files
    files_match = False
    if os.path.exists(test_file) and os.path.exists("received.txt"):
        files_match = filecmp.cmp(test_file, "received.txt", shallow=False)
    
    # Write test summary
    summary = f"""
Test: {test_name}
Parameters:
  Receiver Port: {receiver_port}
  Sender Port: {sender_port}
  Test File: {test_file}
  Max Window: {max_win}
  RTO: {rto}
  Forward Loss: {flp}
  Reverse Loss: {rlp}
  Forward Corruption: {fcp}
  Reverse Corruption: {rcp}

Results:
  Sender Exit Code: {sender.returncode}
  Receiver Exit Code: {receiver.returncode}
  Files Match: {files_match}
  Original File Size: {os.path.getsize(test_file) if os.path.exists(test_file) else 'N/A'}
  Received File Size: {os.path.getsize('received.txt') if os.path.exists('received.txt') else 'N/A'}
"""
    
    with open(os.path.join(output_dir, "summary.txt"), "w") as f:
        f.write(summary)
    
    print(summary)
    
    return {
        "name": test_name,
        "sender_exit": sender.returncode,
        "receiver_exit": receiver.returncode,
        "files_match": files_match,
        "output_dir": output_dir
    }

def main():
    """Run all tests"""
    print("URP Implementation Test Suite")
    print("="*60)
    
    # Create test directory
    os.makedirs(TEST_DIR, exist_ok=True)
    
    results = []
    port_counter = BASE_PORT
    
    # Test 1: Stop and Wait over Reliable Channel
    print("\n" + "="*60)
    print("TEST 1: Stop and Wait over Reliable Channel")
    print("="*60)
    
    for rto in [50, 100, 200]:
        for test_file in TEST_FILES.keys():
            test_name = f"Test1_RTO{rto}_{test_file.replace('.txt', '')}"
            result = run_test(
                test_name, port_counter, port_counter + 1,
                test_file, 1000, rto, 0, 0, 0, 0
            )
            results.append(result)
            port_counter += 2
            time.sleep(1)
    
    # Test 2: Stop and Wait over Unreliable Channel
    print("\n" + "="*60)
    print("TEST 2: Stop and Wait over Unreliable Channel")
    print("="*60)
    
    # 2a: Loss only
    print("\n2a: Loss only")
    for rto in [100, 200]:
        for flp, rlp in [(0.1, 0.1), (0.2, 0.1)]:
            test_name = f"Test2a_Loss_RTO{rto}_FLP{flp}_RLP{rlp}"
            result = run_test(
                test_name, port_counter, port_counter + 1,
                "medium.txt", 1000, rto, flp, rlp, 0, 0
            )
            results.append(result)
            port_counter += 2
            time.sleep(1)
    
    # 2b: Corruption only
    print("\n2b: Corruption only")
    for rto in [100, 200]:
        for fcp, rcp in [(0.1, 0.1), (0.2, 0.1)]:
            test_name = f"Test2b_Corrupt_RTO{rto}_FCP{fcp}_RCP{rcp}"
            result = run_test(
                test_name, port_counter, port_counter + 1,
                "medium.txt", 1000, rto, 0, 0, fcp, rcp
            )
            results.append(result)
            port_counter += 2
            time.sleep(1)
    
    # 2c: Loss and Corruption
    print("\n2c: Loss and Corruption")
    for rto in [100]:
        test_name = f"Test2c_Both_RTO{rto}"
        result = run_test(
            test_name, port_counter, port_counter + 1,
            "medium.txt", 1000, rto, 0.1, 0.1, 0.1, 0.1
        )
        results.append(result)
        port_counter += 2
        time.sleep(1)
    
    # Test 3: Sliding Window over Reliable Channel
    print("\n" + "="*60)
    print("TEST 3: Sliding Window over Reliable Channel")
    print("="*60)
    
    for max_win in [2000, 3000]:
        for rto in [100]:
            test_name = f"Test3_Win{max_win}_RTO{rto}"
            result = run_test(
                test_name, port_counter, port_counter + 1,
                "large.txt", max_win, rto, 0, 0, 0, 0
            )
            results.append(result)
            port_counter += 2
            time.sleep(1)
    
    # Test 4: Sliding Window over Unreliable Channel
    print("\n" + "="*60)
    print("TEST 4: Sliding Window over Unreliable Channel")
    print("="*60)
    
    # 4a: Loss only
    print("\n4a: Loss only")
    for max_win in [2000]:
        test_name = f"Test4a_Loss_Win{max_win}"
        result = run_test(
            test_name, port_counter, port_counter + 1,
            "large.txt", max_win, 100, 0.1, 0.1, 0, 0
        )
        results.append(result)
        port_counter += 2
        time.sleep(1)
    
    # 4b: Corruption only
    print("\n4b: Corruption only")
    for max_win in [2000]:
        test_name = f"Test4b_Corrupt_Win{max_win}"
        result = run_test(
            test_name, port_counter, port_counter + 1,
            "large.txt", max_win, 100, 0, 0, 0.1, 0.1
        )
        results.append(result)
        port_counter += 2
        time.sleep(1)
    
    # 4c: Loss and Corruption
    print("\n4c: Loss and Corruption")
    for max_win in [2000]:
        test_name = f"Test4c_Both_Win{max_win}"
        result = run_test(
            test_name, port_counter, port_counter + 1,
            "large.txt", max_win, 100, 0.05, 0.05, 0.05, 0.05
        )
        results.append(result)
        port_counter += 2
        time.sleep(1)
    
    # Final summary
    print("\n" + "="*60)
    print("FINAL TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for r in results if r["files_match"] and r["sender_exit"] == 0)
    total = len(results)
    
    summary_file = os.path.join(TEST_DIR, "FINAL_SUMMARY.txt")
    with open(summary_file, "w") as f:
        f.write(f"Total Tests: {total}\n")
        f.write(f"Passed: {passed}\n")
        f.write(f"Failed: {total - passed}\n\n")
        
        for r in results:
            status = "PASS" if r["files_match"] and r["sender_exit"] == 0 else "FAIL"
            f.write(f"{status}: {r['name']}\n")
            f.write(f"  Files Match: {r['files_match']}\n")
            f.write(f"  Sender Exit: {r['sender_exit']}\n")
            f.write(f"  Output: {r['output_dir']}\n\n")
    
    print(f"\nTotal Tests: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {total - passed}")
    print(f"\nDetailed results saved to: {summary_file}")
    print(f"All test outputs in: {TEST_DIR}/")

if __name__ == "__main__":
    main()

