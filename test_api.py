#!/usr/bin/env python
"""Test script to verify PCAP upload and analysis workflow."""

import requests
import json
import time
import sys
from pathlib import Path

SERVER_URL = "http://localhost:5000"
TEST_PCAP = r"c:\Users\prith\Desktop\BENFET_fixed\datasets\real_world\dns_traffic.pcap"

def test_upload():
    """Test PCAP upload endpoint."""
    print("\n[TEST] 1. Testing PCAP Upload...")
    
    if not Path(TEST_PCAP).exists():
        print(f"❌ Test PCAP not found: {TEST_PCAP}")
        return None
    
    with open(TEST_PCAP, 'rb') as f:
        files = {'file': f}
        try:
            res = requests.post(f"{SERVER_URL}/api/upload", files=files, timeout=30)
            data = res.json()
            
            if res.status_code == 200:
                print(f"✅ Upload successful: {data['analysis_id']}")
                return data['analysis_id']
            else:
                print(f"❌ Upload failed: {data.get('error')}")
                return None
        except Exception as e:
            print(f"❌ Upload error: {str(e)}")
            return None

def test_analyze(analysis_id):
    """Test analysis endpoint."""
    print(f"\n[TEST] 2. Testing Analysis (ID: {analysis_id})...")
    
    try:
        res = requests.get(f"{SERVER_URL}/api/analyze/{analysis_id}", timeout=120)
        data = res.json()
        
        if res.status_code == 200:
            print(f"✅ Analysis successful!")
            print(f"   - Status: {data.get('status')}")
            print(f"   - Packets: {data.get('metadata', {}).get('total_packets')}")
            print(f"   - Flows: {data.get('metadata', {}).get('total_flows')}")
            print(f"   - Features extracted: {data.get('total_flows', 0)}")
            return True
        else:
            print(f"❌ Analysis failed: {data.get('error')}")
            if 'traceback' in data:
                print(f"   Traceback: {data['traceback'][:200]}...")
            return False
    except requests.exceptions.Timeout:
        print("❌ Analysis timeout (took longer than 120 seconds)")
        return False
    except Exception as e:
        print(f"❌ Analysis error: {str(e)}")
        return False

def test_predict(analysis_id):
    """Test prediction endpoint."""
    print(f"\n[TEST] 3. Testing Prediction (ID: {analysis_id})...")
    
    try:
        res = requests.get(f"{SERVER_URL}/api/predict/{analysis_id}", timeout=180)
        data = res.json()
        
        if res.status_code == 200:
            print(f"✅ Prediction successful!")
            print(f"   - Status: {data.get('status')}")
            print(f"   - Predictions: {len(data.get('predictions', []))} results")
            print(f"   - Explanations: {len(data.get('explanations', []))} results")
            return True
        else:
            print(f"❌ Prediction failed: {data.get('error')}")
            if 'traceback' in data:
                print(f"   Traceback: {data['traceback'][:200]}...")
            return False
    except requests.exceptions.Timeout:
        print("❌ Prediction timeout (took longer than 180 seconds)")
        return False
    except Exception as e:
        print(f"❌ Prediction error: {str(e)}")
        return False

def main():
    print("=" * 60)
    print("BENFET API Test Suite")
    print("=" * 60)
    
    # Test upload
    analysis_id = test_upload()
    if not analysis_id:
        print("\n❌ Upload test failed. Stopping.")
        return
    
    # Wait a moment
    time.sleep(1)
    
    # Test analysis
    if not test_analyze(analysis_id):
        print("\n❌ Analysis test failed. Stopping.")
        return
    
    # Wait a moment
    time.sleep(1)
    
    # Test prediction (only if a model exists)
    test_predict(analysis_id)
    
    print("\n" + "=" * 60)
    print("All tests completed!")
    print("=" * 60)

if __name__ == "__main__":
    main()
