#!/usr/bin/env python3
"""Reverse a Bitcoin TXID (convert between display and internal format)"""

def reverse_txid(txid_hex):
    """Reverse the byte order of a TXID hex string"""
    # Ensure even length
    if len(txid_hex) % 2 != 0:
        raise ValueError("TXID hex string must have even length")
    
    # Split into bytes and reverse
    bytes_list = [txid_hex[i:i+2] for i in range(0, len(txid_hex), 2)]
    reversed_bytes = bytes_list[::-1]
    
    # Join back together
    return ''.join(reversed_bytes)

if __name__ == "__main__":
    # The TXID to reverse
    txid = "9985d82954e10f2233a08905dc7b490eb444660c8759e324c7dfa3d28779d2d5"
    
    # Reverse it
    reversed_txid = reverse_txid(txid)
    
    print(f"Original TXID:  {txid}")
    print(f"Reversed TXID:  {reversed_txid}")
