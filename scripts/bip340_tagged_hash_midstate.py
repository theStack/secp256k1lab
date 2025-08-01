#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "sha256>=1.0",
# ]
# ///
"""Tool to calculate the midstate for a BIP-340 tagged hash."""
import argparse
from sha256 import sha256


def tagged_hash_midstate(tag):
    # see https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
    # "This proposal suggests to include the tag by prefixing the hashed data with SHA256(tag) || SHA256(tag)"
    prefix = sha256(tag.encode('utf-8')).digest() * 2
    state_hash, state_count = sha256(prefix).state
    assert state_count == 64
    return state_hash


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('tag', help='Tag for which the midstate should be calculated')
    args = parser.parse_args()

    midstate_hash = tagged_hash_midstate(args.tag)
    print(f'Midstate for BIP-340 tagged hash "{args.tag}":\n{midstate_hash.hex()}')
    print("Split into 4-byte chunks:")
    for i in range(8):
        chunk = midstate_hash[4*i:4*(i+1)]
        print(f"- s[{i}] = 0x{chunk.hex()}")


if __name__ == '__main__':
    main()
