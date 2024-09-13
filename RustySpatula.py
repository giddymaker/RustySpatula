#!/usr/bin/python

import hashlib
import itertools
import argparse
import sys

def parse_ntds_file(ntds_file):
    """Parse the NTDS.dit file and return dictionaries for LM hashes and NT hashes."""
    lm_hash_map = {}
    nt_hash_map = {}
    with open(ntds_file, 'r') as f:
        for line in f:
            try:
                parts = line.strip().split(':')
                if len(parts) >= 4:
                    username = parts[0]
                    lm_hash = parts[2]
                    nt_hash = parts[3]
                    if lm_hash:
                        if lm_hash in lm_hash_map:
                            if isinstance(lm_hash_map[lm_hash], str):
                                lm_hash_map[lm_hash] = [lm_hash_map[lm_hash], username]
                            else:
                                lm_hash_map[lm_hash].append(username)
                        else:
                            lm_hash_map[lm_hash] = username
                    if nt_hash:
                        if nt_hash in nt_hash_map:
                            if isinstance(nt_hash_map[nt_hash], str):
                                nt_hash_map[nt_hash] = [nt_hash_map[nt_hash], username]
                            else:
                                nt_hash_map[nt_hash].append(username)
                        else:
                            nt_hash_map[nt_hash] = username
            except Exception as e:
                print(f"Error processing line in NTDS.dit file: {line}. Error: {e}")
    return lm_hash_map, nt_hash_map

def split_lm_hashes(lm_hash_map):
    """Split 32-character LM hashes into two 16-character halves, excluding blank LM hashes."""
    for lm_hash, usernames in lm_hash_map.items():
        if lm_hash.lower() == "aad3b435b51404eeaad3b435b51404ee":
            #print(f"Skipping blank LM hash for {usernames}")
            continue
        if len(lm_hash) == 32:
            first_half = lm_hash[:16]
            second_half = lm_hash[16:]
            if isinstance(usernames, str):
                usernames = [usernames]
            for username in usernames:
                print(f"{first_half}\n{second_half}")
        else:
            print(f"Skipping LM hash for {usernames} (length {len(lm_hash)} is not 32 characters)")

def parse_potfile(potfile):
    """Parse the potfile and return a dictionary of LM hashes and their cleartext passwords."""
    hash_password_map = {}
    with open(potfile, 'r') as f:
        for line in f:
            try:
                hash_value, cleartext_password = line.strip().split(':', 1)
                hash_password_map[hash_value] = cleartext_password
            except Exception as e:
                print(f"Error processing line in potfile: {line}. Error: {e}")
    return hash_password_map

def reassemble_lm_potfile(potfile):
    """Reassemble the LM hash potfile into full hashes and passwords."""
    reassembled_entries = []
    try:
        with open(potfile, 'r') as file:
            potfile_lines = file.readlines()
    except FileNotFoundError:
        print(f"Error: File '{potfile}' not found.")
        sys.exit(1)

    for i in range(0, len(potfile_lines), 2):
        if i + 1 >= len(potfile_lines):
            print(f"Warning: Odd number of lines in potfile. Skipping incomplete pair.")
            break
        first_half_line = potfile_lines[i].strip()
        second_half_line = potfile_lines[i + 1].strip()
        hash1, pass1 = first_half_line.split(":")
        hash2, pass2 = second_half_line.split(":")
        full_hash = hash1 + hash2
        full_password = pass1 + pass2
        reassembled_entries.append((full_hash, full_password))

    return reassembled_entries

def calculate_nt_hash(password):
    """Calculate the NT hash for a given password."""
    nt_hash = hashlib.new('md4', password.encode('utf-16le')).hexdigest()
    return nt_hash.lower()

def generate_case_variations(password):
    """Generate all unique case variations of the given password."""
    variations = set(''.join(chars) for chars in itertools.product(*([char.lower(), char.upper()] for char in password)))
    return list(variations)

def match_nt_hashes(nt_hash_map, reassembled_lm_hash_password_map):
    """Match NT hashes with LM passwords' case variations."""
    found_matches = 0
    #print("NT Hash Map Contents:")
    #for nt_hash in nt_hash_map:
        #print(f"NT Hash: {nt_hash}")

    for lm_hash, full_password in reassembled_lm_hash_password_map.items():
        #print(f"Processing password: {full_password} (LM Hash: {lm_hash})")  # Debugging statement
        #print(f"Generating case variations for LM password: {full_password}")
        variations = generate_case_variations(full_password)  # Generate variations
        #print(f"Generated {len(variations)} variations for LM password '{full_password}': {variations[:5]}...")

        for variation in variations:
            hashed_variation = calculate_nt_hash(variation)
            #print(f"Trying variation: {variation} -> NT Hash: {hashed_variation}")  # Debugging statement
            if hashed_variation in nt_hash_map:  # Check if hash is in nt_hash_map
                print(f"{hashed_variation}:{variation}")
                found_matches += 1
                break  # Break once a match is found to avoid redundant checks
    if found_matches == 0:
        print("No matches found.")
    #else:
        #print(f"{found_matches} NT hash matches found.")


def main(args):
    if args.split_lm:
        lm_hash_map, _ = parse_ntds_file(args.ntds_file)  # Only load the NTDS file for LM hashes
        split_lm_hashes(lm_hash_map)
        return


    if args.lm2nt:
        _, nt_hash_map = parse_ntds_file(args.ntds_file)  # Potfile should contain NT hashes
        reassembled_entries = reassemble_lm_potfile(args.potfile)
        reassembled_lm_hash_password_map = {hash: password for hash, password in reassembled_entries}
        match_nt_hashes(nt_hash_map, reassembled_lm_hash_password_map)
        return

    lm_hash_map, nt_hash_map = parse_ntds_file(args.ntds_file)
    
    if args.lmuser_pw:
        reassembled_entries = reassemble_lm_potfile(args.potfile)
        lm_hash_password_map = {hash: password for hash, password in reassembled_entries}
        found = False
        for lm_hash, usernames in lm_hash_map.items():
            if lm_hash in lm_hash_password_map:
                password = lm_hash_password_map[lm_hash]
                if isinstance(usernames, str):
                    usernames = [usernames]
                for username in usernames:
                    print(f"{username}:::::{password}")
                    found = True
        if not found:
            print("No matches found for LM hashes.")

    elif args.ntuser_pw:

        hash_password_map = parse_potfile(args.potfile)
        found = False
        for nt_hash, usernames in nt_hash_map.items():
            if nt_hash in hash_password_map:
                password = hash_password_map[nt_hash]
                if isinstance(usernames, str):
                    usernames = [usernames]
                for username in usernames:
                    print(f"{username}:::::{password}")
                    found = True
        if not found:
            print("No matches found for NT hashes.")

    elif args.nthash_lmpw:
        reassembled_entries = reassemble_lm_potfile(args.potfile)
        reassembled_lm_hash_password_map = {hash: password for hash, password in reassembled_entries}
        found = False
        for lm_hash, usernames in lm_hash_map.items():
            if lm_hash in reassembled_lm_hash_password_map:
                password = reassembled_lm_hash_password_map[lm_hash]
                nt_hashes = [nt_hash for nt_hash, user in nt_hash_map.items() if user == usernames]
                for nt_hash in nt_hashes:
                    print(f"{nt_hash}:::::{password}")
                    found = True
        if not found:
            print("No matches found for NT hashes with LM passwords.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Match NTDS data with cracked passwords from a potfile.")
    parser.add_argument("ntds_file", help="Path to the NTDS.dit file.")
    parser.add_argument("potfile", nargs='?', help="Path to the potfile containing hashes and passwords (optional, required for --lmuser-pw, --ntuser-pw, --nthash-lmpw).")
    parser.add_argument("--lmuser-pw", action="store_true", help="Match LM hashes with passwords. Input the raw hashcat potfile, not the reassembled version.")
    parser.add_argument("--ntuser-pw", action="store_true", help="Match NT hashes with passwords.")
    parser.add_argument("--lm2nt", action="store_true", help="Find matching NT hashes from NTDS extract and LM potfile from hashcat")
    parser.add_argument("--nthash-lmpw", action="store_true", help="Match NT hashes with passwords from LM hashes. Input the raw hashcat potfile, not the reassembled version.")
    parser.add_argument("--fix-lm", action="store", help="Reassemble LM hashes from the potfile.", metavar="LM_POTFILE")
    parser.add_argument("--split-lm", action="store_true", help="Split 32-character LM hashes into two halves from NTDS.dit extract and output the result.")
    
    args = parser.parse_args()
    
    if args.fix_lm or args.split_lm:
        main(args)
    else:
        if not (args.lmuser_pw or args.ntuser_pw or args.nthash_lmpw or args.split_lm or args.lm2nt):
            print("Error: You must specify either --lmuser-pw, --ntuser-pw, --nthash-lmpw, --split-lm, or --lm2nt.")
            sys.exit(1)
        
        if (args.lmuser_pw and args.ntuser_pw) or (args.lmuser_pw and args.nthash_lmpw) or (args.lmuser_pw and args.lm2nt) or (args.ntuser_pw and args.nthash_lmpw) or (args.ntuser_pw and args.lm2nt) or (args.nthash_lmpw and args.lm2nt):
            print("Error: You cannot specify conflicting options.")
            sys.exit(1)
        
        if not args.potfile:
            print("Error: Potfile is required for --lmuser-pw, --ntuser-pw, --nthash-lmpw, or --lm2nt.")
            sys.exit(1)

        main(args)
