# RustySpatula
usage: ./RustySpatula.py [-h] [--lmuser-pw] [--ntuser-pw] [--nthash-lmpw] [--fix-lm LM_POTFILE] [--split-lm LM_POTFILE] ntds_file potfile

## NTDS and NTLM hash manipulator

I'll be completely transparent: I created this code with help from ChatGPT.
I am not a proficient python coder. I am in offensive security and I need tools
sooner than I need to learn how to code by myself. This is another reason why I chose
the license I did and put this publicly on Github for everyone to use. I believe in
sharing information like this and sincerely hope it helps you on your journey.
Credit where credit is due.

Takes outputs from secretsdump.py for the NTDS extract (ntds_file) input.
Tested with full output containing kerberos keys, etc and it seems to work fine.
Takes potfile outputs as they come from hashcat. Shouldn't need any extra formatting.

## Flags' Explanations:

`--lmuser-pw`
Matches usernames with passwords from LM potfile
(takes NTDS extract and raw LM hashcat potfile as input since reassembly is a feature)

`--ntuser-pw`
Matches usernames with passwords from NT potfile
(takes NTDS extract and raw NT hashcat potfile as input)

`--lm2nt`
Using cracked LM hashes' passwords, generate all possible combinations of possible passwords
(since LM is case insensitive and NT is case sensitive), hash combinations into NT hashes, and
check for matches. Stops looking upon match.

`--nthash-lmpw`
Matches NT hash with LM passwords. This feature needs more work to reach the final vision
of being able to enhance the cracked database [potfile] since LM is not case sensitive.
It’s more for cracking enthusiasts who want to crack everything. Like --lmuser-pw, it takes NTDS extract
and raw LM hashcat potfile as input since reassembly is a feature)

`--fix-lm`
Reassemble LM potfiles to output [the whole 32 char hash][:][whole password]
(assuming the two parts to the hash and pass are consecutive entries)

`--split-lm`
Split LM hashes for hashcat with the NTDS NTLM extract as input. (32 char hexadecimal > 16)

## Positional Arguments:
```
  ntds_filePath        to the NTDS.dit file.
  potfile              Path to the potfile containing hashes and passwords (optional, required for --lmuser-pw, --ntuser-pw, --nthash-lmpw).
```
## Options:
```
  -h, --help           show this help message and exit
  --lmuser-pw          Match LM hashes with passwords.
  --ntuser-pw          Match NT hashes with passwords.
  --lm2nt              Find matching NT hashes from NTDS extract and LM potfile from hashcat
  --nthash-lmpw        Match NT hashes with passwords from LM hashes. Input the raw hashcat potfile, not the reassembled version
  --fix-lm LM_POTFILE  Reassemble LM hashes from the potfile.
  --split-lm           Split 32-character LM hashes into two halves from NTDS.dit extract and output the result.
```
I'm expecting to be very slow with developing scripts, but if you have any feedback or feature requests do let me know.
