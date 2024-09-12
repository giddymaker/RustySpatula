# RustySpatula
usage: ./RustySpatula.py [-h] [--lmuser-pw] [--ntuser-pw] [--nthash-lmpw] [--fix-lm LM_POTFILE] [--split-lm LM_POTFILE] ntds_file potfile

NTDS and NTLM hash manipulator

Takes outputs from secretsdump.py for the NTDS extract (ntds_file) input.
Tested with full output containing kerberos keys, etc and it seems to work fine.
Takes potfile outputs as they come from hashcat. Shouldn't need any extra formatting.

--split-lm
Split LM hashes for hashcat with the NTDS NTLM extract as input. (32 char hexadecimal > 16)
--fix-lm
Reassemble LM potfiles to output [the whole 32 char hash][:][whole password]
(assuming the two parts to the hash and pass are consecutive entries)
--lmuser-pw
Matches usernames with passwords from LM potfile
(takes NTDS extract and raw LM hashcat potfile as input since reassembly is a feature)
--ntuser-pw
Matches usernames with passwords from NT potfile
(takes NTDS extract and raw NT hashcat potfile as input)
--nthash-lmpw
Matches NT hash with LM passwords. This feature needs more work to reach the final vision
of being able to enhance the cracked database [potfile] since LM is not case sensitive.
It’s more for cracking enthusiasts who want to crack everything. Like --lmuser-pw, it takes NTDS extract
and raw LM hashcat potfile as input since reassembly is a feature)

positional arguments:
  ntds_file            Path to the NTDS.dit file.
  potfile              Path to the potfile containing hashes and passwords (optional, required for --lmuser-pw, --ntuser-pw, --nthash-lmpw).

options:
  -h, --help           show this help message and exit
  --lmuser-pw          Match LM hashes with passwords.
  --ntuser-pw          Match NT hashes with passwords.
  --nthash-lmpw        Match NT hashes with passwords from LM hashes. Input the raw hashcat potfile, not the reassembled version
  --fix-lm LM_POTFILE  Reassemble LM hashes from the potfile.
  --split-lm           Split 32-character LM hashes into two halves from NTDS.dit extract and output the result.

I'm expecting to be very slow with developing scripts, but if you have any feedback or feature requests do let me know.
