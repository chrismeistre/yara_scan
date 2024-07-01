# yara_scan
Scan an exe file with YARA rule files

This has been built to make use of the YARA rule files from:
https://github.com/elastic/protections-artifacts

Usage:

```
usage: yara_scan.py [-h] [-y YARAFILE] [-d DIRECTORY] [-r] target_file

Scan a file with YARA rules.

positional arguments:
  target_file           Path to the target executable file

options:
  -h, --help            show this help message and exit
  -y YARAFILE, --yarafile YARAFILE
                        Path to a single YARA rule file
  -d DIRECTORY, --directory DIRECTORY
                        Path to a directory of YARA rule files
  -r, --recursive       Recursively search for YARA files in the specified directory
```

Example output with no detections:

```
[DEBUG] Found 569 YARA rule files in directory: /Tools/protections-artifacts
[DEBUG] Successfully compiled YARA rules
[DEBUG] Target file set to: /Payloads/AVBypass/x64/Release/AVBypass.exe
[DEBUG] Successfully read the target file
[DEBUG] Successfully scanned the file with YARA rules
[DEBUG] No matches found
```

Example output with detections:
```
[DEBUG] Rules directory set to: /Tools/protections-artifacts
[DEBUG] Found 569 YARA rule files
[DEBUG] Successfully compiled YARA rules
[DEBUG] Target file set to: /Payloads/demon.x64.exe
[DEBUG] Successfully read the target file
[DEBUG] Successfully scanned the file with YARA rules
[DEBUG] Matches found: 4
Rule: Windows_Generic_Threat_3f390999
Tags: []
Meta: {'author': 'Elastic Security', 'id': '3f390999-601f-464e-8982-09553adee303', 'fingerprint': 'ccfd5fb305ea48d66f299311c5332587355258bdeeb25cb90c450e8e96df3052', 'creation_date': '2024-03-05', 'last_modified': '2024-06-12', 'threat_name': 'Windows.Generic.Threat', 'reference_sample': '1b6fc4eaef3515058f85551e7e5dffb68b9a0550cd7f9ebcbac158dac9ababf1', 'severity': 50, 'arch_context': 'x86', 'scan_context': 'file, memory', 'license': 'Elastic License v2', 'os': 'windows'}
Strings: [(1073, '$a1', b'\x10H\x89\xd9H\x8bY\x10\xffa\x08\x0f\x1f@\x00I\x89\xcb\xc3I\x89\xcaA\x8bC\x08A\xff#\xc3\x90H\xc1\xe1\x041\xc0\x81\xe1\xf0\x0f\x00\x00I\x01\xc8L\x8d\x0c\x02N\x8d\x14\x001\xc9E\x8a\x1c\nH')]
==================================================
Rule: Windows_Trojan_Generic_9997489c
Tags: []
Meta: {'author': 'Elastic Security', 'id': '9997489c-4e22-4df1-90cb-dd098ca26505', 'fingerprint': '4c872be4e5eaf46c92e6f7d62ed0801992c36fee04ada1a1a3039890e2893d8c', 'creation_date': '2024-01-31', 'last_modified': '2024-02-08', 'threat_name': 'Windows.Trojan.Generic', 'severity': 100, 'arch_context': 'x86', 'scan_context': 'file, memory', 'license': 'Elastic License v2', 'os': 'windows'}
Strings: [(28459, '$ldrload_dll', b'CjE\x9e'), (30483, '$loadlibraryw', b'\xf1/\x07\xb7'), (29327, '$ntallocatevirtualmemory', b'\xec\xb8\x83\xf7'), (29761, '$ntcreatethreadex', b'\xb0\xcf\x18\xaf'), (29265, '$ntqueryinformationprocess', b'\xc2]\xdc\x8c'), (29854, '$ntprotectvirtualmemory', b'\x88(\xe9P'), (29978, '$ntreadvirtualmemory', b'\x03\x81(\xa3'), (29916, '$ntwritevirtualmemory', b'\x92\x01\x17\xc3'), (28924, '$rtladdvectoredexceptionhandler', b'\x89l\xf0-'), (28490, '$rtlallocateheap', b'ZL\xe9;'), (28800, '$rtlqueueworkitem', b'\x8e\x02\x92\xae'), (30552, '$virtualprotect', b'\rPW\xe8')]
==================================================
Rule: Windows_Trojan_Havoc_88053562
Tags: []
Meta: {'author': 'Elastic Security', 'id': '88053562-ae19-44fe-8aaf-d6b9687d6b80', 'fingerprint': '818011b7972ab71cbfe07ec2266f504ba0ec7df30136e414d15366aa68ad5b8a', 'creation_date': '2024-01-04', 'last_modified': '2024-01-12', 'threat_name': 'Windows.Trojan.Havoc', 'reference_sample': '2f0b59f8220edd0d34fba92905faf0b51aead95d53be8b5f022eed7e21bdb4af', 'severity': 100, 'arch_context': 'x86', 'scan_context': 'file, memory', 'license': 'Elastic License v2', 'os': 'windows'}
Strings: [(63836, '$a', b'H\x81\xec\xf8\x04\x00\x00H\x8d|$xD\x89\x8c$X\x05\x00\x00H\x8b\xac$`\x05\x00\x00L\x8dl$x\xf3\xab\xb9Y\x00\x00\x00H\xc7D$p\x00\x00\x00\x00\xc7D$xh\x00\x00\x00\xc7\x84$\xb4\x00\x00\x00')]
==================================================
Rule: Windows_Trojan_Havoc_ffecc8af
Tags: []
Meta: {'author': 'Elastic Security', 'id': 'ffecc8af-4a64-4252-b7ca-3316d27c3942', 'fingerprint': 'd09b0519d518b741cec7f6e42efaa657410edd36d027f54e515be510b33fa821', 'creation_date': '2024-04-29', 'last_modified': '2024-05-08', 'threat_name': 'Windows.Trojan.Havoc', 'reference_sample': '495d323651c252e38814b77b9c6c913b9489e769252ac8bbaf8432f15e0efe44', 'severity': 100, 'arch_context': 'x86', 'scan_context': 'file, memory', 'license': 'Elastic License v2', 'os': 'windows'}
Strings: [(97280, '$commands_table', b'\x0b\x00\x00\x00\x00\x00\x00\x00 d\x00@\x01\x00\x00\x00d\x00\x00\x00\x00\x00\x00\x00\x004\x00@\x01\x00\x00\x00\x15\x00\x00\x00\x00\x00\x00\x00pJ\x00@\x01\x00\x00\x00\x10\x10\x00\x00\x00\x00\x00\x000Z\x00@\x01\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x80a\x00@\x01\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00`=\x00@\x01\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00pI\x00@\x01\x00\x00\x00\x01 \x00\x00\x00\x00\x00\x00\x800\x00@\x01\x00\x00\x00\x03 \x00\x00\x00\x00\x00\x00p2\x00@\x01\x00\x00\x00\xc4\t\x00\x00\x00\x00\x00\x0004\x00@\x01\x00\x00\x00\xce\t\x00\x00\x00\x00\x00\x00\xa0c\x00@\x01\x00\x00\x00\xd8\t\x00\x00\x00\x00\x00\x00\x10X\x00@\x01\x00\x00\x004\x08\x00\x00\x00\x00\x00\x00\x90P\x00@\x01\x00\x00\x00\x16\x00\x00\x00\x00\x00\x00\x000F\x00@\x01\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00pG\x00@\x01\x00\x00\x00\x1a\x00\x00\x00\x00\x00\x00\x00@i\x00@\x01\x00\x00\x00(\x00\x00\x00\x00\x00\x00\x00\x10j\x00@\x01\x00\x00\x00\xe2\t\x00\x00\x00\x00\x00\x00Pq\x00@\x01\x00\x00\x00\xec\t\x00\x00\x00\x00\x00\x00\x90d\x00@\x01\x00\x00\x00\xf6\t\x00\x00\x00\x00\x00\x00`K\x00@\x01\x00\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\xf0O\x00@\x01\x00\x00\x00\\\x00\x00\x00\x00\x00\x00\x00'), (28459, '$hash_ldrloaddll', b'CjE\x9e'), (78554, '$hash_ntaddbootentry', b'v\xc7\xfc\x8c'), (29327, '$hash_ntallocatevirtualmemory', b'\xec\xb8\x83\xf7'), (30009, '$hash_ntfreevirtualmemory', b'\t\xc6\x02('), (30040, '$hash_ntunmapviewofsection', b'\xcd\x12\xa4j'), (29916, '$hash_ntwritevirtualmemory', b'\x92\x01\x17\xc3'), (29141, '$hash_ntsetinformationvirtualmemory', b'9\xc2j\x94'), (30071, '$hash_ntqueryvirtualmemory', b']\xe8\xc0\x10'), (29792, '$hash_ntopenprocesstoken', b'\x99\xca\r5'), (29420, '$hash_ntopenthreadtoken', b'\xd2G3\x80')]
==================================================
```