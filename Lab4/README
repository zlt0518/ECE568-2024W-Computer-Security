Part 1:\
1.dig utoronto.ca A \
check the ipv4 address in the answer section \
2.dig utoronto.ca NS \
check the name of the name server in the answer section and the it corresponding ipv4 address from the additional section \
3.dig utoronto.ca MX \
dig utoronto-ca.mail.protection.outlook.com A \
check the name of the mail server in the answer section and we perform another dig to the mail server name( utoronto-ca.mail.protection.outlook.com) and get the name and ipv4 addresses of the mail server \
4. dig @127.0.0.1 -p 9929 utoronto.ca (9929: listen port in BIND server) \
dig to the local BIND server with our listen port 9929 and repeat the above queries 1-3

Part 2:
python comannd：\
python2 dnsproxy_starter.py --port 3112 --dns_port 9929 \
dig command: \
dig utoronto.ca @127.0.0.1 -p 3112 \
dig utoronto.ca @127.0.0.1 -p 9929 \
We developed a DNS proxy server designed to intercept DNS requests from a DNS client(port 3112) and forward them to a BIND DNS server(port 9929) through UDP communication. After receiving the DNS response from the BIND server, the proxy sends it back to the DNS client(port 3112) without any modification. We check the correctness of the code by using the dig command to the proxy server(port 9929) and DNS client(port 3112) and comparing the results.

Part 3: \
python command：\
python2 dnsproxy_starter.py --port 3112 --dns_port 9929 --spoof_response \
dig command: \
dig example.com @127.0.0.1 -p 3112 \
This part is based on part 2, as after we received the DNS response from the BIND server, in the DNS info, the address field is set to 1.2.3.4, ancount field is set to 1, name servers field is set to ns.dnslabattacker.net, nscount field is set to the original value. The additional field is also set to 0. We then forward the modified DNS info back to the DNS client(port 3112)

Part4: \
In this part, we are performing a DNS cache poisoning attack. We first query the BIND server for a name of 10_random_digits+example.com. As this domain cache does not exist in the BIND server, the BIND server will request DNS information about example.com through example.com’s name server. To emulate the responses from example.com, we spoofed the BIND server with fake DNS replies (through the form of DNS reply flooding) along a random transaction number. We emulated the spoofed name server to be ns.dnslabattacker.net and the spoofed ip address to be 11.22.33.44. After sending the packages (that contain spoofed ns and ip) to the BIND server, we check its response messages by validating the answer section, and the name server section. If the DNS cache is spoofed, we stop the flooding operation, ending the Kaminsky attack.
