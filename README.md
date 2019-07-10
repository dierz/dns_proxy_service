# dns_proxy_service
DNS Proxy Service
Requirements:
1) You need to be root
2) gcc 4.8.5 or higher installed on your system
Guide:
1) Upload main.c and proxy_dns.sh file to the directory /root/
2) Run `ln -s /root/proxy_dns.sh /usr/bin/proxy-dns.sh` with root rights/
3) Run `sudo sed -i -e 's/\r$//' /root/proxy_dns.sh`
3) Upload proxy-dns.service to the directory /etc/systemd/system/
4) Run `gcc /root/main.c -std=c99 -o /root/main` with root rights.
5) Check '/root/main', '/root/proxy_dns.sh' have 755 rigths and '/etc/systemd/system/proxy-dns.service' have 644.
6) Run 'systemctl enable proxy-dns' with root rights.
7) Run 'systemctl start proxy-dns' with root rights.

If you don't need service, simply use `proxy-dns.sh` with commands start/stop/status 
