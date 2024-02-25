VERSION = '0.0.0.a1'
AUTHOR = 'baudneo'
SOCAT_COMMANDS = {
    # newer firmware IP is 35.196.85.236 (cm.gelighting.com) - older = 34.73.130.191 (cm-ge.xlink.cn)
    'WRITE_FILE': 'sudo socat -d -d -lf /dev/stdout -x -v 2> dump.txt ssl-l:23779,reuseaddr,fork,cert=certs/server.pem,verify=0 openssl:35.196.85.236:23779,verify=0',
    'STD_OUT': 'sudo socat -d -d -x -v ssl-l:23779,reuseaddr,fork,cert=certs/server.pem,verify=0 openssl:35.196.85.236:23779,verify=0',
}
DNS_REROUTE = {
    'newer': 'cm.gelighting.com',
    'older': 'cm-ge.xlink.cn',
}