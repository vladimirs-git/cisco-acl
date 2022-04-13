"""unittest helpers"""

ACL = "ip access-list extended "
ACL_A = "ip access-list extended A"
ACL_A_REMARK_PERMIT_IP = "ip access-list extended A\nremark text\npermit ip any any"
ACL_REMARK_PERMIT_IP = "ip access-list extended \nremark text\npermit ip any any"

DENY_ICMP = "deny icmp any any"
DENY_IP = "deny ip any any"
DENY_IP_1 = "1 deny ip any any"
DENY_IP_2 = "2 deny ip any any"

PERMIT_ADDR_GR = "permit ip addrgroup NAME any"
PERMIT_ICMP = "permit icmp any any"
PERMIT_IP = "permit ip any any"
PERMIT_IP_1 = "1 permit ip any any"
PERMIT_IP_2 = "2 permit ip any any"
PERMIT_OBJ_GR = "permit ip object-group NAME any"

REMARK = "remark text"
REMARK_1 = "1 remark text"
REMARK_2 = "2 remark text"
REMARK_3 = "3 remark text"

ETH1 = "interface Ethernet1"
ETH2 = "interface Ethernet2"
