"""unittest helpers"""

ACL_IOS = "ip access-list extended "
ACL_NAME_IOS = "ip access-list extended A"
ACL_NAME_RP_IOS = "ip access-list extended A\nremark text\npermit ip any any"
ACL_RP_IOS = "ip access-list extended \nremark text\npermit ip any any"

ACL_CNX = "ip access-list "
ACL_NAME_CNX = "ip access-list A"
ACL_NAME_RP_CNX = "ip access-list A\nremark text\npermit ip any any"
ACL_RP_CNX = "ip access-list \nremark text\npermit ip any any"

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
