"""Remark - comments in ACL"""

from cisco_acl import Remark

remark = Remark(line="10 remark text", note="description")

assert remark.line == "10 remark text"
assert remark.sequence == 10
assert remark.action == "remark"
assert remark.text == "text"
assert remark.note == "description"
