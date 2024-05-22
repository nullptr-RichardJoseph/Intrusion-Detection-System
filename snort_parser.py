import re

class SnortRule:
    def __init__(self, action, proto, src_ip, src_port, direction, dst_ip, dst_port, msg, sid):
        self.action = action
        self.proto = proto
        self.src_ip = src_ip
        self.src_port = src_port
        self.direction = direction
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.msg = msg
        self.sid = sid

    def __repr__(self):
        return f"SnortRule(action={self.action}, proto={self.proto}, src_ip={self.src_ip}, src_port={self.src_port}, direction={self.direction}, dst_ip={self.dst_ip}, dst_port={self.dst_port}, msg={self.msg}, sid={self.sid})"

def parse_snort_rules(file_path):
    rules = []
    rule_pattern = re.compile(r'(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+\((.+?)\)')
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith('#') or not line.strip():
                continue
            match = rule_pattern.match(line)
            if match:
                action, proto, src_ip, src_port, direction, dst_ip, dst_port, options = match.groups()
                msg = re.search(r'msg:"([^"]+)"', options).group(1) if 'msg:' in options else ''
                sid = re.search(r'sid:(\d+);', options).group(1) if 'sid:' in options else ''
                rule = SnortRule(action, proto, src_ip, src_port, direction, dst_ip, dst_port, msg, sid)
                rules.append(rule)
    return rules
