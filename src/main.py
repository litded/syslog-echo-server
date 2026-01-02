#!/usr/bin/env python3
import json
import re
import socketserver

HOST, PORT = "0.0.0.0", 514

FACILITIES = {
    0: "kern",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "cron",
    10: "authpriv",
    11: "ftp",
    16: "local0",
    17: "local1",
    18: "local2",
    19: "local3",
    20: "local4",
    21: "local5",
    22: "local6",
    23: "local7",
}
SEVERITIES = {
    0: "emerg",
    1: "alert",
    2: "crit",
    3: "err",
    4: "warning",
    5: "notice",
    6: "info",
    7: "debug",
}


def parse_syslog(data: str) -> dict:
    result = {"severity": None, "message": data}

    # PRI
    pri_match = re.match(r"<(\d+)>(.+)", data)
    if pri_match:
        pri = int(pri_match.group(1))
        result["severity"] = SEVERITIES.get(pri & 0x07, "unknown")
        data = pri_match.group(2)

    # BSD формат: "Mon DD HH:MM:SS hostname tag: message"
    bsd_match = re.match(r"\w{3}\s+\d+\s+[\d:]+\s+\S+\s+\w+:\s*(.+)", data)
    if bsd_match:
        result["message"] = bsd_match.group(1)

    return result


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = bytes.decode(self.request[0].strip())
        parsed = parse_syslog(data)

        log_entry = {"lvl": parsed["severity"], "msg": parsed["message"]}

        log_entry = {k: v for k, v in log_entry.items() if v}
        print(json.dumps(log_entry, ensure_ascii=False))


if __name__ == "__main__":
    print(f"Syslog сервер запущен на {HOST}:{PORT}")
    try:
        server = socketserver.UDPServer((HOST, PORT), SyslogUDPHandler)
        server.serve_forever(poll_interval=0.5)
    except PermissionError:
        print("Ошибка: требуются права root для порта 514")
    except Exception as e:
        print(f"Ошибка: {type(e).__name__}: {e}")
