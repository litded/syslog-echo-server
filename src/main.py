#!/usr/bin/env python3
import json
import re
import socketserver
from abc import ABC, abstractmethod
from datetime import datetime

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

# ============== ПАРСЕРЫ СОБЫТИЙ ==============


class EventParser(ABC):
    """Базовый класс для парсеров событий"""

    name = "generic"

    @abstractmethod
    def match(self, hostname: str, message: str) -> bool:
        """Проверка, подходит ли этот парсер"""
        pass

    @abstractmethod
    def parse(self, message: str) -> tuple[str, dict]:
        """Парсинг сообщения, возвращает (event_type, event_data)"""
        pass


class MikroTikParser(EventParser):
    """Парсер событий MikroTik RouterOS"""

    name = "mikrotik"

    patterns = {
        r"event (up|down) \[ (.+?) \]": "vpn_status",
        r"(aiot|defconf) (assigned|deassigned) ([\d.]+) for ([A-F0-9:]+) ?(.*)": "dhcp",
        r"route (.+?) changed by (.+)": "route_change",
        r"device changed by (.+)": "device_change",
        r"wireguard peer entry changed by (.+)": "wireguard_peer",
        r"traffic generator packet template (added|removed) by (.+)": "traffic_gen",
        r"user (.+?) logged (in|out) from ([\d.]+) via (.+)": "auth",
        r"(.+?): (connected|authenticated|connecting|initializing|disabled|terminating)": "pppoe",
        r"wg-(.+?): \[peer\d+\] .+: Handshake .+ retrying": "wireguard_handshake",
    }

    def match(self, hostname: str, message: str) -> bool:
        # MikroTik обычно шлёт INFO/WARNING/ERROR и специфичные паттерны
        indicators = [
            "netwatch:",
            "wireguard",
            "aiot ",
            "defconf ",
            "event up",
            "event down",
        ]
        return any(ind in message for ind in indicators)

    def parse(self, message: str) -> tuple[str, dict]:
        for pattern, etype in self.patterns.items():
            match = re.search(pattern, message)
            if match:
                groups = match.groups()
                event_data = self._extract_data(etype, groups)
                return etype, event_data
        return "unknown", {}

    def _extract_data(self, etype: str, groups: tuple) -> dict:
        if etype == "vpn_status":
            return {"state": groups[0], "interface": groups[1]}
        elif etype == "dhcp":
            return {
                "pool": groups[0],
                "action": groups[1],
                "ip": groups[2],
                "mac": groups[3],
                "hostname": groups[4].strip() or None,
            }
        elif etype == "route_change":
            return {"route": groups[0], "source": groups[1]}
        elif etype == "auth":
            return {
                "user": groups[0],
                "action": f"logged_{groups[1]}",
                "source_ip": groups[2],
                "method": groups[3],
            }
        elif etype == "pppoe":
            return {"interface": groups[0], "state": groups[1]}
        elif etype == "wireguard_handshake":
            return {"interface": f"wg-{groups[0]}", "issue": "handshake_retry"}
        elif etype in ("device_change", "wireguard_peer"):
            return {"source": groups[0]}
        elif etype == "traffic_gen":
            return {"action": groups[0], "source": groups[1]}
        return {}


class LinuxParser(EventParser):
    """Парсер событий Linux (sshd, sudo, systemd и т.д.)"""

    name = "linux"

    patterns = {
        r"sshd\[\d+\]: Accepted (\w+) for (\w+) from ([\d.]+)": "ssh_login",
        r"sshd\[\d+\]: Failed password for (\w+) from ([\d.]+)": "ssh_failed",
        r"sudo:\s+(\w+) : .+ COMMAND=(.+)": "sudo_command",
        r"systemd\[\d+\]: (Started|Stopped|Starting|Stopping) (.+)": "systemd_service",
        r"kernel: \[[\d.]+\] (.+)": "kernel",
    }

    def match(self, hostname: str, message: str) -> bool:
        indicators = ["sshd[", "sudo:", "systemd[", "kernel:"]
        return any(ind in message for ind in indicators)

    def parse(self, message: str) -> tuple[str, dict]:
        for pattern, etype in self.patterns.items():
            match = re.search(pattern, message)
            if match:
                groups = match.groups()
                if etype == "ssh_login":
                    return etype, {
                        "method": groups[0],
                        "user": groups[1],
                        "ip": groups[2],
                    }
                elif etype == "ssh_failed":
                    return etype, {"user": groups[0], "ip": groups[1]}
                elif etype == "sudo_command":
                    return etype, {"user": groups[0], "command": groups[1]}
                elif etype == "systemd_service":
                    return etype, {"action": groups[0].lower(), "service": groups[1]}
                elif etype == "kernel":
                    return etype, {"info": groups[0]}
        return "unknown", {}


class GenericParser(EventParser):
    """Fallback парсер для неизвестных источников"""

    name = "generic"

    def match(self, hostname: str, message: str) -> bool:
        return True  # Всегда совпадает как fallback

    def parse(self, message: str) -> tuple[str, dict]:
        return "unknown", {}


# ============== ОСНОВНОЙ КОД ==============

# Регистрация парсеров (порядок важен - проверяются по очереди)
PARSERS = [
    MikroTikParser(),
    LinuxParser(),
    GenericParser(),  # Всегда последний
]


def parse_syslog(data: str) -> dict:
    """Парсинг базового syslog формата"""
    result = {
        "facility": None,
        "severity": None,
        "timestamp": None,
        "hostname": None,
        "level": None,
        "message": data,
    }

    # PRI
    pri_match = re.match(r"<(\d+)>(.+)", data)
    if pri_match:
        pri = int(pri_match.group(1))
        result["facility"] = {
            "code": pri >> 3,
            "name": FACILITIES.get(pri >> 3, "unknown"),
        }
        result["severity"] = {
            "code": pri & 0x07,
            "name": SEVERITIES.get(pri & 0x07, "unknown"),
        }
        data = pri_match.group(2)

    # BSD формат: "Mon DD HH:MM:SS hostname tag: message"
    bsd_match = re.match(r"(\w{3}\s+\d+\s+[\d:]+)\s+(\S+)\s+(\w+):\s*(.+)", data)
    if bsd_match:
        result["timestamp"] = bsd_match.group(1)
        result["hostname"] = bsd_match.group(2)
        result["level"] = bsd_match.group(3)
        result["message"] = bsd_match.group(4)

    return result


def detect_and_parse_event(hostname: str, message: str) -> tuple[str, str, dict]:
    """Определение источника и парсинг события"""
    for parser in PARSERS:
        if parser.match(hostname, message):
            event_type, event_data = parser.parse(message)
            return parser.name, event_type, event_data
    return "generic", "unknown", {}


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = bytes.decode(self.request[0].strip())
        client_ip = self.client_address[0]
        client_port = self.client_address[1]

        parsed = parse_syslog(data)
        source_type, event_type, event_data = detect_and_parse_event(
            parsed["hostname"], parsed["message"]
        )

        log_entry = {
            "received_at": datetime.now().isoformat(),
            "source": {
                "ip": client_ip,
                "port": client_port,
                "hostname": parsed["hostname"],
                "type": source_type,  # mikrotik, linux, generic
            },
            "syslog": {
                "facility": parsed["facility"],
                "severity": parsed["severity"],
                "level": parsed["level"],
                "original_timestamp": parsed["timestamp"],
            },
            "event": {"type": event_type, "data": event_data},
            "message": parsed["message"],
            "raw": data,
        }

        print(json.dumps(log_entry, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    print(f"Universal Syslog сервер запущен на {HOST}:{PORT}")
    print(f"Загружены парсеры: {[p.name for p in PARSERS]}")
    try:
        server = socketserver.UDPServer((HOST, PORT), SyslogUDPHandler)
        server.serve_forever(poll_interval=0.5)
    except PermissionError:
        print("Ошибка: требуются права root для порта 514")
    except Exception as e:
        print(f"Ошибка: {type(e).__name__}: {e}")
