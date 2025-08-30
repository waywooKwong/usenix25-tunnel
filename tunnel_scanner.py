from scapy.all import *
import time
import threading
import csv
import argparse
import random
import ipaddress

# === 用户配置 ===
SCANNER_IP = "192.168.234.241"  # 替换为你的公网 IP
INTERFACE = "eth0"  # 替换为你的网卡
DELAY_BETWEEN_PROBES = 0.01
TARGET_FILE = "targets.txt"
RESULT_FILE = "results.csv"
SPOOF_PREFIX = "100.200"  # Spoofing 扫描使用的伪造地址前缀
# =================

# === 记录回传 IP ===
detected_ips = set()
lock = threading.Lock()


def handle_packet(pkt):
    """监听返回的封包，记录回传 IP"""
    if IP in pkt and pkt[IP].dst == SCANNER_IP:
        src = pkt[IP].src
        with lock:
            if src not in detected_ips:
                print(f"[✓] Forwarded packet from: {src}")
                detected_ips.add(src)


def start_sniffer():
    sniff(filter=f"ip dst {SCANNER_IP}", iface=INTERFACE, prn=handle_packet, store=0)


# === 计算不同扫描模式的源 IP 地址 ===
def get_inner_src_ip(target_ip, scan_mode):
    ip_parts = target_ip.split(".")

    if scan_mode == "standard":
        return target_ip  # 标准扫描：使用目标 IP 作为源地址

    elif scan_mode == "subnet-spoof":
        # 修改最后一个八位数，保持在同一 /24 子网
        spoofed_last_octet = str((int(ip_parts[3]) + 1) % 255)
        return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{spoofed_last_octet}"

    elif scan_mode == "spoof":
        # 完全伪造源 IP（100.200.X.Y）
        return f"{SPOOF_PREFIX}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    elif scan_mode == "6to4":
        # 计算 IPv4-mapped IPv6 地址 ::ffff:a.b.c.d
        ipv6_mapped = ipaddress.IPv6Address(f"::ffff:{target_ip}")
        return str(ipv6_mapped)

    else:
        raise ValueError(f"未知的扫描模式: {scan_mode}")


# === 发送探测包 ===
def send_probe(target_ip, scan_mode, tunnel_type):
    inner_src_ip = get_inner_src_ip(target_ip, scan_mode)

    if tunnel_type == "ipip":
        outer = IP(src=SCANNER_IP, dst=target_ip, proto=4)
        inner = IP(src=inner_src_ip, dst=SCANNER_IP)
        pkt = outer / inner

    elif tunnel_type == "gre":
        outer = IP(src=SCANNER_IP, dst=target_ip, proto=47)
        gre = GRE()
        inner = IP(src=inner_src_ip, dst=SCANNER_IP)
        pkt = outer / gre / inner

    elif tunnel_type == "6in4":
        outer = IPv6(src=SCANNER_IP, dst=target_ip, nh=41)
        inner = IPv6(src=inner_src_ip, dst=SCANNER_IP)
        pkt = outer / inner

    elif tunnel_type == "4in6":
        outer = IP(src=SCANNER_IP, dst=target_ip, proto=41)
        inner = IPv6(src=inner_src_ip, dst=SCANNER_IP)
        pkt = outer / inner

    else:
        raise ValueError(f"未知的隧道类型: {tunnel_type}")

    send(pkt, iface=INTERFACE, verbose=False)


# === 读取目标并扫描 ===
def scan_targets(scan_mode, tunnel_type):
    with open(TARGET_FILE, "r") as f:
        targets = [line.strip() for line in f if line.strip()]
    print(f"[+] Loaded {len(targets)} target IPs.")

    for ip in targets:
        try:
            print(f"[>] Probing {ip} via {tunnel_type.upper()} ({scan_mode})...")
            send_probe(ip, scan_mode, tunnel_type)
            time.sleep(DELAY_BETWEEN_PROBES)
        except Exception as e:
            print(f"[!] Error probing {ip}: {e}")


# === 结果记录 ===
def write_results(scan_mode, tunnel_type):
    with open(RESULT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Protocol", "Scan Mode"])
        for ip in sorted(detected_ips):
            writer.writerow([ip, tunnel_type, scan_mode])
    print(f"[+] Results saved to {RESULT_FILE}")


# === 主程序 ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tunnel Scanner with Spoofing")
    parser.add_argument(
        "-s",
        "--scan-mode",
        default="standard",
        choices=["standard", "subnet-spoof", "spoof", "6to4"],
        help="Select scanning mode",
    )
    parser.add_argument(
        "-t",
        "--tunnel-type",
        default="ipip",
        choices=["ipip", "gre", "6in4", "4in6"],
        help="Select tunnel type",
    )
    args = parser.parse_args()

    scan_mode = args.scan_mode
    tunnel_type = args.tunnel_type

    # 启动监听线程
    sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
    sniffer_thread.start()

    # 开始扫描
    scan_targets(scan_mode, tunnel_type)

    # 等待回传数据
    print("[*] Waiting 10s for potential forwarded packets...")
    time.sleep(10)

    # 记录扫描结果
    write_results(scan_mode, tunnel_type)
