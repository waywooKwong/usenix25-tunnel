from scapy.all import *
import time
import threading
import csv

# === 用户配置 ===
SCANNER_IP = "YOUR_SCANNER_PUBLIC_IP"  # 替换为你公网 IP
INTERFACE = "eth0"  # 替换为你的网卡名
DELAY_BETWEEN_PROBES = 0.01
MODE = "ipip"  # "ipip" or "gre"
TARGET_FILE = "targets.txt"
RESULT_FILE = "results.csv"  # 输出记录文件
# =================

# === 记录回传 IP ===
detected_ips = set()
lock = threading.Lock()


def handle_packet(pkt):
    if IP in pkt and pkt[IP].dst == SCANNER_IP:
        src = pkt[IP].src
        with lock:
            if src not in detected_ips:
                print(f"[✓] Forwarded packet from: {src}")
                detected_ips.add(src)


def start_sniffer():
    sniff(filter=f"ip dst {SCANNER_IP}", iface=INTERFACE, prn=handle_packet, store=0)


# ==================


def send_ipip_probe(target_ip):
    outer = IP(src=SCANNER_IP, dst=target_ip, proto=4)
    inner = IP(src=target_ip, dst=SCANNER_IP)
    pkt = outer / inner
    send(pkt, iface=INTERFACE, verbose=False)


def send_gre_probe(target_ip):
    outer = IP(src=SCANNER_IP, dst=target_ip, proto=47)
    gre = GRE()
    inner = IP(src=target_ip, dst=SCANNER_IP)
    pkt = outer / gre / inner
    send(pkt, iface=INTERFACE, verbose=False)


def scan_targets(mode):
    with open(TARGET_FILE, "r") as f:
        targets = [line.strip() for line in f if line.strip()]
    print(f"[+] Loaded {len(targets)} target IPs.")

    for ip in targets:
        try:
            print(f"[>] Probing {ip} via {mode.upper()}...")
            if mode == "ipip":
                send_ipip_probe(ip)
            elif mode == "gre":
                send_gre_probe(ip)
            time.sleep(DELAY_BETWEEN_PROBES)
        except Exception as e:
            print(f"[!] Error probing {ip}: {e}")


def write_results():
    with open(RESULT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Protocol"])
        for ip in sorted(detected_ips):
            writer.writerow([ip, MODE])
    print(f"[+] Results saved to {RESULT_FILE}")


if __name__ == "__main__":
    # 启动监听器
    sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
    sniffer_thread.start()

    # 启动扫描
    scan_targets(MODE)

    # 等待回传数据
    print("[*] Waiting 10s for potential forwarded packets...")
    time.sleep(10)

    # 保存结果
    write_results()
