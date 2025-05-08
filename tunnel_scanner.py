from scapy.all import *
import time

# === 用户配置 ===
SCANNER_IP = "YOUR_SCANNER_PUBLIC_IP"  # 替换成你公网 IP
INTERFACE = "eth0"                      # 你的网卡名
DELAY_BETWEEN_PROBES = 0.01            # 控制速率，避免被封
MODE = "ipip"                           # "ipip" or "gre"
TARGET_FILE = "targets.txt"            # ZMap 扫描结果文件
# =================

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

if __name__ == "__main__":
    scan_targets(MODE)
