#!/usr/bin/env python3
import socket
import time
import sys
import os
import argparse
import threading
import queue
import ipaddress
import json
import subprocess
import platform
from collections import defaultdict

class C:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'

def cprint(text, color=C.RESET, bold=False):
    prefix = C.BOLD if bold else ''
    print(f"{prefix}{color}{text}{C.RESET}")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

class ScannerCore:
    def __init__(self):
        self.results = defaultdict(dict)
        self.lock = threading.Lock()
        self.stop_flag = False
        self.timeout = 1.0

    def tcp_connect_scan(self, target_ip, target_port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((target_ip, target_port))
            s.close()
            if result == 0:
                return "open"
            elif result == 111:
                return "closed"
            else:
                return "filtered"
        except socket.timeout:
            return "filtered"
        except Exception:
            return "error"

    def grab_banner(self, target_ip, target_port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((target_ip, target_port))
            if target_port in [80, 443, 8080, 8000]:
                s.send(b"HEAD / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\nConnection: close\r\n\r\n")
            elif target_port == 21:
                pass
            elif target_port == 22:
                pass
            elif target_port == 25:
                s.send(b"HELO test\r\n")
            time.sleep(0.3)
            data = s.recv(1024)
            s.close()
            banner = data.decode('utf-8', errors='ignore').strip()
            return banner.replace('\r', '').replace('\n', ' | ')[:80]
        except Exception:
            return None

    def get_os_guess(self, target_ip, open_ports):
        os_guesses = []
        if 135 in open_ports or 139 in open_ports or 445 in open_ports:
            os_guesses.append("Windows")
        if 22 in open_ports:
            os_guesses.append("Linux/Unix")
        if 548 in open_ports:
            os_guesses.append("Mac OS X")
        if 62078 in open_ports:
            os_guesses.append("iOS")
        if 5555 in open_ports:
            os_guesses.append("Android")
        if not os_guesses:
            return "Неизвестно"
        return ", ".join(os_guesses)

    def icmp_ping(self, target_ip):
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', '-w', '1000', target_ip] if platform.system().lower() == 'windows' else ['ping', param, '1', '-W', '1', target_ip]
            output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
            return output.returncode == 0
        except Exception:
            return False

    def scan_ports_threaded(self, target_ip, port_range):
        open_ports = []
        port_list = []
        for part in port_range.split(','):
            if '-' in part:
                start, end = part.split('-')
                port_list.extend(range(int(start), int(end) + 1))
            else:
                port_list.append(int(part))
                
        port_queue = queue.Queue()
        for p in port_list:
            port_queue.put(p)

        def worker():
            while not port_queue.empty() and not self.stop_flag:
                try:
                    port = port_queue.get(timeout=0.1)
                except queue.Empty:
                    break
                status = self.tcp_connect_scan(target_ip, port)
                if status == "open":
                    with self.lock:
                        open_ports.append(port)
                port_queue.task_done()

        threads = []
        for _ in range(min(300, len(port_list))):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        return sorted(open_ports)

    def resolve_target(self, target):
        try:
            return socket.gethostbyname(target)
        except Exception:
            return None

    def reverse_dns(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "N/A"

    def ping_sweep(self, network_cidr):
        alive = []
        try:
            net = ipaddress.ip_network(network_cidr, strict=False)
        except ValueError:
            cprint("[!] Неверный формат сети. Используйте CIDR (например, 192.168.1.0/24).", C.RED)
            return alive

        threads = []
        lock = threading.Lock()

        def ping_host(ip):
            if self.icmp_ping(ip):
                with lock:
                    alive.append(ip)
                    print(f"  {C.GREEN}[+] {ip}{C.RESET} доступен ({self.reverse_dns(ip)})")

        cprint(f"[*] Запуск пинг-сканирования сети {network_cidr}...", C.CYAN)
        for ip in net.hosts():
            ip_str = str(ip)
            t = threading.Thread(target=ping_host, args=(ip_str,))
            t.daemon = True
            t.start()
            threads.append(t)
            if len(threads) >= 50:
                for thr in threads: thr.join()
                threads = []

        for thr in threads: thr.join()
        return alive

class AdvancedScanner(ScannerCore):
    def __init__(self):
        super().__init__()
        self.service_db = {
            20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
            80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
            143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds",
            3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc",
            6379: "redis", 8080: "http-proxy", 27017: "mongodb"
        }
        self.last_scan_results = {}

    def get_service_name(self, port):
        return self.service_db.get(port, "unknown")

    def save_report(self, filename="scan_report.json"):
        if not self.last_scan_results:
            cprint("[!] Нет данных для сохранения.", C.YELLOW)
            return
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.last_scan_results, f, indent=4, ensure_ascii=False)
            cprint(f"[+] Отчет успешно сохранен в файл: {filename}", C.GREEN)
        except Exception as e:
            cprint(f"[!] Ошибка сохранения файла: {e}", C.RED)

    def scan_single_ip(self, target):
        ip = self.resolve_target(target)
        if not ip:
            cprint(f"[!] Не удалось разрешить адрес {target}", C.RED)
            return
        cprint(f"\n[*] Анализ отдельного IP: {ip} ({self.reverse_dns(ip)})", C.BLUE, bold=True)
        if not self.icmp_ping(ip):
            cprint("[!] Хост не отвечает на ICMP, принудительное сканирование...", C.YELLOW)
        else:
            cprint("[+] Хост доступен по ICMP.", C.GREEN)

        cprint("[*] Сканирование портов (1-1024)...", C.CYAN)
        open_ports = self.scan_ports_threaded(ip, "1-1024")
        
        self.last_scan_results[ip] = {"hostname": self.reverse_dns(ip), "ports": open_ports, "os": self.get_os_guess(ip, open_ports)}
        
        if not open_ports:
            cprint("[!] Открытых портов не найдено.", C.YELLOW)
            return

        cprint(f"\n[+] Найдено открытых портов: {len(open_ports)}", C.GREEN, bold=True)
        cprint(f"[*] Вероятная ОС: {self.get_os_guess(ip, open_ports)}", C.MAGENTA)
        
        print(f"{C.BOLD}{'ПОРТ':<10}{'СЕРВИС':<15}{'БАННЕР (ОБРЕЗКА)'}{C.RESET}")
        print(f"{C.GRAY}{'-'*70}{C.RESET}")
        for port in open_ports:
            banner = self.grab_banner(ip, port)
            service = self.get_service_name(port)
            banner_str = f"{C.GRAY}{banner[:50]}...{C.RESET}" if banner else ""
            print(f"{C.GREEN}{port:<10}{C.RESET}{C.CYAN}{service:<15}{C.RESET}{banner_str}")

    def scan_port_nmap_style(self, target, port_range):
        ip = self.resolve_target(target)
        if not ip:
            cprint(f"[!] Не удалось разрешить адрес {target}", C.RED)
            return
        cprint(f"\n[*] Глубокий анализ портов (nmap-style) для {ip}", C.BLUE, bold=True)
        
        cprint(f"[*] Сканирование портов {port_range}...", C.CYAN)
        open_ports = self.scan_ports_threaded(ip, port_range)
        
        self.last_scan_results[ip] = {"hostname": self.reverse_dns(ip), "ports": open_ports, "os": self.get_os_guess(ip, open_ports)}

        if not open_ports:
            cprint("[!] Открытых портов не найдено.", C.YELLOW)
            return

        print(f"\n{C.BOLD}{'ПОРТ':<8}{'СОСТОЯНИЕ':<12}{'СЕРВИС':<18}{'ВЕРСИЯ/БАННЕР'}{C.RESET}")
        print(f"{C.GRAY}{'-'*80}{C.RESET}")
        for port in open_ports:
            banner = self.grab_banner(ip, port)
            service = self.get_service_name(port)
            b_str = banner if banner else "-"
            print(f"{C.GREEN}{port:<8}{C.RESET}{C.GREEN}open{C.RESET}      {C.CYAN}{service:<18}{C.RESET}{C.WHITE}{b_str[:50]}{C.RESET}")

    def scan_network_full(self, network_cidr):
        cprint(f"\n[*] Анализ полной сети: {network_cidr}", C.BLUE, bold=True)
        alive_ips = self.ping_sweep(network_cidr)
        if not alive_ips:
            cprint("[!] В сети не найдено активных хостов.", C.YELLOW)
            return

        cprint(f"\n[+] Найдено активных хостов: {len(alive_ips)}. Запуск анализа портов...", C.GREEN)
        print(f"\n{C.BOLD}{'IP-АДРЕС':<16}{'ИМЯ ХОСТА':<20}{'ОС':<25}{'ОТКРЫТЫЕ ПОРТЫ'}{C.RESET}")
        print(f"{C.GRAY}{'-'*85}{C.RESET}")
        
        lock = threading.Lock()
        self.last_scan_results = {}

        def analyze_host(ip):
            open_ports = self.scan_ports_threaded(ip, "1-1024")
            os_guess = self.get_os_guess(ip, open_ports) if open_ports else "Неизвестно"
            hostname = self.reverse_dns(ip)
            
            with lock:
                self.last_scan_results[ip] = {
                    "hostname": hostname,
                    "os": os_guess,
                    "ports": open_ports
                }
                
                if open_ports:
                    ports_str = ", ".join(str(p) for p in open_ports[:5])
                    if len(open_ports) > 5: ports_str += "..."
                else:
                    ports_str = "Нет"
                    
                host_disp = f"{ip:<16}"
                name_disp = f"{hostname[:19]:<20}"
                os_disp = f"{os_guess:<25}"
                print(f"{C.CYAN}{host_disp}{C.RESET}{C.WHITE}{name_disp}{C.RESET}{C.MAGENTA}{os_disp}{C.RESET}{C.GREEN}{ports_str}{C.RESET}")

        threads = []
        for ip in alive_ips:
            t = threading.Thread(target=analyze_host, args=(ip,))
            t.daemon = True
            t.start()
            threads.append(t)
            if len(threads) >= 5:
                for thr in threads: thr.join()
                threads = []
        for thr in threads: thr.join()
        
        cprint(f"\n[*] Анализ сети завершён.", C.CYAN)
        self.save_report()

def print_header():
    clear_screen()
    cprint("=" * 60, C.CYAN)
    cprint("    NETWORK SCANNER    ", C.GREEN, bold=True)
    cprint("    Tool by @dimagmd(@withoutusernamebtw(https://github.com/dimagmd))    ", C.GRAY)
    cprint("=" * 60, C.CYAN)

def main_menu():
    while True:
        print_header()
        print(f"{C.YELLOW}Главное меню:{C.RESET}")
        print(f"  {C.GREEN}1.{C.RESET} Анализ полной сети")
        print(f"  {C.GREEN}2.{C.RESET} Анализ IP")
        print(f"  {C.GREEN}3.{C.RESET} Анализ портов")
        print(f"  {C.GREEN}4.{C.RESET} Выход")
        print()
        choice = input(f"{C.CYAN}Выберите действие (1-4): {C.RESET}").strip()
        scanner = AdvancedScanner()
        
        try:
            if choice == "1":
                network = input(f"{C.YELLOW}Введите сеть в формате CIDR (например, 192.168.1.0/24): {C.RESET}").strip()
                if network:
                    scanner.scan_network_full(network)
            elif choice == "2":
                target = input(f"{C.YELLOW}Введите IP-адрес или домен (например, 192.168.1.1 или google.com): {C.RESET}").strip()
                if target:
                    scanner.scan_single_ip(target)
            elif choice == "3":
                target = input(f"{C.YELLOW}Введите IP-адрес или домен: {C.RESET}").strip()
                ports = input(f"{C.YELLOW}Введите порты (например, 1-1024 или 22,80,443): {C.RESET}").strip()
                if target and ports:
                    scanner.scan_port_nmap_style(target, ports)
            elif choice == "4":
                cprint("Выход из программы...", C.GREEN)
                sys.exit(0)
            else:
                cprint("[!] Неверный выбор.", C.RED)
        except KeyboardInterrupt:
            cprint("\n[!] Прервано пользователем. Возврат в меню...", C.YELLOW)
        except Exception as e:
            cprint(f"\n[!] Ошибка: {e}", C.RED)
        
        print()
        input(f"{C.CYAN}Нажмите Enter, чтобы продолжить...{C.RESET}")

if __name__ == "__main__":
    if os.name == 'nt':
        os.system('color')
        
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="Advanced Network Scanner")
        parser.add_argument("-t", "--target", required=True, help="Target IP, CIDR, or hostname")
        parser.add_argument("-p", "--ports", default="1-1024", help="Ports to scan")
        parser.add_argument("-s", "--scan-type", default="single", choices=["single", "nmap", "network"], help="Scan type")
        args = parser.parse_args()
        scanner = AdvancedScanner()
        if args.scan_type == "single":
            scanner.scan_single_ip(args.target)
        elif args.scan_type == "nmap":
            scanner.scan_port_nmap_style(args.target, args.ports)
        elif args.scan_type == "network":
            scanner.scan_network_full(args.target)
    else:
        try:
            main_menu()
        except KeyboardInterrupt:
            cprint("\nВыход...", C.GREEN)
            sys.exit(0)
