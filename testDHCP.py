#!/usr/bin/env python3
"""
DHCP Options Scanner v3.0 - работает без остановки DHCP клиента
Требует запуска с правами администратора (sudo)
"""

import socket
import struct
import random
import time
import sys
import os
import select
from typing import Dict, List, Optional, Tuple
from datetime import datetime

# DHCP константы
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
DHCP_MAGIC_COOKIE = b'\x63\x82\x53\x63'

# Коды DHCP опций
DHCP_OPTIONS = {
    1: "Subnet Mask",
    2: "Time Offset",
    3: "Router",
    6: "DNS Server",
    12: "Host Name",
    15: "Domain Name",
    28: "Broadcast Address",
    42: "NTP Servers",
    51: "IP Address Lease Time",
    53: "DHCP Message Type",
    54: "Server Identifier",
    55: "Parameter Request List",
    58: "Renewal Time",
    59: "Rebinding Time",
    61: "Client Identifier",
    66: "TFTP Server Name",
    67: "Bootfile Name",
    101: "TZ Code",
    102: "TZ String",
    121: "Classless Static Route",
    150: "TFTP Server Address",
}

class DHCPPacket:
    """Класс для работы с DHCP пакетами"""
    
    def __init__(self, op=1, htype=1, hlen=6, hops=0, 
                 xid=None, secs=0, flags=0, ciaddr='0.0.0.0',
                 yiaddr='0.0.0.0', siaddr='0.0.0.0', giaddr='0.0.0.0',
                 chaddr=None, sname=b'', file=b'', options=None):
        
        self.op = op
        self.htype = htype
        self.hlen = hlen
        self.hops = hops
        self.xid = xid or random.randint(0, 0xFFFFFFFF)
        self.secs = secs
        self.flags = flags
        self.ciaddr = ciaddr
        self.yiaddr = yiaddr
        self.siaddr = siaddr
        self.giaddr = giaddr
        self.chaddr = chaddr or b'\x00' * 16
        self.sname = sname.ljust(64, b'\x00')
        self.file = file.ljust(128, b'\x00')
        self.options = options or []
    
    def pack(self) -> bytes:
        """Упаковка пакета в бинарный формат"""
        packet = struct.pack(
            '!BBBBLHHLLLL16s64s128s',
            self.op,
            self.htype,
            self.hlen,
            self.hops,
            self.xid,
            self.secs,
            self.flags,
            struct.unpack('!L', socket.inet_aton(self.ciaddr))[0],
            struct.unpack('!L', socket.inet_aton(self.yiaddr))[0],
            struct.unpack('!L', socket.inet_aton(self.siaddr))[0],
            struct.unpack('!L', socket.inet_aton(self.giaddr))[0],
            self.chaddr,
            self.sname,
            self.file
        )
        
        packet += DHCP_MAGIC_COOKIE
        
        for opt_code, opt_data in self.options:
            if opt_code == 0:
                packet += bytes([opt_code])
            elif opt_code == 255:
                packet += bytes([opt_code])
            else:
                opt_len = len(opt_data)
                packet += bytes([opt_code, opt_len]) + opt_data
        
        if not any(opt[0] == 255 for opt in self.options):
            packet += b'\xff'
            
        return packet
    
    @classmethod
    def unpack(cls, data: bytes) -> 'DHCPPacket':
        """Распаковка бинарных данных в объект DHCPPacket"""
        fields = struct.unpack('!BBBBLHHLLLL16s64s128s', data[:236])
        
        obj = cls(
            op=fields[0],
            htype=fields[1],
            hlen=fields[2],
            hops=fields[3],
            xid=fields[4],
            secs=fields[5],
            flags=fields[6],
            ciaddr=socket.inet_ntoa(struct.pack('!L', fields[7])),
            yiaddr=socket.inet_ntoa(struct.pack('!L', fields[8])),
            siaddr=socket.inet_ntoa(struct.pack('!L', fields[9])),
            giaddr=socket.inet_ntoa(struct.pack('!L', fields[10])),
            chaddr=fields[11],
            sname=fields[12].rstrip(b'\x00'),
            file=fields[13].rstrip(b'\x00'),
        )
        
        options_data = data[240:]
        obj.options = cls._parse_options(options_data)
        
        return obj
    
    @staticmethod
    def _parse_options(data: bytes) -> List[tuple]:
        """Парсинг секции опций"""
        options = []
        i = 0
        
        while i < len(data):
            opt_code = data[i]
            i += 1
            
            if opt_code == 0:
                continue
            elif opt_code == 255:
                break
            elif i < len(data):
                opt_len = data[i]
                i += 1
                opt_data = data[i:i+opt_len]
                i += opt_len
                options.append((opt_code, opt_data))
            else:
                break
        
        return options

class DHCPListener:
    """Класс для прослушивания DHCP трафика без привязки к порту 68"""
    
    def __init__(self, interface: str = None):
        self.interface = interface
        self.socket = None
        self.xid_filter = None
        
    def start(self):
        """Запуск прослушивания DHCP трафика"""
        try:
            # Создаем RAW сокет для захвата всех пакетов
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
            
            # Привязываемся к интерфейсу
            if self.interface:
                self.socket.bind((self.interface, 0))
            else:
                self.socket.bind(('any', 0))
                
            # Устанавливаем неблокирующий режим
            self.socket.setblocking(False)
            
            return True
        except Exception as e:
            print(f"❌ Ошибка создания RAW сокета: {e}")
            return False
    
    def set_filter(self, xid: int):
        """Установка фильтра по XID пакета"""
        self.xid_filter = xid
    
    def receive(self, timeout: int = 5) -> Optional[DHCPPacket]:
        """Прием DHCP пакета с фильтром по XID"""
        if not self.socket:
            return None
        
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                # Используем select для проверки наличия данных
                ready, _, _ = select.select([self.socket], [], [], 0.1)
                if not ready:
                    continue
                
                # Получаем пакет
                packet = self.socket.recv(2048)
                
                # Проверяем, что это IP пакет достаточной длины
                if len(packet) < 14:
                    continue
                
                # Пропускаем Ethernet заголовок (14 байт)
                ip_header = packet[14:]
                
                # Проверяем, что это UDP (протокол 17)
                if ip_header[9] != 17:
                    continue
                
                # Пропускаем IP заголовок (20 байт для IPv4 без опций)
                ip_hlen = (ip_header[0] & 0x0F) * 4
                udp_header = ip_header[ip_hlen:]
                
                # Проверяем порты (67 -> 68)
                src_port = struct.unpack('!H', udp_header[0:2])[0]
                dst_port = struct.unpack('!H', udp_header[2:4])[0]
                
                if src_port != 67 or dst_port != 68:
                    continue
                
                # Получаем длину UDP пакета
                udp_length = struct.unpack('!H', udp_header[4:6])[0]
                
                # Извлекаем данные DHCP
                dhcp_data = udp_header[8:8+udp_length-8]
                
                if len(dhcp_data) < 240:
                    continue
                
                # Парсим DHCP пакет
                dhcp_packet = DHCPPacket.unpack(dhcp_data)
                
                # Фильтруем по XID если задан фильтр
                if self.xid_filter is not None and dhcp_packet.xid != self.xid_filter:
                    continue
                
                return dhcp_packet
                
            except BlockingIOError:
                continue
            except Exception as e:
                print(f"⚠️  Ошибка при разборе пакета: {e}")
                continue
        
        return None
    
    def stop(self):
        """Остановка прослушивания"""
        if self.socket:
            self.socket.close()
            self.socket = None

def get_mac_address(interface: str) -> Optional[bytes]:
    """Получение MAC адреса интерфейса"""
    try:
        if sys.platform.startswith('linux'):
            mac_path = f'/sys/class/net/{interface}/address'
            if os.path.exists(mac_path):
                with open(mac_path, 'r') as f:
                    mac_str = f.read().strip()
                    return bytes.fromhex(mac_str.replace(':', ''))
    except Exception as e:
        print(f"⚠️  Не удалось получить MAC адрес: {e}")
    
    # Генерация случайного MAC
    print("⚠️  Используется случайный MAC адрес")
    return bytes([random.randint(0x00, 0xFF) for _ in range(6)])

def create_dhcp_discover(mac: bytes, xid: int) -> DHCPPacket:
    """Создание DHCP DISCOVER пакета"""
    chaddr = mac.ljust(16, b'\x00')
    
    # Запрашиваем основные опции
    requested_options = bytes([1, 2, 3, 6, 12, 15, 28, 42, 51, 54, 58, 59, 101, 102])
    
    options = [
        (53, b'\x01'),  # DHCP Message Type: Discover
        (55, requested_options),  # Parameter Request List
        (61, b'\x01' + mac),  # Client Identifier
        (12, b'dhcp-scanner'),  # Hostname
        (60, b'python-scanner'),  # Vendor Class Identifier
        (255, b''),  # End
    ]
    
    return DHCPPacket(
        op=1,
        htype=1,
        hlen=6,
        xid=xid,
        chaddr=chaddr,
        options=options
    )

def send_dhcp_discover_raw(mac: bytes, xid: int, interface: str = None) -> bytes:
    """Создание сырого Ethernet кадра с DHCP DISCOVER"""
    # Создаем DHCP пакет
    dhcp_packet = create_dhcp_discover(mac, xid)
    dhcp_data = dhcp_packet.pack()
    
    # Создаем UDP заголовок
    udp_length = 8 + len(dhcp_data)
    udp_header = struct.pack('!HHHH', 
        random.randint(40000, 65535),  # Источник (случайный порт > 1024)
        DHCP_SERVER_PORT,              # Назначение (порт 67)
        udp_length,                    # Длина
        0                              # Контрольная сумма (0 = вычисляется ядром)
    )
    
    # Создаем IP заголовок
    ip_header = struct.pack('!BBHHHBBH4s4s',
        0x45,                          # Версия (4) + длина заголовка (5)
        0x00,                          # DSCP
        20 + udp_length,               # Общая длина
        random.randint(0, 65535),      # Идентификатор
        0x4000,                        # Флаги + смещение
        0x80,                          # TTL (128)
        17,                            # Протокол (UDP)
        0,                             # Контрольная сумма
        socket.inet_aton('0.0.0.0'),   # Источник
        socket.inet_aton('255.255.255.255')  # Назначение (broadcast)
    )
    
    # Создаем Ethernet заголовок (broadcast)
    eth_header = struct.pack('!6s6sH',
        b'\xff\xff\xff\xff\xff\xff',   # MAC назначения (broadcast)
        mac,                           # MAC источника
        0x0800                         # EtherType (IPv4)
    )
    
    # Собираем полный кадр
    return eth_header + ip_header + udp_header + dhcp_data

def scan_dhcp_options(interface: str) -> Optional[Dict]:
    """Сканирование DHCP опций на указанном интерфейсе"""
    print(f"🔍 Сканирование на интерфейсе: {interface}")
    print(f"⏳ Пожалуйста, подождите...")
    
    # Получаем MAC адрес
    mac = get_mac_address(interface)
    print(f"🔢 MAC адрес: {':'.join(f'{b:02x}' for b in mac)}")
    
    # Генерируем уникальный XID
    xid = random.randint(0, 0xFFFFFFFF)
    print(f"🆔 XID запроса: 0x{xid:08x}")
    
    # Создаем слушатель
    listener = DHCPListener(interface)
    if not listener.start():
        print("❌ Не удалось запустить прослушиватель")
        return None
    
    listener.set_filter(xid)
    
    try:
        # Создаем сырой сокет для отправки
        send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
        send_sock.bind((interface, 0))
        
        # Отправляем DHCP DISCOVER
        discover_frame = send_dhcp_discover_raw(mac, xid, interface)
        
        print("🔄 Отправка DHCP DISCOVER...")
        
        # Отправляем 3 раза с интервалом
        for i in range(3):
            send_sock.send(discover_frame)
            print(f"   Попытка {i+1}/3 отправлена")
            if i < 2:
                time.sleep(0.5)
        
        send_sock.close()
        
        # Ждем ответ
        print("👂 Ожидание ответа от DHCP сервера...")
        
        response = listener.receive(timeout=8)
        
        if response:
            print(f"✅ Получен ответ от DHCP сервера!")
            print(f"📡 Предлагаемый IP: {response.yiaddr}")
            
            # Парсим опции
            parsed_options = {}
            for opt_code, opt_data in response.options:
                if opt_code == 53 and opt_data:  # Message Type
                    msg_types = {b'\x01': 'DISCOVER', b'\x02': 'OFFER', b'\x03': 'REQUEST',
                               b'\x05': 'ACK', b'\x06': 'NAK'}
                    parsed_options[opt_code] = msg_types.get(opt_data, f'Unknown ({opt_data.hex()})')
                elif opt_code == 2:  # Time Offset
                    if len(opt_data) >= 4:
                        offset = struct.unpack('!l', opt_data[:4])[0]
                        hours = offset // 3600
                        minutes = (offset % 3600) // 60
                        parsed_options[opt_code] = f"{offset} сек ({hours:+d}ч {minutes}м)"
                    else:
                        parsed_options[opt_code] = f"0x{opt_data.hex()}"
                elif opt_code in [1, 3, 6, 28, 42, 54] and len(opt_data) % 4 == 0:
                    ips = []
                    for i in range(0, len(opt_data), 4):
                        ip = socket.inet_aton(opt_data[i:i+4])
                        ips.append(socket.inet_ntoa(ip))
                    parsed_options[opt_code] = ', '.join(ips)
                elif opt_code in [51, 58, 59] and len(opt_data) == 4:
                    seconds = struct.unpack('!L', opt_data)[0]
                    parsed_options[opt_code] = f"{seconds} сек"
                elif opt_data:
                    try:
                        parsed_options[opt_code] = opt_data.decode('ascii', errors='ignore')
                    except:
                        parsed_options[opt_code] = f"0x{opt_data.hex()}"
                else:
                    parsed_options[opt_code] = "Present"
            
            return {
                'response': response,
                'options': parsed_options,
                'interface': interface,
                'mac': mac
            }
        else:
            print("❌ DHCP сервер не ответил")
            return None
            
    except Exception as e:
        print(f"❌ Ошибка при сканировании: {e}")
        return None
    finally:
        listener.stop()

def display_results(results: Dict):
    """Отображение результатов сканирования"""
    response = results['response']
    options = results['options']
    
    print("\n" + "="*60)
    print("РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ DHCP")
    print("="*60)
    
    print(f"\n📡 Основная информация:")
    print(f"  Интерфейс:        {results['interface']}")
    print(f"  MAC адрес:        {':'.join(f'{b:02x}' for b in results['mac'])}")
    print(f"  Предлагаемый IP:  {response.yiaddr}")
    print(f"  DHCP сервер:      {response.siaddr if response.siaddr != '0.0.0.0' else 'не указан'}")
    
    print(f"\n📋 Обнаруженные опции DHCP ({len(response.options)}):")
    print("-"*60)
    
    # Группируем опции по важности
    time_options = [2, 42, 101, 102, 51, 58, 59]
    network_options = [1, 3, 6, 28, 54]
    other_options = [opt_code for opt_code in sorted(options.keys()) 
                     if opt_code not in time_options + network_options]
    
    print("\n⏰ Опции времени:")
    for opt_code in sorted([opt for opt in options.keys() if opt in time_options]):
        opt_name = DHCP_OPTIONS.get(opt_code, f"Unknown ({opt_code})")
        value = options[opt_code]
        
        if opt_code == 2:
            print(f"  🔴 {opt_code:3} - {opt_name:25} : {value} (УСТАРЕВШАЯ)")
        elif opt_code == 42:
            print(f"  🟢 {opt_code:3} - {opt_name:25} : {value} (ВАЖНАЯ)")
        else:
            print(f"  ⚪ {opt_code:3} - {opt_name:25} : {value}")
    
    print("\n🌐 Сетевые опции:")
    for opt_code in sorted([opt for opt in options.keys() if opt in network_options]):
        opt_name = DHCP_OPTIONS.get(opt_code, f"Unknown ({opt_code})")
        value = options[opt_code]
        print(f"  🔵 {opt_code:3} - {opt_name:25} : {value}")
    
    print("\n📄 Прочие опции:")
    for opt_code in sorted(other_options):
        opt_name = DHCP_OPTIONS.get(opt_code, f"Unknown ({opt_code})")
        value = options[opt_code]
        print(f"  ⚪ {opt_code:3} - {opt_name:25} : {value}")
    
    # Анализ поддержки Time Offset
    if 2 in options:
        print(f"\n⚠️  ВАЖНО: Роутер поддерживает устаревшую опцию Time Offset (2)")
        print(f"   Значение: {options[2]}")
        print(f"   Это указывает на использование устаревшей конфигурации")
        print(f"   Рекомендуется перейти на опцию 42 (NTP Servers)")
    else:
        print(f"\n✅ Роутер НЕ поддерживает устаревшую опцию Time Offset (2)")
        print(f"   Это нормально для современного оборудования")
    
    # Анализ поддержки NTP
    if 42 in options:
        print(f"\n✅ Роутер поддерживает современную опцию NTP Servers (42)")
        print(f"   Серверы NTP: {options[42]}")
        print(f"   Синхронизация времени через DHCP работает корректно")
    else:
        print(f"\n⚠️  Роутер НЕ поддерживает опцию NTP Servers (42)")
        print(f"   Для синхронизации времени используйте:")
        print(f"   1. Ручную настройку NTP на устройствах")
        print(f"   2. Настройку NTP на самом роутере")
        print(f"   3. Другие методы синхронизации времени")
    
    print(f"\n📊 Итог: Обнаружено {len(options)} опций DHCP")

def get_network_interfaces() -> List[str]:
    """Получение списка сетевых интерфейсов"""
    interfaces = []
    
    try:
        # Для Linux
        if sys.platform.startswith('linux'):
            net_path = '/sys/class/net/'
            if os.path.exists(net_path):
                for iface in os.listdir(net_path):
                    if iface != 'lo' and not iface.startswith('docker'):
                        # Проверяем, что интерфейс не виртуальный
                        iface_path = os.path.join(net_path, iface)
                        if os.path.exists(os.path.join(iface_path, 'device')):
                            interfaces.append(iface)
                        else:
                            # Проверяем, есть ли у интерфейса операционный статус
                            operstate_path = os.path.join(iface_path, 'operstate')
                            if os.path.exists(operstate_path):
                                with open(operstate_path, 'r') as f:
                                    if f.read().strip() == 'up':
                                        interfaces.append(iface)
    except Exception as e:
        print(f"⚠️  Ошибка при получении интерфейсов: {e}")
    
    return interfaces

def main():
    """Основная функция"""
    print("="*60)
    print("DHCP OPTIONS SCANNER v3.0")
    print("="*60)
    print("🔍 Сканирование DHCP опций без остановки DHCP клиента")
    print("="*60)
    
    # Проверка прав
    if os.geteuid() != 0:
        print("\n❌ ОШИБКА: Программа требует прав администратора!")
        print("\n📋 Инструкция по запуску:")
        print("1. Сохраните файл как dhcp_scanner.py")
        print("2. Запустите в терминале:")
        print("   sudo python3 dhcp_scanner.py")
        print("\n🔄 Программа использует RAW сокеты и не требует")
        print("   остановки системного DHCP клиента.")
        sys.exit(1)
    
    # Проверка платформы
    if not sys.platform.startswith('linux'):
        print("❌ Эта программа работает только на Linux!")
        print("   Windows и macOS не поддерживают необходимые RAW сокеты.")
        sys.exit(1)
    
    # Получение интерфейса
    interface = None
    if len(sys.argv) > 1:
        interface = sys.argv[1]
        print(f"🎯 Используется интерфейс: {interface}")
    else:
        # Автоопределение интерфейса
        interfaces = get_network_interfaces()
        
        if not interfaces:
            print("❌ Сетевые интерфейсы не найдены!")
            print("   Убедитесь, что сетевой адаптер подключен.")
            sys.exit(1)
        
        print(f"\n📶 Найдено интерфейсов: {len(interfaces)}")
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface}")
        
        print("\n🎯 Выберите интерфейс для сканирования:")
        print("   - Введите номер интерфейса (1, 2, ...)")
        print("   - Или введите имя интерфейса")
        print("   - Или нажмите Enter для первого интерфейса")
        
        choice = input("Ваш выбор: ").strip()
        
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(interfaces):
                interface = interfaces[idx]
            else:
                print("❌ Неверный номер")
                sys.exit(1)
        elif choice:
            if choice in interfaces:
                interface = choice
            else:
                print(f"❌ Интерфейс '{choice}' не найден")
                sys.exit(1)
        else:
            interface = interfaces[0]
            print(f"🔄 Используется первый интерфейс: {interface}")
    
    # Проверка существования интерфейса
    if not os.path.exists(f'/sys/class/net/{interface}'):
        print(f"❌ Интерфейс '{interface}' не существует!")
        print("   Проверьте название интерфейса командой: ip addr show")
        sys.exit(1)
    
    # Запуск сканирования
    print("\n" + "="*60)
    print("НАЧАЛО СКАНИРОВАНИЯ")
    print("="*60)
    
    start_time = time.time()
    results = scan_dhcp_options(interface)
    
    if results:
        display_results(results)
        
        # Сохранение результатов в файл
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"dhcp_scan_{interface}_{timestamp}.txt"
        
        try:
            with open(filename, 'w') as f:
                f.write(f"DHCP Scan Results - {datetime.now()}\n")
                f.write(f"Interface: {interface}\n")
                f.write(f"MAC: {':'.join(f'{b:02x}' for b in results['mac'])}\n")
                f.write(f"Offered IP: {results['response'].yiaddr}\n")
                f.write(f"DHCP Server: {results['response'].siaddr}\n\n")
                f.write("Options:\n")
                for opt_code in sorted(results['options'].keys()):
                    opt_name = DHCP_OPTIONS.get(opt_code, f"Unknown ({opt_code})")
                    f.write(f"{opt_code:3} - {opt_name:25}: {results['options'][opt_code]}\n")
            
            print(f"\n💾 Результаты сохранены в файл: {filename}")
        except Exception as e:
            print(f"⚠️  Не удалось сохранить результаты: {e}")
    else:
        print("\n" + "="*60)
        print("СКАНИРОВАНИЕ НЕ УДАЛОСЬ")
        print("="*60)
        
        print("\n🔍 Возможные причины:")
        print("1. 📡 Нет подключения к сети")
        print("2. 🔌 DHCP отключен на роутере")
        print("3. 🛡️  Фаервол блокирует DHCP трафик")
        print("4. ⚙️  Используется статическая IP адресация")
        
        print("\n🛠️  Рекомендации по устранению:")
        print("1. Проверьте подключение кабеля/Wi-Fi")
        print("2. Проверьте настройки роутера (включен ли DHCP)")
        print("3. Попробуйте другой интерфейс")
        print("4. Проверьте с помощью команд:")
        print("   sudo tcpdump -i {interface} port 67 or port 68")
        print("   sudo dhclient -v {interface}")
    
    elapsed_time = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"Сканирование завершено за {elapsed_time:.1f} секунд")
    print(f"Время: {datetime.now().strftime('%H:%M:%S')}")
    print("="*60)

if __name__ == "__main__":
    main()