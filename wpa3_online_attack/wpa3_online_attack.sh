#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

plugin_name="WPA3 online attack"
plugin_description="A plugin to perform a dictionary online attack over WPA3 wireless networks"
plugin_author="OscarAkaElvis"

#This plugin is based in the Wacker script. Credits to the authors: https://github.com/blunderbuss-wctf/wacker

plugin_enabled=1

plugin_minimum_ag_affected_version="11.10"
plugin_maximum_ag_affected_version=""
plugin_distros_supported=("*")

#Custom function. Channel mappings to frequency
function custom_channel_mappings() {

	debug_print

	declare -gA channels_to_freq_correspondence

	channels_to_freq_correspondence["1"]="2412"
	channels_to_freq_correspondence["2"]="2417"
	channels_to_freq_correspondence["3"]="2422"
	channels_to_freq_correspondence["4"]="2427"
	channels_to_freq_correspondence["5"]="2432"
	channels_to_freq_correspondence["6"]="2437"
	channels_to_freq_correspondence["7"]="2442"
	channels_to_freq_correspondence["8"]="2447"
	channels_to_freq_correspondence["9"]="2452"
	channels_to_freq_correspondence["10"]="2457"
	channels_to_freq_correspondence["11"]="2462"
	channels_to_freq_correspondence["12"]="2467"
	channels_to_freq_correspondence["13"]="2472"
	channels_to_freq_correspondence["14"]="2484"
	channels_to_freq_correspondence["36"]="5180"
	channels_to_freq_correspondence["40"]="5200"
	channels_to_freq_correspondence["44"]="5220"
	channels_to_freq_correspondence["48"]="5240"
	channels_to_freq_correspondence["52"]="5260"
	channels_to_freq_correspondence["56"]="5280"
	channels_to_freq_correspondence["60"]="5300"
	channels_to_freq_correspondence["64"]="5320"
	channels_to_freq_correspondence["100"]="5500"
	channels_to_freq_correspondence["104"]="5520"
	channels_to_freq_correspondence["108"]="5540"
	channels_to_freq_correspondence["112"]="5560"
	channels_to_freq_correspondence["116"]="5580"
	channels_to_freq_correspondence["120"]="5600"
	channels_to_freq_correspondence["124"]="5620"
	channels_to_freq_correspondence["128"]="5640"
	channels_to_freq_correspondence["132"]="5660"
	channels_to_freq_correspondence["136"]="5680"
	channels_to_freq_correspondence["140"]="5700"
	channels_to_freq_correspondence["144"]="5720"
	channels_to_freq_correspondence["149"]="5745"
	channels_to_freq_correspondence["153"]="5765"
	channels_to_freq_correspondence["157"]="5785"
	channels_to_freq_correspondence["161"]="5805"
	channels_to_freq_correspondence["165"]="5825"
}

#Custom function. Validate if right custom wpa_supplicant binary file exist
function custom_wpa_supplicant_validation() {

	debug_print

	custom_wpa_supplicant_binaries_dir="wpa_supplicant_binaries/"

	if [ "${is_arm}" -eq 1 ]; then
		if uname -m | grep -Ei "armv6l|armv7l" > /dev/null; then
			if ! [ -f "${scriptfolder}${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_armhf" ]; then
				echo
				language_strings "${language}" "wpa3_online_attack_9" "red"
				language_strings "${language}" 115 "read"
				return 1
			else
				custom_wpa_supplicant_binary_path="${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_armhf"
			fi
		elif uname -m | grep -Ei "aarch64|aarch64_be|armv8b|armv8l" > /dev/null; then
			if ! [ -f "${scriptfolder}${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_arm64" ]; then
				echo
				language_strings "${language}" "wpa3_online_attack_9" "red"
				language_strings "${language}" 115 "read"
				return 1
			else
				custom_wpa_supplicant_binary_path="${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_arm64"
			fi
		else
			if ! [ -f "${scriptfolder}${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_armel" ]; then
				echo
				language_strings "${language}" "wpa3_online_attack_9" "red"
				language_strings "${language}" 115 "read"
				return 1
			else
				custom_wpa_supplicant_binary_path="${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_armel"
			fi
		fi
	else
		if uname -m | grep -Ei "x86_64" > /dev/null; then
			if ! [ -f "${scriptfolder}${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_amd64" ]; then
				echo
				language_strings "${language}" "wpa3_online_attack_9" "red"
				language_strings "${language}" 115 "read"
				return 1
			else
				custom_wpa_supplicant_binary_path="${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_amd64"
			fi
		else
			if ! [ -f "${scriptfolder}${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_i386" ]; then
				echo
				language_strings "${language}" "wpa3_online_attack_9" "red"
				language_strings "${language}" 115 "read"
				return 1
			else
				custom_wpa_supplicant_binary_path="${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_i386"
			fi
		fi
	fi

	chmod +x "${custom_wpa_supplicant_binary_path}" 2> /dev/null

	return 0
}

#Custom function. Execute WPA3 online dictionary attack
function exec_wpa3_online_dictionary_attack() {

	debug_print

	freq="${channels_to_freq_correspondence[${channel}]}"

	tmpfiles_toclean=1
	rm -rf "${tmpdir}agwpa3"* > /dev/null 2>&1
	mkdir "${tmpdir}agwpa3" > /dev/null 2>&1

	recalculate_windows_sizes
	manage_output "+j -bg \"#000000\" -fg \"#FFC0CB\" -geometry ${g1_topright_window} -T \"wpa3 online dictionary attack\"" "${python3} ${scriptfolder}${plugins_dir}wpa3_online_attack.py ${DICTIONARY} ${essid} ${bssid} ${interface} ${freq} ${custom_wpa_supplicant_binary_path} ${tmpdir}agwpa3 ${language}" "wpa3 online dictionary attack" "active"
	wait_for_process "${python3} ${scriptfolder}${plugins_dir}wpa3_online_attack.py ${DICTIONARY} ${essid} ${bssid} ${interface} ${freq} ${custom_wpa_supplicant_binary_path} ${tmpdir}agwpa3 ${language}" "wpa3 online dictionary attack"
}

#Custom function. Validate a WPA3 network
function validate_wpa3_network() {

	debug_print

	if [ "${enc}" != "WPA3" ]; then
		echo
		language_strings "${language}" "wpa3_online_attack_6" "red"
		language_strings "${language}" 115 "read"
		return 1
	fi

	return 0
}

#Custom function. Validate if the needed plugin python file exists
function python3_script_validation() {

	debug_print

	if ! [ -f "${scriptfolder}${plugins_dir}wpa3_online_attack.py" ]; then
		echo
		language_strings "${language}" "wpa3_online_attack_8" "red"
		language_strings "${language}" 115 "read"
		return 1
	fi

	return 0
}

#Custom function. Validate if the system has python3.1+ installed and set python launcher
function python3_validation() {

	debug_print

	if ! hash python3 2> /dev/null; then
		if ! hash python 2> /dev/null; then
			echo
			language_strings "${language}" "wpa3_online_attack_7" "red"
			language_strings "${language}" 115 "read"
			return 1
		else
			python_version=$(python -V 2>&1 | sed 's/.* \([0-9]\).\([0-9]\).*/\1\2/')
			if [ "${python_version}" -lt "31" ]; then
				echo
				language_strings "${language}" "wpa3_online_attack_7" "red"
				language_strings "${language}" 115 "read"
				return 1
			fi
			python3="python"
		fi
	else
		python_version=$(python3 -V 2>&1 | sed 's/.* \([0-9]\).\([0-9]\).*/\1\2/')
		if [ "${python_version}" -lt "31" ]; then
			echo
			language_strings "${language}" "wpa3_online_attack_7" "red"
			language_strings "${language}" 115 "read"
			return 1
		fi
		python3="python3"
	fi

	return 0
}

#Custom function. Prepare WPA3 online dictionary attack
function wpa3_online_dictionary_attack_option() {

	debug_print

	if [[ -z ${bssid} ]] || [[ -z ${essid} ]] || [[ -z ${channel} ]] || [[ "${essid}" = "(Hidden Network)" ]]; then
		echo
		language_strings "${language}" 125 "yellow"
		language_strings "${language}" 115 "read"
		if ! explore_for_targets_option "WPA3"; then
			return 1
		fi
	fi

	if check_monitor_enabled "${interface}"; then
		echo
		language_strings "${language}" "wpa3_online_attack_10" "yellow"
		echo
		language_strings "${language}" 115 "read"
		echo
		managed_option "${interface}"
	fi

	if ! validate_wpa3_network; then
		return 1
	fi

	manage_asking_for_dictionary_file

	if ! python3_validation; then
		return 1
	fi

	if ! python3_script_validation; then
		return 1
	fi

	if ! custom_wpa_supplicant_validation; then
		return 1
	fi

	custom_channel_mappings

	echo
	language_strings "${language}" 32 "green"
	echo
	language_strings "${language}" 33 "yellow"
	language_strings "${language}" 4 "read"

	exec_wpa3_online_dictionary_attack
}

#Custom function. Create the WPA3 attacks menu
function wpa3_attacks_menu() {

	debug_print

	clear
	language_strings "${language}" "wpa3_online_attack_2" "title"
	current_menu="wpa3_attacks_menu"
	initialize_menu_and_print_selections
	echo
	language_strings "${language}" 47 "green"
	print_simple_separator
	language_strings "${language}" 59
	language_strings "${language}" 48
	language_strings "${language}" 55
	language_strings "${language}" 56
	language_strings "${language}" 49
	language_strings "${language}" 50 "separator"
	language_strings "${language}" "wpa3_online_attack_3"
	print_hint ${current_menu}

	read -rp "> " wpa3_option
	case ${wpa3_option} in
		0)
			return
		;;
		1)
			select_interface
		;;
		2)
			monitor_option "${interface}"
		;;
		3)
			managed_option "${interface}"
		;;
		4)
			explore_for_targets_option "WPA3"
		;;
		5)
			wpa3_online_dictionary_attack_option
		;;
		*)
			invalid_menu_option
		;;
	esac

	wpa3_attacks_menu
}

#Prehook for explore_for_targets_option function to show right message on WPA3 filtered scanning
#shellcheck disable=SC2016
function wpa3_online_attack_prehook_explore_for_targets_option() {

	sed -zri 's|"WPA3"\)\n\t{4}#Only WPA3 including WPA2\/WPA3 in Mixed mode\n\t{4}#Not used yet in airgeddon\n\t{4}:|"WPA3"\)\n\t\t\t\t#Only WPA3 including WPA2/WPA3 in Mixed mode\n\t\t\t\tlanguage_strings "${language}" "wpa3_online_attack_4" "yellow"|' "${scriptfolder}${scriptname}" 2> /dev/null
}

#Prehook for remove_warnings function to modify existing strings
function wpa3_online_attack_prehook_remove_warnings() {

	arr["ENGLISH",60]="12. About & Credits / Sponsorship mentions"
	arr["SPANISH",60]="12. Acerca de & Créditos / Menciones de patrocinadores"
	arr["FRENCH",60]="12. À propos de & Crédits / Mentions du sponsors"
	arr["CATALAN",60]="12. Sobre & Crédits / Mencions de sponsors"
	arr["PORTUGUESE",60]="12. Sobre & Créditos / Nossos patrocinadores"
	arr["RUSSIAN",60]="12. О программе и Благодарности / Спонсорские упоминания"
	arr["GREEK",60]="12. Σχετικά με & Εύσημα / Αναφορές χορηγίας"
	arr["ITALIAN",60]="12. Informazioni & Crediti / Menzioni di sponsorizzazione"
	arr["POLISH",60]="12. O programie & Podziękowania / Wzmianki sponsorskie"
	arr["GERMAN",60]="12. About & Credits / Sponsoring-Erwähnungen"
	arr["TURKISH",60]="12. Krediler ve Sponsorluk Hakkında"
	arr["ARABIC",60]="12. فريق العمل برعاية"
	arr["CHINESE",60]="12. 关于 & 鸣谢 / 赞助"

	arr["ENGLISH",444]="13. Options and language menu"
	arr["SPANISH",444]="13. Menú de opciones e idioma"
	arr["FRENCH",444]="13. Menu options et langues"
	arr["CATALAN",444]="13. Menú d'opcions i idioma"
	arr["PORTUGUESE",444]="13. Opções de menu e idioma"
	arr["RUSSIAN",444]="13. Настройки и языковое меню"
	arr["GREEK",444]="13. Μενού επιλογών και γλώσσας"
	arr["ITALIAN",444]="13. Menú opzioni e lingua"
	arr["POLISH",444]="13. Opcje i menu językowe"
	arr["GERMAN",444]="13. Optionen und Sprachmenü"
	arr["TURKISH",444]="13. Ayarlar ve dil menüsü"
	arr["ARABIC",444]="13. الخيارات وقائمة اللغة"
	arr["CHINESE",444]="13. 脚本设置和语言菜单"

	arr["ENGLISH","wpa3_online_attack_1"]="11. WPA3 attacks menu"
	arr["SPANISH","wpa3_online_attack_1"]="11. Menú de ataques WPA3"
	arr["FRENCH","wpa3_online_attack_1"]="11. Menu d'attaque WPA3"
	arr["CATALAN","wpa3_online_attack_1"]="11. Menú d'atacs WPA3"
	arr["PORTUGUESE","wpa3_online_attack_1"]="11. Menu de ataques WPA3"
	arr["RUSSIAN","wpa3_online_attack_1"]="11. Меню атак на WPA3"
	arr["GREEK","wpa3_online_attack_1"]="11. Μενού επιθέσεων WPA3"
	arr["ITALIAN","wpa3_online_attack_1"]="11. Menu degli attacchi WPA3"
	arr["POLISH","wpa3_online_attack_1"]="11. Menu ataków WPA3"
	arr["GERMAN","wpa3_online_attack_1"]="11. WPA3-Angriffsmenü"
	arr["TURKISH","wpa3_online_attack_1"]="11. WPA3 saldırılar menüsü"
	arr["ARABIC","wpa3_online_attack_1"]="11. WPA3 قائمة هجمات"
	arr["CHINESE","wpa3_online_attack_1"]="11. WPA3 攻击菜单"

	arr["ENGLISH","wpa3_online_attack_2"]="WPA3 attacks menu"
	arr["SPANISH","wpa3_online_attack_2"]="Menú de ataques WPA3"
	arr["FRENCH","wpa3_online_attack_2"]="Menu d'attaque WPA3"
	arr["CATALAN","wpa3_online_attack_2"]="Menú d'atacs WPA3"
	arr["PORTUGUESE","wpa3_online_attack_2"]="Menu de ataques WPA3"
	arr["RUSSIAN","wpa3_online_attack_2"]="Меню атак на WPA3"
	arr["GREEK","wpa3_online_attack_2"]="Μενού επιθέσεων WPA3"
	arr["ITALIAN","wpa3_online_attack_2"]="Menu degli attacchi WPA3"
	arr["POLISH","wpa3_online_attack_2"]="Menu ataków WPA3"
	arr["GERMAN","wpa3_online_attack_2"]="WPA3-Angriffsmenü"
	arr["TURKISH","wpa3_online_attack_2"]="WPA3 saldırılar menüsü"
	arr["ARABIC","wpa3_online_attack_2"]="WPA3 قائمة هجمات"
	arr["CHINESE","wpa3_online_attack_2"]="WPA3 攻击菜单"

	arr["ENGLISH","wpa3_online_attack_3"]="5.  WPA3 online dictionary attack"
	arr["SPANISH","wpa3_online_attack_3"]="5.  Ataque de diccionario online de WPA3"
	arr["FRENCH","wpa3_online_attack_3"]="5.  Attaque online WPA3 avec dictionaire"
	arr["CATALAN","wpa3_online_attack_3"]="5.  Atac de diccionari en línia de WPA3"
	arr["PORTUGUESE","wpa3_online_attack_3"]="5.  Ataque online de dicionário no WPA3"
	arr["RUSSIAN","wpa3_online_attack_3"]="5.  Онлайн атака на WPA3 со словарём"
	arr["GREEK","wpa3_online_attack_3"]="5.  Διαδικτυακή επίθεση σε WPA3 με λεξικό"
	arr["ITALIAN","wpa3_online_attack_3"]="5.  Attacco online WPA3 con dizionario"
	arr["POLISH","wpa3_online_attack_3"]="5.  Atak słownikowy online WPA3"
	arr["GERMAN","wpa3_online_attack_3"]="5.  WPA3-Angriff auf das Online-Wörterbuch"
	arr["TURKISH","wpa3_online_attack_3"]="5.  WPA3 çevrimiçi sözlük saldırısı"
	arr["ARABIC","wpa3_online_attack_3"]="5.  WPA3 قاموس الهجوم علي الشبكة ل"
	arr["CHINESE","wpa3_online_attack_3"]="5.  WPA3 在线字典攻击"

	arr["ENGLISH","wpa3_online_attack_4"]="WPA3 filter enabled in scan. When started, press [Ctrl+C] to stop..."
	arr["SPANISH","wpa3_online_attack_4"]="Filtro WPA3 activado en escaneo. Una vez empezado, pulse [Ctrl+C] para pararlo..."
	arr["FRENCH","wpa3_online_attack_4"]="Le filtre WPA3 est activé dans le scan. Une fois l'opération a été lancée, veuillez presser [Ctrl+C] pour l'arrêter..."
	arr["CATALAN","wpa3_online_attack_4"]="Filtre WPA3 activat en escaneig. Un cop començat, premeu [Ctrl+C] per aturar-lo..."
	arr["PORTUGUESE","wpa3_online_attack_4"]="Filtro WPA3 ativo na busca de redes wifi. Uma vez iniciado, pressione [Ctrl+C] para pará-lo..."
	arr["RUSSIAN","wpa3_online_attack_4"]="Для сканирования активирован фильтр WPA3. После запуска, нажмите [Ctrl+C] для остановки..."
	arr["GREEK","wpa3_online_attack_4"]="Το φίλτρο WPA3 ενεργοποιήθηκε κατά τη σάρωση. Όταν αρχίσει, μπορείτε να το σταματήσετε πατώντας [Ctrl+C]..."
	arr["ITALIAN","wpa3_online_attack_4"]="Filtro WPA3 attivato durante la scansione. Una volta avviato, premere [Ctrl+C] per fermarlo..."
	arr["POLISH","wpa3_online_attack_4"]="Filtr WPA3 aktywowany podczas skanowania. Naciśnij [Ctrl+C] w trakcie trwania, aby zatrzymać..."
	arr["GERMAN","wpa3_online_attack_4"]="WPA3-Filter beim Scannen aktiviert. Nach den Start, drücken Sie [Ctrl+C], um es zu stoppen..."
	arr["TURKISH","wpa3_online_attack_4"]="WPA3 filtesi taramada etkin. Başladıktan sonra, durdurmak için [Ctrl+C] yapınız..."
	arr["ARABIC","wpa3_online_attack_4"]="...للإيقاف [Ctrl+C] عند البدء ، اضغط على .WPA3 تم تفعيل المسح لشبكات"
	arr["CHINESE","wpa3_online_attack_4"]="已在扫描时启用  WPA3 过滤器。启动中... 按 [Ctrl+C] 停止..."

	arr["ENGLISH","wpa3_online_attack_5"]="WPA3 online dictionary attack takes considerably longer than an offline decryption attack, so it is recommended to only perform it over pure WPA3 networks. If your target network is in WPA2/WPA3 \"Mixed Mode\", it is recommended to carry out the traditional WPA2 attacks (Handshake, PMKID) instead of the online attack"
	arr["SPANISH","wpa3_online_attack_5"]="El ataque de diccionario online de WPA3 tarda bastante más tiempo que un ataque de descifrado offline, por lo que se recomienda solo realizarlo sobre redes puras WPA3. Si tu red objetivo está en WPA2/WPA3 \"Mixed Mode\", lo recomendable es realizar los ataques tradicionales de WPA2 (Handshake, PMKID) en lugar del ataque online"
	arr["FRENCH","wpa3_online_attack_5"]="L'attaque en ligne avec dictionnaire WPA3 prend beaucoup plus de temps qu'une attaque de décryptage hors ligne, il est donc recommandé de ne l'exécuter que sur des réseaux WPA3 purs. Si votre réseau cible est en WPA2/WPA3 \"Mixed Mode\", il est recommandé d'effectuer les attaques WPA2 traditionnelles (Handshake, PMKID) au lieu de l'attaque en ligne"
	arr["CATALAN","wpa3_online_attack_5"]="L'atac de diccionari online de WPA3 triga força més temps que un atac de desxifrat offline, per la qual cosa es recomana només fer-ho sobre xarxes pures WPA3. Si la teva xarxa objectiu està a WPA2/WPA3 \"Mixed Mode\", el recomanable és realitzar els atacs tradicionals de WPA2 (Handshake, PMKID) en lloc de l'atac en línia"
	arr["PORTUGUESE","wpa3_online_attack_5"]="O ataque online de dicionário no WPA3 demora consideravelmente mais que um ataque de descriptografia offline, portanto, é recomendável executá-lo apenas em redes WPA3 puras. Se a rede alvo estiver em WPA2/WPA3 \"Mixed Mode\", é recomendável realizar os ataques WPA2 tradicionais (Handshake ou PMKID) em vez do ataque online"
	arr["RUSSIAN","wpa3_online_attack_5"]="Онлайн атака на WPA3 по словарю занимает значительно больше времени, чем офлайн атака с дешифрованием, поэтому рекомендуется выполнять ее только в WPA3 сетях. Если ваша целевая сеть находится в WPA2/WPA3 \"Mixed Mode\", рекомендуется проводить традиционные атаки на WPA2 (handshake, PMKID)"
	arr["GREEK","wpa3_online_attack_5"]="Η διαδικτυακή επίθεση σε WPA3 με λεξικό διαρκεί πολύ περισσότερο από μια επίθεση αποκρυπτογράφησης εκτός σύνδεσης, επομένως συνιστάται να εκτελείται μόνο μέσω καθαρά WPA3 δικτύων. Εάν το δίκτυο-στόχος σας είναι σε WPA2/WPA3 \"Mixed Mode\", συνιστάται να πραγματοποιήσετε τις καθιερωμένες επιθέσεις WPA2 (Handshake, PMKID) αντί για την διαδικτυακή επίθεση"
	arr["ITALIAN","wpa3_online_attack_5"]="L'attacco online WPA3 con dizionario richiede molto più tempo di un attacco di decriptazione offline, quindi si consiglia di eseguirlo solo su reti WPA3 pure. Se la rete di destinazione è in WPA2/WPA3 \"Modalità mista\", si consiglia di eseguire i tradizionali attacchi WPA2 (Handshake, PMKID) anziché l'attacco online"
	arr["POLISH","wpa3_online_attack_5"]="Atak słownikowy online WPA3 trwa znacznie dłużej niż atak offline. Dlatego zaleca się przeprowadzanie go w sieciach z aktywnym wyłącznie WPA3. Jeśli Twoja sieć docelowa jest w trybie WPA2/WPA3 \"Mixed Mode\", zaleca się przeprowadzenie tradycyjnych ataków WPA2 (Handshake, PMKID) zamiast ataków online"
	arr["GERMAN","wpa3_online_attack_5"]="Der WPA3-Online-Wörterbuchangriff dauert erheblich länger als ein Offline-Entschlüsselungsangriff, daher wird es empfohlen, ihn nur über reine WPA3-Netzwerke durchzuführen. Wenn sich Ihr Zielnetzwerk im WPA2/WPA3 \"Mixed Mode\", befindet, empfiehlt es sich, anstelle des Online-Angriffs die traditionellen WPA2-Angriffe (Handshake, PMKID) durchzuführen"
	arr["TURKISH","wpa3_online_attack_5"]="WPA3 çevrimiçi sözlük saldırısı, çevrimdışı şifre çözme saldırısından çok daha uzun sürer, bu nedenle yalnızca saf WPA3 ağları üzerinden gerçekleştirilmesi önerilir. Hedef ağınız WPA2/WPA3 \"Mixed Mode\" da ise, çevrimiçi saldırı yerine geleneksel WPA2 saldırılarını (Handshake, PMKID) gerçekleştirmeniz önerilir"
	arr["ARABIC","wpa3_online_attack_5"]="(Handshake, PMKID) WPA2 من الافضل ان تستخدم هجمات ال WPA2/WPA3 \"Mixed Mode\" يستغرق الكثير من الوقت ,إن كان هدفك شبكة  WPA3 قاموس الهجوم علي الشبكة ل"
	arr["CHINESE","wpa3_online_attack_5"]="WPA3 在线字典攻击比离线字典解密攻击花费的时间要长得多，因此建议仅在使用纯  WPA3 加密方式网络上执行此攻击。如果您的目标网络处于  WPA2/WPA3 \"混合模式\"，建议进行传统的  WPA2 攻击 (握手、PMKID) 而不是在线攻击"

	arr["ENGLISH","wpa3_online_attack_6"]="The selected network is invalid. The target network must be WPA3 or WPA2/WPA3 in \"Mixed Mode\""
	arr["SPANISH","wpa3_online_attack_6"]="La red seleccionada no es válida. La red objetivo debe ser WPA3 o WPA2/WPA3 en \"Mixed Mode\""
	arr["FRENCH","wpa3_online_attack_6"]="Le réseau sélectionné n'est pas valide. Le réseau cible doit être WPA3 ou WPA2/WPA3 en \"Mixed Mode\""
	arr["CATALAN","wpa3_online_attack_6"]="La xarxa seleccionada no és vàlida. La xarxa objectiu ha de ser WPA3 o WPA2/WPA3 a \"Mixed Mode\""
	arr["PORTUGUESE","wpa3_online_attack_6"]="A rede selecionada é inválida. A rede deve ser WPA3 ou WPA2/WPA3 em \"Mixed Mode\""
	arr["RUSSIAN","wpa3_online_attack_6"]="Выбранная сеть недействительна. Целевая сеть должна быть WPA3 или WPA2/WPA3 в \"Mixed Mode\""
	arr["GREEK","wpa3_online_attack_6"]="Το επιλεγμένο δίκτυο δεν είναι έγκυρο. Το δίκτυο-στόχος πρέπει να είναι WPA3 ή WPA2/WPA3 σε \"Mixed Mode\""
	arr["ITALIAN","wpa3_online_attack_6"]="La rete selezionata non è valida. La rete obbiettivo deve essere WPA3 o WPA2/WPA3 in \"Mixed Mode\""
	arr["POLISH","wpa3_online_attack_6"]="Wybrana sieć jest nieprawidłowa. Sieć docelowa musi być w trybie WPA3 lub \"Mixed Mode\" WPA2/WPA3"
	arr["GERMAN","wpa3_online_attack_6"]="Das ausgewählte Netzwerk ist ungültig. Das Zielnetzwerk muss WPA3 oder WPA2/WPA3 im \"Mixed Mode\" sein"
	arr["TURKISH","wpa3_online_attack_6"]="Seçilen ağ geçersiz. Hedef ağ, \"Mixed Mode\" da WPA3 veya WPA2/WPA3 olmalıdır"
	arr["ARABIC","wpa3_online_attack_6"]="\"Mixed Mode\" WPA2/WPA3 او WPA3 الشبكة المحددة غير صالحة. يجب أن تكون الشبكة المستهدفة "
	arr["CHINESE","wpa3_online_attack_6"]="所选网络无效。目标网络必须是 WPA3 加密，或者“混合模式”下的 WPA2/WPA3"

	arr["ENGLISH","wpa3_online_attack_7"]="This attack requires to have python3.1+ installed on your system"
	arr["SPANISH","wpa3_online_attack_7"]="Este ataque requiere tener python3.1+ instalado en el sistema"
	arr["FRENCH","wpa3_online_attack_7"]="Cette attaque a besoin de python3.1+ installé sur le système"
	arr["CATALAN","wpa3_online_attack_7"]="Aquest atac requereix tenir python3.1+ instal·lat al sistema"
	arr["PORTUGUESE","wpa3_online_attack_7"]="Este ataque necessita do python3.1+ instalado no sistema"
	arr["RUSSIAN","wpa3_online_attack_7"]="Для этой атаки необходимо, чтобы в системе был установлен python3.1+"
	arr["GREEK","wpa3_online_attack_7"]="Αυτή η επίθεση απαιτεί την εγκατάσταση python3.1+ στο σύστημά σας"
	arr["ITALIAN","wpa3_online_attack_7"]="Questo attacco richiede che python3.1+ sia installato nel sistema"
	arr["POLISH","wpa3_online_attack_7"]="Ten atak wymaga zainstalowania w systemie python3.1+"
	arr["GERMAN","wpa3_online_attack_7"]="Für diesen Angriff muss python3.1+ auf dem System installiert sein"
	arr["TURKISH","wpa3_online_attack_7"]="Bu saldırı için sisteminizde, python3.1+'ün kurulu olmasını gereklidir"
	arr["ARABIC","wpa3_online_attack_7"]="على النظام python3.1+ يتطلب هذا الهجوم تثبيت"
	arr["CHINESE","wpa3_online_attack_7"]="此攻击需要在您的系统上安装 python3.1+"

	arr["ENGLISH","wpa3_online_attack_8"]="The python3 script required as part of this plugin to run this attack is missing. Please make sure that the file \"\${normal_color}wpa3_online_attack.py\${red_color}\" exists and that it is in the plugins dir next to the \"\${normal_color}wpa3_online_attack.sh\${red_color}\" file"
	arr["SPANISH","wpa3_online_attack_8"]="El script de python3 requerido como parte de este plugin para ejecutar este ataque no se encuentra. Por favor, asegúrate de que existe el fichero \"\${normal_color}wpa3_online_attack.py\${red_color}\" y que está en la carpeta de plugins junto al fichero \"\${normal_color}wpa3_online_attack.sh\${red_color}\""
	arr["FRENCH","wpa3_online_attack_8"]="Le script de python3 requis dans cet plugin pour exécuter cette attaque est manquant. Assurez-vous que le fichier \"\${normal_color}wpa3_online_attack.py\${red_color}\" existe et qu'il se trouve dans le dossier plugins à côté du fichier \"\${normal_color}wpa3_online_attack.sh\${red_color}\""
	arr["CATALAN","wpa3_online_attack_8"]="El script de python3 requerit com a part d'aquest plugin per executar aquest atac no es troba. Assegureu-vos que existeix el fitxer \"\${normal_color}wpa3_online_attack.py\${red_color}\" i que està a la carpeta de plugins al costat del fitxer \"\${normal_color}wpa3_online_attack.sh\${red_color}\""
	arr["PORTUGUESE","wpa3_online_attack_8"]="O arquivo python para executar este ataque está ausente. Verifique se o arquivo \"\${normal_color}wpa3_online_attack.py\${red_color}\" existe e se está na pasta de plugins com o arquivo \"\${normal_color}wpa3_online_attack.sh\${red_color}\""
	arr["RUSSIAN","wpa3_online_attack_8"]="Скрипт, необходимый этому плагину для запуска этой атаки, отсутствует. Убедитесь, что файл \"\${normal_color}wpa3_online_attack.py\${red_color}\" существует и находится в папке для плагинов рядом с файлом \"\${normal_color}wpa3_online_attack.sh\${red_color}\"."
	arr["GREEK","wpa3_online_attack_8"]="Το python3 script που απαιτείται ως μέρος αυτής της προσθήκης για την εκτέλεση αυτής της επίθεσης λείπει. Βεβαιωθείτε ότι το αρχείο \"\${normal_color}wpa3_online_attack.py\${red_color}\" υπάρχει και ότι βρίσκεται στον φάκελο plugins δίπλα στο αρχείο \"\${normal_color}wpa3_online_attack.sh\${red_color}\""
	arr["ITALIAN","wpa3_online_attack_8"]="Lo script python3 richiesto come parte di questo plugin per eseguire questo attacco è assente. Assicurati che il file \"\${normal_color}wpa3_online_attack.py\${red_color}\" esista e che sia nella cartella dei plugin assieme al file \"\${normal_color}wpa3_online_attack.sh\${red_color}\""
	arr["POLISH","wpa3_online_attack_8"]="Do uruchomienia tego ataku brakuje skryptu python3 wymaganego jako część pluginu. Upewnij się, że plik \"\${normal_color}wpa3_online_attack.py\${red_color}\" istnieje i znajduje się w folderze pluginów obok pliku \"\${normal_color}wpa3_online_attack.sh\${red_color}\""
	arr["GERMAN","wpa3_online_attack_8"]="Das python3-Skript, das als Teil dieses Plugins erforderlich ist, um diesen Angriff auszuführen, fehlt. Bitte stellen Sie sicher, dass die Datei \"\${normal_color}wpa3_online_attack.py\${red_color}\" vorhanden ist und dass sie sich im Plugin-Ordner neben der Datei \"\${normal_color}wpa3_online_attack.sh\${red_color}\" befindet"
	arr["TURKISH","wpa3_online_attack_8"]="Bu saldırıyı çalıştırmak için bu eklentinin bir parçası olarak gereken python3 komutu dosyası eksik. Lütfen, eklentiler klasöründe \"\${normal_color}wpa3_online_attack.sh\${red_color}\" dosyasının yanında, \"\${normal_color}wpa3_online_attack.py\${red_color}\" dosyasının da var olduğundan emin olun"
	arr["ARABIC","wpa3_online_attack_8"]="\"\${normal_color}wpa3_online_attack.sh\${red_color}\" موجود وأنه موجود في مجلد المكونات الإضافية بجوار الملف \"\${normal_color}wpa3_online_attack.py\${red_color}\" المطلوب كجزء من هذا البرنامج المساعد لتشغيل هذا الهجوم مفقود. يرجى التأكد من أن الملف pyhton3 سكربت"
	arr["CHINESE","wpa3_online_attack_8"]="作为此插件的一部分运行此攻击所需的 python3 脚本丢失。请确保文件 \"\${normal_color}wpa3_online_attack.py\${red_color}\" 存在，并且位于 \"\${normal_color}wpa3_online_attack.sh\${red_color}\" 旁边的插件目录中 文件"

	arr["ENGLISH","wpa3_online_attack_9"]="The precompiled custom wpa_supplicant binary file needed to execute this attack is missing. Please make sure that the binary according to your processor architecture exists in the \"\${normal_color}wpa_supplicant_binaries\${red_color}\" dir which is inside the plugins dir"
	arr["SPANISH","wpa3_online_attack_9"]="El fichero binario personalizado y precompilado de wpa_supplicant necesario para ejecutar este ataque no se encuentra. Por favor, asegúrate de que existe el binario acorde a to arquitectura de procesador existe en la carpeta \"\${normal_color}wpa_supplicant_binaries\${red_color}\" dentro de la carpeta de plugins"
	arr["FRENCH","wpa3_online_attack_9"]="Le fichier binaire personnalisé précompilé de wpa_supplicant nécessaire pour exécuter cette attaque est manquant. Assurez-vous que le binaire correspondant à l'architecture de votre processeur existe dans le dossier \"\${normal_color}wpa_supplicant_binaries\${red_color}\" à l'intérieur du dossier des plugins"
	arr["CATALAN","wpa3_online_attack_9"]="El fitxer binari personalitzat i precompilat de wpa_supplicant necessari per executar aquest atac no es troba. Assegureu-vos que existeix el binari d'acord amb l'arquitectura de processador a la carpeta \"\${normal_color}wpa_supplicant_binaries\${red_color}\" dins de la carpeta de connectors"
	arr["PORTUGUESE","wpa3_online_attack_9"]="O arquivo pré-compilado do wpa_supplicant está ausente. Certifique-se de que o binário \"\${normal_color}wpa_supplicant_binaries\${red_color}\" de acordo com a arquitetura do seu processador exista dentro da pasta de plugins"
	arr["RUSSIAN","wpa3_online_attack_9"]="Пользовательский wpa_supplicant, необходимый для выполнения этой атаки, отсутствует. Убедитесь, что файл, соответствующий архитектуре вашего процессора, существует в папке \"\${normal_color}wpa_supplicant_binaries\${red_color}\" внутри папки для плагинов."
	arr["GREEK","wpa3_online_attack_9"]="Το προμεταγλωττισμένο προσαρμοσμένο δυαδικό αρχείο του wpa_supplicant που απαιτείται για την εκτέλεση αυτής της επίθεσης λείπει. Βεβαιωθείτε ότι το δυαδικό αρχείο σύμφωνα με την αρχιτεκτονική του επεξεργαστή σας υπάρχει στο φάκελο \"\${normal_color}wpa_supplicant_binaries\${red_color}\" μέσα στο φάκελο plugins"
	arr["ITALIAN","wpa3_online_attack_9"]="Manca il file personalizzato e precompilato di wpa_supplicant necessario per eseguire questo attacco. Assicurati che il file appropiato in base all'architettura del tuo processore esista nella cartella \"\${normal_color}wpa_supplicant_binaries\${red_color}\" all'interno della cartella dei plugin"
	arr["POLISH","wpa3_online_attack_9"]="Brakuje prekompilowanego niestandardowego pliku binarnego wpa_supplicant potrzebnego do wykonania tego ataku. Upewnij się, że plik binarny zgodnie z architekturą twojego procesora znajduje się w folderze pluginów \"\${normal_color}wpa_supplicant_binaries\${red_color}\""
	arr["GERMAN","wpa3_online_attack_9"]="Die vorkompilierte benutzerdefinierte Binärdatei von wpa_supplicant, die zur Ausführung dieses Angriffs benötigt wird, fehlt. Bitte stellen Sie sicher, dass die Binärdatei entsprechend Ihrer Prozessorarchitektur im Ordner \"\${normal_color}wpa_supplicant_binaries\${red_color}\" innerhalb des Plugins-Ordners vorhanden ist"
	arr["TURKISH","wpa3_online_attack_9"]="Bu saldırıyı gerçekleştirmek için gereken wpa_supplicant'ın önceden derlenmiş özel ikili dosyası eksik. Lütfen işlemci mimarinize göre bu ikili dosyanın, eklentiler klasörünün içindeki \"\${normal_color}wpa_supplicant_binaries\${red_color}\" klasöründe bulunduğundan emin olun"
	arr["ARABIC","wpa3_online_attack_9"]="داخل مجلد المكونات الإضافية \"\${normal_color}wpa_supplicant_binaries\${red_color}\" المطلوب لتنفيذ هذا الهجوم مفقود. الرجاء التأكد من وجود الملف الثنائي وفقًا لبنية المعالج في المجلد wpa_supplicant الملف الثنائي المخصص المترجم مسبقًا لـ"
	arr["CHINESE","wpa3_online_attack_9"]="执行此攻击所需的预编译自定义 wpa_supplicant 二进制文件丢失。请确保符合您的处理器架构的二进制文件存在于插件目录内的 \"\${normal_color}wpa_supplicant_binaries\${red_color}\" 目录中"

	arr["ENGLISH","wpa3_online_attack_10"]="To launch this attack, the card must be in \"Managed\" mode. It has been detected that your card is in \"Monitor\" mode, so airgeddon will automatically change it to be able to carry out the attack"
	arr["SPANISH","wpa3_online_attack_10"]="Para lanzar este ataque es necesario que la tarjeta esté en modo \"Managed\". Se ha detectado que tu tarjeta está en modo \"Monitor\" por lo que airgeddon la cambiará automáticamente para poder realizar el ataque"
	arr["FRENCH","wpa3_online_attack_10"]="Pour lancer cette attaque, la carte doit être en mode \"Managed\". Il a été détecté que votre carte est en mode \"Monitor\", donc airgeddon la changera automatiquement pour pouvoir mener l'attaque"
	arr["CATALAN","wpa3_online_attack_10"]="Per llançar aquest atac cal que la targeta estigui en mode \"Managed\". S'ha detectat que la teva targeta està en mode \"Monitor\" pel que airgeddon la canviarà automàticament per poder realitzar l'atac"
	arr["PORTUGUESE","wpa3_online_attack_10"]="Para iniciar este ataque a interface deve estar no modo \"Managed\". Foi detectado que sua interface está no modo \"Monitor\", o airgeddon irá alterá-la automaticamente para poder prosseguir com o ataque"
	arr["RUSSIAN","wpa3_online_attack_10"]="Для запуска этой атаки сетевая карта должна находиться в режиме \"Managed\". Ваша карта находится в режиме \"Monitor\", airgeddon автоматически поменяет режим, чтобы иметь возможность провести атаку"
	arr["GREEK","wpa3_online_attack_10"]="Για να ξεκινήσει αυτή η επίθεση, η κάρτα πρέπει να βρίσκεται σε λειτουργία \"Managed\". Έχει εντοπιστεί ότι η κάρτα σας βρίσκεται σε λειτουργία \"Monitor\", επομένως το airgeddon θα την αλλάξει αυτόματα για να μπορέσει να πραγματοποιήσει την επίθεση"
	arr["ITALIAN","wpa3_online_attack_10"]="Per lanciare questo attacco, la scheda deve essere in modalità \"Managed\". È stato rilevato che la tua scheda è in modalità \"Monitor\", quindi airgeddon la cambierà automaticamente per poter eseguire l'attacco"
	arr["POLISH","wpa3_online_attack_10"]="Aby przeprowadzić ten atak, karta musi być w trybie \"Managed\". Wykryto, że twoja karta jest w trybie \"Monitor\", więc aby móc przeprowadzić atak airgeddon automatycznie go zmieni"
	arr["GERMAN","wpa3_online_attack_10"]="Um diesen Angriff zu starten, muss sich die Karte im \"Managed\"-Modus befinden. Es wurde festgestellt, dass Ihre Karte im \"Monitor\"-Modus ist, also wird airgeddon sie automatisch ändern, um den Angriff ausführen zu können"
	arr["TURKISH","wpa3_online_attack_10"]="Bu saldırıyı başlatmak için kartın \"Managed\" modunda olması gerekir. Kartınızın \"Monitor\" modunda olduğu tespit edildi, bu nedenle airgeddon saldırıyı gerçekleştirebilmek için kartı otomatik olarak değiştirecektir."
	arr["ARABIC","wpa3_online_attack_10"]="تلقائيًا لتتمكن من تنفيذ الهجوم airgeddon لذلك سيغيرها ,\"Monitor\" تم اكتشاف أن شريحتك في وضع .\"Managed\" لبدء هذا الهجوم ، يجب أن تكون الشريحتك في وضع"
	arr["CHINESE","wpa3_online_attack_10"]="要发起此攻击，该卡必须处于“管理”模式。检测到您的卡处于“监听”模式，因此 airgeddon 会自动更改它以能够进行攻击"
}

#Override initialize_menu_and_print_selections function to add the new WPA3 menu
function wpa3_online_attack_override_initialize_menu_and_print_selections() {

	debug_print

	forbidden_options=()

	case ${current_menu} in
		"wpa3_attacks_menu")
			print_iface_selected
			print_all_target_vars
			if [ -n "${DICTIONARY}" ]; then
				language_strings "${language}" 182 "blue"
			fi
		;;
		"main_menu")
			print_iface_selected
		;;
		"decrypt_menu")
			print_decrypt_vars
		;;
		"personal_decrypt_menu")
			print_personal_decrypt_vars
		;;
		"enterprise_decrypt_menu")
			print_enterprise_decrypt_vars
			enterprise_asleap_challenge=""
			enterprise_asleap_response=""
		;;
		"handshake_pmkid_tools_menu")
			print_iface_selected
			print_all_target_vars
			return_to_handshake_pmkid_tools_menu=0
		;;
		"dos_attacks_menu")
			dos_pursuit_mode=0
			print_iface_selected
			print_all_target_vars
		;;
		"dos_handshake_menu")
			print_iface_selected
			print_all_target_vars
		;;
		"language_menu")
			print_iface_selected
		;;
		"evil_twin_attacks_menu")
			enterprise_mode=""
			return_to_et_main_menu=0
			return_to_enterprise_main_menu=0
			retry_handshake_capture=0
			return_to_et_main_menu_from_beef=0
			retrying_handshake_capture=0
			internet_interface_selected=0
			et_mode=""
			et_processes=()
			secondary_wifi_interface=""
			et_attack_adapter_prerequisites_ok=0
			print_iface_selected
			print_all_target_vars_et
		;;
		"enterprise_attacks_menu")
			return_to_enterprise_main_menu=0
			return_to_et_main_menu=0
			enterprise_mode=""
			et_processes=()
			secondary_wifi_interface=""
			et_enterprise_attack_adapter_prerequisites_ok=0
			print_iface_selected
			print_all_target_vars
		;;
		"et_dos_menu")
			dos_pursuit_mode=0
			print_iface_selected
			if [ -n "${enterprise_mode}" ]; then
				print_all_target_vars
			else
				if [ "${retry_handshake_capture}" -eq 1 ]; then
					retry_handshake_capture=0
					retrying_handshake_capture=1
				fi
				print_et_target_vars
				print_iface_internet_selected
			fi
		;;
		"wps_attacks_menu")
			print_iface_selected
			print_all_target_vars_wps
		;;
		"offline_pin_generation_menu")
			print_iface_selected
			print_all_target_vars_wps
		;;
		"wep_attacks_menu")
			print_iface_selected
			print_all_target_vars
		;;
		"beef_pre_menu")
			et_attack_adapter_prerequisites_ok=0
			print_iface_selected
			print_all_target_vars_et
		;;
		"option_menu")
			print_options
		;;
		*)
			print_iface_selected
			print_all_target_vars
		;;
	esac
}

#Override print_hint function to print custom messages related to WPA3 on WPA3 menu
function wpa3_online_attack_override_print_hint() {

	debug_print

	declare -A hints

	declare wpa3_hints=(128 134 437 438 442 445 516 590 626 660 697 699 "wpa3_online_attack_5")

	case ${1} in
		"wpa3_attacks_menu")
			store_array hints wpa3_hints "${wpa3_hints[@]}"
			hintlength=${#wpa3_hints[@]}
			((hintlength--))
			randomhint=$(shuf -i 0-"${hintlength}" -n 1)
			strtoprint=${hints[wpa3_hints|${randomhint}]}
		;;
		"main_menu")
			store_array hints main_hints "${main_hints[@]}"
			hintlength=${#main_hints[@]}
			((hintlength--))
			randomhint=$(shuf -i 0-"${hintlength}" -n 1)
			strtoprint=${hints[main_hints|${randomhint}]}
		;;
		"dos_attacks_menu")
			store_array hints dos_hints "${dos_hints[@]}"
			hintlength=${#dos_hints[@]}
			((hintlength--))
			randomhint=$(shuf -i 0-"${hintlength}" -n 1)
			strtoprint=${hints[dos_hints|${randomhint}]}
		;;
		"handshake_pmkid_tools_menu")
			store_array hints handshake_pmkid_hints "${handshake_pmkid_hints[@]}"
			hintlength=${#handshake_pmkid_hints[@]}
			((hintlength--))
			randomhint=$(shuf -i 0-"${hintlength}" -n 1)
			strtoprint=${hints[handshake_pmkid_hints|${randomhint}]}
		;;
		"dos_handshake_menu")
			store_array hints dos_handshake_hints "${dos_handshake_hints[@]}"
			hintlength=${#dos_handshake_hints[@]}
			((hintlength--))
			randomhint=$(shuf -i 0-"${hintlength}" -n 1)
			strtoprint=${hints[dos_handshake_hints|${randomhint}]}
		;;
		"decrypt_menu")
			store_array hints decrypt_hints "${decrypt_hints[@]}"
			hintlength=${#decrypt_hints[@]}
			((hintlength--))
			randomhint=$(shuf -i 0-"${hintlength}" -n 1)
			strtoprint=${hints[decrypt_hints|${randomhint}]}
		;;
		"personal_decrypt_menu")
			store_array hints personal_decrypt_hints "${personal_decrypt_hints[@]}"
			hintlength=${#personal_decrypt_hints[@]}
			((hintlength--))
			randomhint=$(shuf -i 0-"${hintlength}" -n 1)
			strtoprint=${hints[personal_decrypt_hints|${randomhint}]}
		;;
		"enterprise_decrypt_menu")
			store_array hints enterprise_decrypt_hints "${enterprise_decrypt_hints[@]}"
			hintlength=${#enterprise_decrypt_hints[@]}
			((hintlength--))
			randomhint=$(shuf -i 0-"${hintlength}" -n 1)
			strtoprint=${hints[enterprise_decrypt_hints|${randomhint}]}
		;;
		"select_interface_menu")
			store_array hints select_interface_hints "${select_interface_hints[@]}"
			hintlength=${#select_interface_hints[@]}
			((hintlength--))
			randomhint=$(shuf -i 0-"${hintlength}" -n 1)
			strtoprint=${hints[select_interface_hints|${randomhint}]}
		;;
		"language_menu")
			store_array hints language_hints "${language_hints[@]}"
			hintlength=${#language_hints[@]}
			((hintlength--))
			randomhint=$(shuf -i 0-"${hintlength}" -n 1)
			strtoprint=${hints[language_hints|${randomhint}]}
		;;
		"option_menu")
			store_array hints option_hints "${option_hints[@]}"
			hintlength=${#option_hints[@]}
			((hintlength--))
			randomhint=$(shuf -i 0-"${hintlength}" -n 1)
			strtoprint=${hints[option_hints|${randomhint}]}
		;;
		"evil_twin_attacks_menu")
			store_array hints evil_twin_hints "${evil_twin_hints[@]}"
			hintlength=${#evil_twin_hints[@]}
			((hintlength--))
			randomhint=$(shuf -i 0-"${hintlength}" -n 1)
			strtoprint=${hints[evil_twin_hints|${randomhint}]}
		;;
		"et_dos_menu")
			store_array hints evil_twin_dos_hints "${evil_twin_dos_hints[@]}"
			hintlength=${#evil_twin_dos_hints[@]}
			((hintlength--))
			randomhint=$(shuf -i 0-"${hintlength}" -n 1)
			strtoprint=${hints[evil_twin_dos_hints|${randomhint}]}
		;;
		"wps_attacks_menu"|"offline_pin_generation_menu")
			store_array hints wps_hints "${wps_hints[@]}"
			hintlength=${#wps_hints[@]}
			((hintlength--))
			randomhint=$(shuf -i 0-"${hintlength}" -n 1)
			strtoprint=${hints[wps_hints|${randomhint}]}
		;;
		"wep_attacks_menu")
			store_array hints wep_hints "${wep_hints[@]}"
			hintlength=${#wep_hints[@]}
			((hintlength--))
			randomhint=$(shuf -i 0-"${hintlength}" -n 1)
			strtoprint=${hints[wep_hints|${randomhint}]}
		;;
		"beef_pre_menu")
			store_array hints beef_hints "${beef_hints[@]}"
			hintlength=${#beef_hints[@]}
			((hintlength--))
			randomhint=$(shuf -i 0-"${hintlength}" -n 1)
			strtoprint=${hints[beef_hints|${randomhint}]}
		;;
		"enterprise_attacks_menu")
			store_array hints enterprise_hints "${enterprise_hints[@]}"
			hintlength=${#enterprise_hints[@]}
			((hintlength--))
			randomhint=$(shuf -i 0-"${hintlength}" -n 1)
			strtoprint=${hints[enterprise_hints|${randomhint}]}
		;;
	esac

	if "${AIRGEDDON_PRINT_HINTS:-true}"; then
		print_simple_separator
		language_strings "${language}" "${strtoprint}" "hint"
	fi
	print_simple_separator
}

#Override main_menu function to add the new WPA3 attack category
function wpa3_online_attack_override_main_menu() {

	debug_print

	clear
	language_strings "${language}" 101 "title"
	current_menu="main_menu"
	initialize_menu_and_print_selections
	echo
	language_strings "${language}" 47 "green"
	print_simple_separator
	language_strings "${language}" 61
	language_strings "${language}" 48
	language_strings "${language}" 55
	language_strings "${language}" 56
	print_simple_separator
	language_strings "${language}" 118
	language_strings "${language}" 119
	language_strings "${language}" 169
	language_strings "${language}" 252
	language_strings "${language}" 333
	language_strings "${language}" 426
	language_strings "${language}" 57
	language_strings "${language}" "wpa3_online_attack_1"
	print_simple_separator
	language_strings "${language}" 60
	language_strings "${language}" 444
	print_hint ${current_menu}

	read -rp "> " main_option
	case ${main_option} in
		0)
			exit_script_option
		;;
		1)
			select_interface
		;;
		2)
			monitor_option "${interface}"
		;;
		3)
			managed_option "${interface}"
		;;
		4)
			dos_attacks_menu
		;;
		5)
			handshake_pmkid_tools_menu
		;;
		6)
			decrypt_menu
		;;
		7)
			evil_twin_attacks_menu
		;;
		8)
			wps_attacks_menu
		;;
		9)
			wep_attacks_menu
		;;
		10)
			enterprise_attacks_menu
		;;
		11)
			wpa3_attacks_menu
		;;
		12)
			credits_option
		;;
		13)
			option_menu
		;;
		*)
			invalid_menu_option
		;;
	esac

	main_menu
}

#Posthook clean_tmpfiles function to remove temp wpa3 attack files on exit
function wpa3_online_attack_posthook_clean_tmpfiles() {

	rm -rf "${tmpdir}agwpa3"* > /dev/null 2>&1
}
