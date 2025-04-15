#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

plugin_name="WPA3 online attack"
plugin_description="A plugin to perform a dictionary online attack over WPA3 wireless networks"
plugin_author="OscarAkaElvis"

#This plugin is based in the Wacker script. Credits to the authors: https://github.com/blunderbuss-wctf/wacker

plugin_enabled=1

plugin_minimum_ag_affected_version="11.50"
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
				custom_wpa_supplicant_binary_path="${scriptfolder}${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_armhf"
			fi
		elif uname -m | grep -Ei "aarch64|aarch64_be|armv8b|armv8l" > /dev/null; then
			if ! [ -f "${scriptfolder}${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_arm64" ]; then
				echo
				language_strings "${language}" "wpa3_online_attack_9" "red"
				language_strings "${language}" 115 "read"
				return 1
			else
				custom_wpa_supplicant_binary_path="${scriptfolder}${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_arm64"
			fi
		else
			if ! [ -f "${scriptfolder}${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_armel" ]; then
				echo
				language_strings "${language}" "wpa3_online_attack_9" "red"
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
				language_strings "${language}" "wpa3_online_attack_9" "red"
				language_strings "${language}" 115 "read"
				return 1
			else
				custom_wpa_supplicant_binary_path="${scriptfolder}${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_amd64"
			fi
		else
			if ! [ -f "${scriptfolder}${plugins_dir}${custom_wpa_supplicant_binaries_dir}wpa_supplicant_i386" ]; then
				echo
				language_strings "${language}" "wpa3_online_attack_9" "red"
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
		echo -e "${arr[${language},"wpa3_online_attack_12"]}"
		echo ""
		echo -e "BSSID: ${bssid}"
		echo -e "${arr[${language},"wpa3_online_attack_13"]}: ${channel}"
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
		language_strings "${language}" "wpa3_online_attack_14" "blue"
		language_strings "${language}" 115 "read"
	fi
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

	aircrack_wpa3_version="1.7"
	get_aircrack_version

	if compare_floats_greater_than "${aircrack_wpa3_version}" "${aircrack_version}"; then
		echo
		language_strings "${language}" "wpa3_online_attack_15" "red"
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
		language_strings "${language}" "wpa3_online_attack_10" "yellow"
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

	if ! python3_validation; then
		return 1
	fi

	if ! python3_script_validation; then
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

#Custom function. Check if the password was captured using wpa3 online dictionary attack and manage to save it on a file
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

#Prehook for hookable_for_languages function to modify language strings
#shellcheck disable=SC1111
function wpa3_online_attack_prehook_hookable_for_languages() {

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
	arr["ARABIC","wpa3_online_attack_6"]="\"Mixed Mode\" WPA2/WPA3 او WPA3 الشبكة المحددة غير صالحة. يجب أن تكون الشبكة المستهدفة"
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

	arr["ENGLISH","wpa3_online_attack_11"]="If the password for the wifi network is obtained with the WPA3 attack, you should decide where to save it. \${green_color}Type the path to store the file or press [Enter] to accept the default proposal \${normal_color}[\${wpa3_potpath}]"
	arr["SPANISH","wpa3_online_attack_11"]="Si se consigue la contraseña de la red wifi con el ataque WPA3, hay que decidir donde guardarla. \${green_color}Escribe la ruta donde guardaremos el fichero o pulsa [Enter] para aceptar la propuesta por defecto \${normal_color}[\${wpa3_potpath}]"
	arr["FRENCH","wpa3_online_attack_11"]="Si le mot de passe est obtenu par une attaque WPA3, il faut ensuite indiquer l'endroit pour la garder. \${green_color}Entrez la route vers l'endroit où vous voulez garder le fichier ou bien appuyez sur [Enter] si la route proposée par défaut vous convient \${normal_color}[\${wpa3_potpath}]"
	arr["CATALAN","wpa3_online_attack_11"]="Si s'aconsegueix la contrasenya de la xarxa wifi amb l'atac WPA3, cal decidir on guardar-la. \${green_color}Escriu la ruta on guardarem el fitxer o prem [Enter] per acceptar la proposta per defecte \${normal_color}[\${wpa3_potpath}]"
	arr["PORTUGUESE","wpa3_online_attack_11"]="Se a senha da rede wifi for obtida com o ataque WPA3, onde deseja salvá-la?. \${green_color}Digite o caminho onde armazenar o arquivo ou pressione [Enter] para aceitar o padrão \${normal_color}[\${wpa3_potpath}]"
	arr["RUSSIAN","wpa3_online_attack_11"]="Если во время WPA3 атаки на Wi-Fi сеть получен пароль, вы должны решить, где его сохранить. \${green_color} Наберите путь для сохранения файла или нажмите [Enter] для принятия значения по умолчанию \${normal_color}[\${wpa3_potpath}]"
	arr["GREEK","wpa3_online_attack_11"]="Εάν βρεθεί ο κωδικός πρόσβασης για το ασύρματο δίκτυο με την επίθεση WPA3, θα πρέπει να αποφασίσετε που θα τον αποθηκεύσετε. \${green_color}Πληκτρολογήστε το μονοπάτι για την αποθήκευση του αρχείου ή πατήστε [Enter] για την προεπιλεγμένη επιλογή \${normal_color}[\${wpa3_potpath}]"
	arr["ITALIAN","wpa3_online_attack_11"]="Se si ottiene la password della rete wireless con l'attacco WPA3, decidere dove salvarla. \${green_color}Immettere il percorso dove memorizzare il file o premere [Enter] per accettare la proposta di default \${normal_color}[\${wpa3_potpath}]"
	arr["POLISH","wpa3_online_attack_11"]="Jeśli hasło sieci wifi zostanie zdobyte atakiem WPA3, musisz zdecydować, gdzie je zapisać. \${green_color}Wpisz ścieżkę, w której będziemy zapisywać plik lub naciśnij [Enter], aby zaakceptować domyślną propozycję \${normal_color}[\${wpa3_potpath}]"
	arr["GERMAN","wpa3_online_attack_11"]="Wenn Sie das WLAN-Passwort mit dem WPA3-Angriff erhalten, müssen Sie entscheiden, wo Sie es speichern möchten. \${green_color} Geben Sie den Pfad ein, unter dem die Datei gespeichert werden soll, oder drücken Sie die [Enter]-Taste, um den Standardvorschlag \${normal_color}[\${wpa3_potpath}] \${blue_color}zu akzeptieren"
	arr["TURKISH","wpa3_online_attack_11"]="Kablosuz ağın şifresi WPA3 saldırısıyla elde edilirse, nereye kaydedeceğinize karar vermelisiniz. \${green_color}Dosyayı depolamak için yolu yazın veya varsayılan teklifi kabul etmek için [Enter] tuşuna basın \${normal_color}[\${wpa3_potpath}]"
	arr["ARABIC","wpa3_online_attack_11"]="\${normal_color}[\${wpa3_potpath}]\${green_color} لقبول الاقتراح [Enter] فيجب أن تقرر مكان حفظها \${blue_color}.اكتب المسار لتخزين الملف أو اضغط على ،WPA3 بهجوم wifi إذا تم الحصول على كلمة المرور لشبكة\${normal_color}"
	arr["CHINESE","wpa3_online_attack_11"]="如果 wifi 网络的密码是通过 WPA3 攻击获得的，您应该决定将其保存在何处。 \${green_color}键入存储文件的路径或按 [Enter] 接受默认建议 \${normal_color}[\${wpa3_potpath}]"

	arr["ENGLISH","wpa3_online_attack_12"]="airgeddon. Decrypted password during WPA3 attack"
	arr["SPANISH","wpa3_online_attack_12"]="airgeddon. Contraseña descifrada en ataque WPA3"
	arr["FRENCH","wpa3_online_attack_12"]="airgeddon. Mot de passe déchiffré à l'aide de l'attaque WPA3"
	arr["CATALAN","wpa3_online_attack_12"]="airgeddon. Contrasenya desxifrada amb l'atac WPA3"
	arr["PORTUGUESE","wpa3_online_attack_12"]="airgeddon. Senha decifrada no ataque WPA3"
	arr["RUSSIAN","wpa3_online_attack_12"]="airgeddon. Пароль расшифрован во время WPA3 атаки"
	arr["GREEK","wpa3_online_attack_12"]="airgeddon. Ο κωδικός αποκρυπτογραφήθηκε κατά την επίθεση WPA3"
	arr["ITALIAN","wpa3_online_attack_12"]="airgeddon. Password decifrata con l'attacco WPA3"
	arr["POLISH","wpa3_online_attack_12"]="airgeddon. Hasło odszyfrowane w ataku WPA3"
	arr["GERMAN","wpa3_online_attack_12"]="airgeddon. Passwort während WPA3-Angriff entschlüsselt"
	arr["TURKISH","wpa3_online_attack_12"]="airgeddon. WPA3 saldırısı sırasında çözülen şifre"
	arr["ARABIC","wpa3_online_attack_12"]="WPA3 فك تشفير كلمة السر أثناء هجوم .airgeddon"
	arr["CHINESE","wpa3_online_attack_12"]="airgeddon WPA3 攻击期间解密的密码"

	arr["ENGLISH","wpa3_online_attack_13"]="Channel"
	arr["SPANISH","wpa3_online_attack_13"]="Canal"
	arr["FRENCH","wpa3_online_attack_13"]="Canal"
	arr["CATALAN","wpa3_online_attack_13"]="Canal"
	arr["PORTUGUESE","wpa3_online_attack_13"]="Canal"
	arr["RUSSIAN","wpa3_online_attack_13"]="Канал"
	arr["GREEK","wpa3_online_attack_13"]="Κανάλι"
	arr["ITALIAN","wpa3_online_attack_13"]="Canale"
	arr["POLISH","wpa3_online_attack_13"]="Kanał"
	arr["GERMAN","wpa3_online_attack_13"]="Kanal"
	arr["TURKISH","wpa3_online_attack_13"]="Kanal"
	arr["ARABIC","wpa3_online_attack_13"]="قناة"
	arr["CHINESE","wpa3_online_attack_13"]="信道"

	arr["ENGLISH","wpa3_online_attack_14"]="WPA3 key decrypted successfully. The password was saved on file [\${normal_color}\${wpa3potenteredpath}\${blue_color}]"
	arr["SPANISH","wpa3_online_attack_14"]="Clave WPA3 descifrada con éxito. La contraseña se ha guardado en el fichero [\${normal_color}\${wpa3potenteredpath}\${blue_color}]"
	arr["FRENCH","wpa3_online_attack_14"]="Clé WPA3 déchiffré. Le mot de passe est enregistré dans le fichier [\${normal_color}\${wpa3potenteredpath}\${blue_color}]"
	arr["CATALAN","wpa3_online_attack_14"]="Clau WPA3 desxifrada amb èxit. La contrasenya s'ha guardat en el fitxer [\${normal_color}\${wpa3potenteredpath}\${blue_color}]"
	arr["PORTUGUESE","wpa3_online_attack_14"]="A senha da rede WPA3 foi descriptografada com sucesso. A senha foi salva no arquivo [\${normal_color}\${wpa3potenteredpath}\${blue_color}]"
	arr["RUSSIAN","wpa3_online_attack_14"]="WPA3 ключ успешно расшифрован. Пароль был сохранён в файле [\${normal_color}\${wpa3potenteredpath}\${blue_color}]"
	arr["GREEK","wpa3_online_attack_14"]="Το κλειδί WPA3 αποκρυπτογραφήθηκε με επιτυχία. Ο κωδικός πρόσβασης αποθηκεύτηκε στο αρχείο [\${normal_color}\${wpa3potenteredpath}\${blue_color}]"
	arr["ITALIAN","wpa3_online_attack_14"]="Chiave WPA3 decifrata con successo. La password è stata salvata nel file [\${normal_color}\${wpa3potenteredpath}\${blue_color}]"
	arr["POLISH","wpa3_online_attack_14"]="Klucz WPA3 odszyfrowywany prawidłowo. Hasło zostało zapisane do pliku [\${normal_color}\${wpa3potenteredpath}\${blue_color}]"
	arr["GERMAN","wpa3_online_attack_14"]="WPA3-Schlüssel erfolgreich entschlüsselt. Das Passwort wurde in der Datei gespeichert [\${normal_color}\${wpa3potenteredpath}\${blue_color}]"
	arr["TURKISH","wpa3_online_attack_14"]="WPA3 anahtarı başarıyla çözüldü. Şifre dosyaya kaydedildi [\${normal_color}\${wpa3potenteredpath}\${blue_color}]"
	arr["ARABIC","wpa3_online_attack_14"]="[\${normal_color}\${wpa3potenteredpath}\${blue_color}] بنجاحز. تم حفظ كلمة المرور في الملف WPA3 تم فك تشفير مفتاح"
	arr["CHINESE","wpa3_online_attack_14"]="WPA3 密钥解密成功。密码已保存至文件 [\${normal_color}\${wpa3potenteredpath}\${blue_color}]"

	arr["ENGLISH","wpa3_online_attack_15"]="An old version of aircrack has been detected. To handle WPA3 networks correctly, at least version \${aircrack_wpa3_version} is required. Otherwise, the attack cannot be performed. Please upgrade your aircrack package to a later version"
	arr["SPANISH","wpa3_online_attack_15"]="Se ha detectado una versión antigua de aircrack. Para manejar redes WPA3 correctamente se requiere como mínimo la versión \${aircrack_wpa3_version}. De lo contrario el ataque no se puede realizar. Actualiza tu paquete de aircrack a una versión posterior"
	arr["FRENCH","wpa3_online_attack_15"]="Une version ancienne d'aircrack a été détectée. Pour gérer correctement les réseaux WPA3, la version \${aircrack_wpa3_version} est requise au moins. Dans le cas contraire, l'attaque ne pourra pas être faire. Mettez à jour votre package d'aircrack à une version ultérieure"
	arr["CATALAN","wpa3_online_attack_15"]="S'ha detectat una versió antiga d'aircrack. Per manejar xarxes WPA3 es requereix com a mínim la versió \${aircrack_wpa3_version} Si no, l'atac no es pot fer. Actualitza el teu paquet d'aircrack a una versió posterior"
	arr["PORTUGUESE","wpa3_online_attack_15"]="Uma versão antiga do aircrack foi detectada. Para lidar corretamente com redes WPA3, é necessário pelo menos a versão \${aircrack_wpa3_version}. Caso contrário o ataque não poderá ser realizado. Atualize seu pacote aircrack para uma versão posterior"
	arr["RUSSIAN","wpa3_online_attack_15"]="Обнаружена старая версия aircrack. Для корректной работы с WPA3 сетями требуется как минимум версия \${aircrack_wpa3_version}. В противном случае атака не может быть осуществлена. Обновите пакет aircrack до более новой версии"
	arr["GREEK","wpa3_online_attack_15"]="Εντοπίστηκε μια παλιά έκδοση του aircrack. Για να χειριστείτε σωστά τα δίκτυα WPA3, απαιτείται τουλάχιστον η έκδοση \${aircrack_wpa3_version}. Διαφορετικά η επίθεση δεν μπορεί να πραγματοποιηθεί. Ενημερώστε το πακέτο aircrack σε νεότερη έκδοση"
	arr["ITALIAN","wpa3_online_attack_15"]="È stata rilevata una versione vecchia di aircrack. Per gestire correttamente le reti WPA3 è richiesta almeno la versione \${aircrack_wpa3_version}, altrimenti l'attacco non può essere eseguito. Aggiorna il tuo pacchetto aircrack ad una versione successiva"
	arr["POLISH","wpa3_online_attack_15"]="Wykryto starą wersję narzędzia aircrack. Aby poprawnie obsługiwać sieci WPA3, wymagana jest co najmniej wersja \${aircrack_wpa3_version}. Inaczej atak nie będzie możliwy. Zaktualizuj pakiet aircrack do nowszej wersji"
	arr["GERMAN","wpa3_online_attack_15"]="Es wurde eine alte Version von Aircrack entdeckt. Für den korrekten Umgang mit WPA3-Netzwerken ist mindestens die Version \${aircrack_wpa3_version} erforderlich. Andernfalls kann der Angriff nicht durchgeführt werden. Aktualisieren Sie Ihr Aircrack-Paket auf eine neuere Version"
	arr["TURKISH","wpa3_online_attack_15"]="aircrack'in eski bir sürümü tespit edildi. WPA3 ağlarını doğru şekilde yönetmek için en az \${aircrack_wpa3_version} sürümü gereklidir. Aksi takdirde saldırı gerçekleştirilemez. Aircrack paketinizi daha sonraki bir sürüme güncelleyin"
	arr["ARABIC","wpa3_online_attack_15"]="إلى إصدار أحدث aircrack  بشكل صحيح. قم بتحديث  WPA3  على الأقل, للتعامل مع شبكات ال \${aircrack_wpa3_version}  يلزم توفر الإصدار  .aircrack تم اكتشاف نسخة قديمة من"
	arr["CHINESE","wpa3_online_attack_15"]="当前aircrack的版本已过期。如果您需要处理 WPA3 加密类型的网络，至少需要版本 \${aircrack_wpa3_version}。否则将无法进行攻击。请尝试将您的aircrack包更新到最高版本"
}

#Override hookable_for_menus function to add the WPA3 menu
function wpa3_online_attack_override_hookable_for_menus() {

	debug_print

	case ${current_menu} in
		"wpa3_attacks_menu")
			print_iface_selected
			print_all_target_vars
			if [ -n "${DICTIONARY}" ]; then
				language_strings "${language}" 182 "blue"
			fi
			return 0
		;;
		*)
			return 1
		;;
	esac
}

#Override hookable_for_hints function to print custom messages related to WPA3 on WPA3 menu
function wpa3_online_attack_override_hookable_for_hints() {

	debug_print

	declare wpa3_hints=(128 134 437 438 442 445 516 590 626 660 697 699 "wpa3_online_attack_5")

	case "${current_menu}" in
		"wpa3_attacks_menu")
			store_array hints wpa3_hints "${wpa3_hints[@]}"
			hintlength=${#wpa3_hints[@]}
			((hintlength--))
			randomhint=$(shuf -i 0-"${hintlength}" -n 1)
			strtoprint=${hints[wpa3_hints|${randomhint}]}
		;;
	esac
}

#Override main_menu function to add the WPA3 attack category
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
			handshake_pmkid_decloaking_tools_menu
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

#Override read_path function to add the WPA3 option
function wpa3_online_attack_override_read_path() {

	debug_print

	echo
	case ${1} in
		"wpa3pot")
			language_strings "${language}" "wpa3_online_attack_11" "blue"
			read_and_clean_path "wpa3potenteredpath"
			if [ -z "${wpa3potenteredpath}" ]; then
				wpa3potenteredpath="${wpa3_potpath}"
			fi
			wpa3potenteredpath=$(set_absolute_path "${wpa3potenteredpath}")
			validate_path "${wpa3potenteredpath}" "${1}"
		;;
		"handshake")
			language_strings "${language}" 148 "green"
			read_and_clean_path "enteredpath"
			if [ -z "${enteredpath}" ]; then
				enteredpath="${handshakepath}"
			fi
			enteredpath=$(set_absolute_path "${enteredpath}")
			validate_path "${enteredpath}" "${1}"
		;;
		"cleanhandshake")
			language_strings "${language}" 154 "green"
			read_and_clean_path "filetoclean"
			check_file_exists "${filetoclean}"
		;;
		"pmkid")
			language_strings "${language}" 674 "green"
			read_and_clean_path "enteredpath"
			if [ -z "${enteredpath}" ]; then
				enteredpath="${pmkidpath}"
			fi
			enteredpath=$(set_absolute_path "${enteredpath}")
			validate_path "${enteredpath}" "${1}"
		;;
		"pmkidcap")
			language_strings "${language}" 686 "green"
			read_and_clean_path "enteredpath"
			if [ -z "${enteredpath}" ]; then
				enteredpath="${pmkidcappath}"
			fi
			enteredpath=$(set_absolute_path "${enteredpath}")
			validate_path "${enteredpath}" "${1}"
		;;
		"dictionary")
			language_strings "${language}" 180 "green"
			read_and_clean_path "DICTIONARY"
			check_file_exists "${DICTIONARY}"
		;;
		"targetfilefordecrypt")
			language_strings "${language}" 188 "green"
			read_and_clean_path "enteredpath"
			check_file_exists "${enteredpath}"
		;;
		"targethashcatpmkidfilefordecrypt")
			language_strings "${language}" 188 "green"
			read_and_clean_path "hashcatpmkidenteredpath"
			check_file_exists "${hashcatpmkidenteredpath}"
		;;
		"targethashcatenterprisefilefordecrypt")
			language_strings "${language}" 188 "green"
			read_and_clean_path "hashcatenterpriseenteredpath"
			check_file_exists "${hashcatenterpriseenteredpath}"
		;;
		"targetjtrenterprisefilefordecrypt")
			language_strings "${language}" 188 "green"
			read_and_clean_path "jtrenterpriseenteredpath"
			check_file_exists "${jtrenterpriseenteredpath}"
		;;
		"rules")
			language_strings "${language}" 242 "green"
			read_and_clean_path "RULES"
			check_file_exists "${RULES}"
		;;
		"aircrackpot")
			language_strings "${language}" 441 "green"
			read_and_clean_path "aircrackpotenteredpath"
			if [ -z "${aircrackpotenteredpath}" ]; then
				aircrackpotenteredpath="${aircrack_potpath}"
			fi
			aircrackpotenteredpath=$(set_absolute_path "${aircrackpotenteredpath}")
			validate_path "${aircrackpotenteredpath}" "${1}"
		;;
		"jtrpot")
			language_strings "${language}" 611 "green"
			read_and_clean_path "jtrpotenteredpath"
			if [ -z "${jtrpotenteredpath}" ]; then
				jtrpotenteredpath="${jtr_potpath}"
			fi
			jtrpotenteredpath=$(set_absolute_path "${jtrpotenteredpath}")
			validate_path "${jtrpotenteredpath}" "${1}"
		;;
		"hashcatpot")
			language_strings "${language}" 233 "green"
			read_and_clean_path "potenteredpath"
			if [ -z "${potenteredpath}" ]; then
				potenteredpath="${hashcat_potpath}"
			fi
			potenteredpath=$(set_absolute_path "${potenteredpath}")
			validate_path "${potenteredpath}" "${1}"
		;;
		"asleappot")
			language_strings "${language}" 555 "green"
			read_and_clean_path "asleapenteredpath"
			if [ -z "${asleapenteredpath}" ]; then
				asleapenteredpath="${asleap_potpath}"
			fi
			asleapenteredpath=$(set_absolute_path "${asleapenteredpath}")
			validate_path "${asleapenteredpath}" "${1}"
		;;
		"ettercaplog")
			language_strings "${language}" 303 "green"
			read_and_clean_path "ettercap_logpath"
			if [ -z "${ettercap_logpath}" ]; then
				ettercap_logpath="${default_ettercap_logpath}"
			fi
			ettercap_logpath=$(set_absolute_path "${ettercap_logpath}")
			validate_path "${ettercap_logpath}" "${1}"
		;;
		"bettercaplog")
			language_strings "${language}" 398 "green"
			read_and_clean_path "bettercap_logpath"
			if [ -z "${bettercap_logpath}" ]; then
				bettercap_logpath="${default_bettercap_logpath}"
			fi
			bettercap_logpath=$(set_absolute_path "${bettercap_logpath}")
			validate_path "${bettercap_logpath}" "${1}"
		;;
		"ethandshake")
			language_strings "${language}" 154 "green"
			read_and_clean_path "et_handshake"
			check_file_exists "${et_handshake}"
		;;
		"writeethandshake")
			language_strings "${language}" 148 "green"
			read_and_clean_path "et_handshake"
			if [ -z "${et_handshake}" ]; then
				et_handshake="${handshakepath}"
			fi
			et_handshake=$(set_absolute_path "${et_handshake}")
			validate_path "${et_handshake}" "${1}"
		;;
		"et_captive_portallog")
			language_strings "${language}" 317 "blue"
			read_and_clean_path "et_captive_portal_logpath"
			if [ -z "${et_captive_portal_logpath}" ]; then
				et_captive_portal_logpath="${default_et_captive_portal_logpath}"
			fi
			et_captive_portal_logpath=$(set_absolute_path "${et_captive_portal_logpath}")
			validate_path "${et_captive_portal_logpath}" "${1}"
		;;
		"wpspot")
			language_strings "${language}" 123 "blue"
			read_and_clean_path "wpspotenteredpath"
			if [ -z "${wpspotenteredpath}" ]; then
				wpspotenteredpath="${wps_potpath}"
			fi
			wpspotenteredpath=$(set_absolute_path "${wpspotenteredpath}")
			validate_path "${wpspotenteredpath}" "${1}"
		;;
		"weppot")
			language_strings "${language}" 430 "blue"
			read_and_clean_path "weppotenteredpath"
			if [ -z "${weppotenteredpath}" ]; then
				weppotenteredpath="${wep_potpath}"
			fi
			weppotenteredpath=$(set_absolute_path "${weppotenteredpath}")
			validate_path "${weppotenteredpath}" "${1}"
		;;
		"enterprisepot")
			language_strings "${language}" 525 "blue"
			read_and_clean_path "enterprisepotenteredpath"
			if [ -z "${enterprisepotenteredpath}" ]; then
				enterprisepotenteredpath="${enterprise_potpath}"
			fi
			enterprisepotenteredpath=$(set_absolute_path "${enterprisepotenteredpath}")
			validate_path "${enterprisepotenteredpath}" "${1}"
		;;
		"certificates")
			language_strings "${language}" 643 "blue"
			read_and_clean_path "certificatesenteredpath"
			if [ -z "${certificatesenteredpath}" ]; then
				certificatesenteredpath="${enterprisecertspath}"
			fi
			certificatesenteredpath=$(set_absolute_path "${certificatesenteredpath}")
			validate_path "${certificatesenteredpath}" "${1}"
		;;
	esac

	validpath="$?"
	return "${validpath}"
}

#Override validate_path function to add the WPA3 option
function wpa3_online_attack_override_validate_path() {

	debug_print

	lastcharmanualpath=${1: -1}

	if [[ "${2}" = "enterprisepot" ]] || [[ "${2}" = "certificates" ]]; then
		dirname=$(dirname "${1}")

		if [ -d "${dirname}" ]; then
			if ! check_write_permissions "${dirname}"; then
				language_strings "${language}" 157 "red"
				return 1
			fi
		else
			if ! dir_permission_check "${1}"; then
				language_strings "${language}" 526 "red"
				return 1
			fi
		fi

		if [ "${lastcharmanualpath}" != "/" ]; then
			pathname="${1}/"
		fi
	else
		dirname=${1%/*}

		if [[ ! -d "${dirname}" ]] || [[ "${dirname}" = "." ]]; then
			language_strings "${language}" 156 "red"
			return 1
		fi

		if ! check_write_permissions "${dirname}"; then
			language_strings "${language}" 157 "red"
			return 1
		fi
	fi

	if [[ "${lastcharmanualpath}" = "/" ]] || [[ -d "${1}" ]] || [[ "${2}" = "enterprisepot" ]] || [[ "${2}" = "certificates" ]]; then
		if [ "${lastcharmanualpath}" != "/" ]; then
			pathname="${1}/"
		else
			pathname="${1}"
		fi

		case ${2} in
			"wpa3pot")
				suggested_filename="${wpa3pot_filename}"
				wpa3potenteredpath+="${wpa3pot_filename}"
			;;
			"handshake")
				enteredpath="${pathname}${standardhandshake_filename}"
				suggested_filename="${standardhandshake_filename}"
			;;
			"pmkid")
				enteredpath="${pathname}${standardpmkid_filename}"
				suggested_filename="${standardpmkid_filename}"
			;;
			"pmkidcap")
				enteredpath="${pathname}${standardpmkidcap_filename}"
				suggested_filename="${standardpmkidcap_filename}"
			;;
			"aircrackpot")
				suggested_filename="${aircrackpot_filename}"
				aircrackpotenteredpath+="${aircrackpot_filename}"
			;;
			"jtrpot")
				suggested_filename="${jtrpot_filename}"
				jtrpotenteredpath+="${jtrpot_filename}"
			;;
			"hashcatpot")
				suggested_filename="${hashcatpot_filename}"
				potenteredpath+="${hashcatpot_filename}"
			;;
			"asleappot")
				suggested_filename="${asleappot_filename}"
				asleapenteredpath+="${asleappot_filename}"
			;;
			"ettercaplog")
				suggested_filename="${default_ettercaplogfilename}"
				ettercap_logpath="${ettercap_logpath}${default_ettercaplogfilename}"
			;;
			"bettercaplog")
				suggested_filename="${default_bettercaplogfilename}"
				bettercap_logpath="${bettercap_logpath}${default_bettercaplogfilename}"
			;;
			"writeethandshake")
				et_handshake="${pathname}${standardhandshake_filename}"
				suggested_filename="${standardhandshake_filename}"
			;;
			"et_captive_portallog")
				suggested_filename="${default_et_captive_portallogfilename}"
				et_captive_portal_logpath+="${default_et_captive_portallogfilename}"
			;;
			"wpspot")
				suggested_filename="${wpspot_filename}"
				wpspotenteredpath+="${wpspot_filename}"
			;;
			"weppot")
				suggested_filename="${weppot_filename}"
				weppotenteredpath+="${weppot_filename}"
			;;
			"enterprisepot")
				enterprise_potpath="${pathname}"
				enterprise_basepath=$(dirname "${enterprise_potpath}")

				if [ "${enterprise_basepath}" != "." ]; then
					enterprise_dirname=$(basename "${enterprise_potpath}")
				fi

				if [ "${enterprise_basepath}" != "/" ]; then
					enterprise_basepath+="/"
				fi

				if [ "${enterprise_dirname}" != "${enterprisepot_suggested_dirname}" ]; then
					enterprise_completepath="${enterprise_potpath}${enterprisepot_suggested_dirname}/"
				else
					enterprise_completepath="${enterprise_potpath}"
					if [ "${enterprise_potpath: -1}" != "/" ]; then
						enterprise_completepath+="/"
					fi
				fi

				echo
				language_strings "${language}" 158 "yellow"
				return 0
			;;
			"certificates")
				enterprisecertspath="${pathname}"
				enterprisecerts_basepath=$(dirname "${enterprisecertspath}")

				if [ "${enterprisecerts_basepath}" != "/" ]; then
					enterprisecerts_basepath+="/"
				fi

				enterprisecerts_completepath="${enterprisecertspath}"
				if [ "${enterprisecertspath: -1}" != "/" ]; then
					enterprisecerts_completepath+="/"
				fi

				echo
				language_strings "${language}" 158 "yellow"
				return 0
			;;
		esac

		echo
		language_strings "${language}" 155 "yellow"
		return 0
	fi

	echo
	language_strings "${language}" 158 "yellow"
	return 0
}

#Posthook clean_tmpfiles function to remove temp wpa3 attack files on exit
function wpa3_online_attack_posthook_clean_tmpfiles() {

	rm -rf "${tmpdir}agwpa3"* > /dev/null 2>&1
}
