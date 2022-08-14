#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

plugin_name="WPA3 online attack"
plugin_description="A plugin to perform a dictionary online attack over WPA3 wireless networks"
plugin_author="OscarAkaElvis"

#This plugin is based in the Wacker script. Credits to the authors: https://github.com/blunderbuss-wctf/wacker

plugin_enabled=1

plugin_minimum_ag_affected_version="11.02"
plugin_maximum_ag_affected_version=""
plugin_distros_supported=("*")

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

#Custom function. Execute WPA3 online dictionary attack
function execute_wpa3_online_dictionary_attack() {

	debug_print

	if [[ -z ${bssid} ]] || [[ -z ${essid} ]] || [[ -z ${channel} ]] || [[ "${essid}" = "(Hidden Network)" ]]; then
		echo
		language_strings "${language}" 125 "yellow"
		language_strings "${language}" 115 "read"
		if ! explore_for_targets_option "WPA3"; then
			return 1
		fi
	fi

	if ! check_monitor_enabled "${interface}"; then
		echo
		language_strings "${language}" 14 "red"
		language_strings "${language}" 115 "read"
		return 1
	fi

	if ! validate_wpa3_network; then
		return 1
	fi

	#TODO
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
			execute_wpa3_online_dictionary_attack
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

	arr["ENGLISH",60]="12. About & Credits"
	arr["SPANISH",60]="12. Acerca de & Créditos"
	arr["FRENCH",60]="12. A propos de & Crédits"
	arr["CATALAN",60]="12. Sobre & Crédits"
	arr["PORTUGUESE",60]="12. Sobre & Créditos"
	arr["RUSSIAN",60]="12. О программе и Благодарности"
	arr["GREEK",60]="12. Σχετικά με & Εύσημα"
	arr["ITALIAN",60]="12. Informazioni & Credits"
	arr["POLISH",60]="12. O programie & Podziękowania"
	arr["GERMAN",60]="12. About & Credits"
	arr["TURKISH",60]="12. Hakkında & Güven"
	arr["ARABIC",60]="12. بشأن ومنسوبات"

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

	arr["ENGLISH","wpa3_online_attack_1"]="11. WPA3 attacks menu"
	arr["SPANISH","wpa3_online_attack_1"]="11. Menú de ataques WPA3"
	arr["FRENCH","wpa3_online_attack_1"]="\${pending_of_translation} 11. Menu d'attaque WPA3"
	arr["CATALAN","wpa3_online_attack_1"]="\${pending_of_translation} 11. Menú d'atacs WPA3"
	arr["PORTUGUESE","wpa3_online_attack_1"]="\${pending_of_translation} 11. Menu de ataques WPA3"
	arr["RUSSIAN","wpa3_online_attack_1"]="\${pending_of_translation} 11. Меню WPA3 атак"
	arr["GREEK","wpa3_online_attack_1"]="\${pending_of_translation} 11. Μενού επιλογών WPA3"
	arr["ITALIAN","wpa3_online_attack_1"]="\${pending_of_translation} 11. Menu dell'attacco WPA3"
	arr["POLISH","wpa3_online_attack_1"]="\${pending_of_translation} 11. Menu ataków WPA3"
	arr["GERMAN","wpa3_online_attack_1"]="\${pending_of_translation} 11. WPA3-Angriffsmenü"
	arr["TURKISH","wpa3_online_attack_1"]="\${pending_of_translation} 11. WPA3 saldırılar menüsü"
	arr["ARABIC","wpa3_online_attack_1"]="\${pending_of_translation} 11. WPA3 قائمة هجمات"

	arr["ENGLISH","wpa3_online_attack_2"]="WPA3 attacks menu"
	arr["SPANISH","wpa3_online_attack_2"]="Menú de ataques WPA3"
	arr["FRENCH","wpa3_online_attack_2"]="\${pending_of_translation} Menu d'attaque WPA3"
	arr["CATALAN","wpa3_online_attack_2"]="\${pending_of_translation} Menú d'atacs WPA3"
	arr["PORTUGUESE","wpa3_online_attack_2"]="\${pending_of_translation} Menu de ataques WPA3"
	arr["RUSSIAN","wpa3_online_attack_2"]="\${pending_of_translation} Меню WPA3 атак"
	arr["GREEK","wpa3_online_attack_2"]="\${pending_of_translation} Μενού επιλογών WPA3"
	arr["ITALIAN","wpa3_online_attack_2"]="\${pending_of_translation} Menu dell'attacco WPA3"
	arr["POLISH","wpa3_online_attack_2"]="\${pending_of_translation} Menu ataków WPA3"
	arr["GERMAN","wpa3_online_attack_2"]="\${pending_of_translation} WPA3-Angriffsmenü"
	arr["TURKISH","wpa3_online_attack_2"]="\${pending_of_translation} WPA3 saldırılar menüsü"
	arr["ARABIC","wpa3_online_attack_2"]="\${pending_of_translation} WPA3 قائمة هجمات"

	arr["ENGLISH","wpa3_online_attack_3"]="5.  WPA3 online dictionary attack"
	arr["SPANISH","wpa3_online_attack_3"]="5.  Ataque de diccionario online de WPA3"
	arr["FRENCH","wpa3_online_attack_3"]="\${pending_of_translation} 5.  Attaque par dictionnaire online WPA3"
	arr["CATALAN","wpa3_online_attack_3"]="\${pending_of_translation} 5.  Atac de diccionari online de WPA3"
	arr["PORTUGUESE","wpa3_online_attack_3"]="\${pending_of_translation} 5.  Ataque de dicionário online WPA3"
	arr["RUSSIAN","wpa3_online_attack_3"]="\${pending_of_translation} 5.  Атака по онлайн-словарю WPA3"
	arr["GREEK","wpa3_online_attack_3"]="\${pending_of_translation} 5.  Επίθεση σε διαδικτυακό λεξικό WPA3"
	arr["ITALIAN","wpa3_online_attack_3"]="\${pending_of_translation} 5.  Attacco al dizionario online WPA3"
	arr["POLISH","wpa3_online_attack_3"]="\${pending_of_translation} 5.  Atak słownikowy online WPA3"
	arr["GERMAN","wpa3_online_attack_3"]="\${pending_of_translation} 5.  WPA3-Angriff auf das Online-Wörterbuch"
	arr["TURKISH","wpa3_online_attack_3"]="\${pending_of_translation} 5.  WPA3 çevrimiçi sözlük saldırısı"
	arr["ARABIC","wpa3_online_attack_3"]="\${pending_of_translation} 5.  هجوم WPA3 القاموس على الإنترنت"

	arr["ENGLISH","wpa3_online_attack_4"]="WPA3 filter enabled in scan. When started, press [Ctrl+C] to stop..."
	arr["SPANISH","wpa3_online_attack_4"]="Filtro WPA3 activado en escaneo. Una vez empezado, pulse [Ctrl+C] para pararlo..."
	arr["FRENCH","wpa3_online_attack_4"]="\${pending_of_translation} Le filtre WPA3 est activé dans le scan. Une fois l'opération lancée, veuillez presser [Ctrl+C] pour l'arrêter..."
	arr["CATALAN","wpa3_online_attack_4"]="\${pending_of_translation} Filtre WPA3 activat en escaneig. Una vegada iniciat, polsi [Ctrl+C] per detenir-ho..."
	arr["PORTUGUESE","wpa3_online_attack_4"]="\${pending_of_translation} Filtro WPA3 ativo na busca de redes wifi. Uma vez iniciado, pressione [Ctrl+C] para pará-lo..."
	arr["RUSSIAN","wpa3_online_attack_4"]="\${pending_of_translation} Для сканирования активирован фильтр WPA3. После запуска, нажмите [Ctrl+C] для остановки..."
	arr["GREEK","wpa3_online_attack_4"]="\${pending_of_translation} Το φίλτρο WPA3 ενεργοποιήθηκε κατά τη σάρωση. Όταν αρχίσει, μπορείτε να το σταματήσετε πατώντας [Ctrl+C]..."
	arr["ITALIAN","wpa3_online_attack_4"]="\${pending_of_translation} Filtro WPA3 attivato durante la scansione. Una volta avviato, premere [Ctrl+C] per fermarlo..."
	arr["POLISH","wpa3_online_attack_4"]="\${pending_of_translation} Filtr WPA3 aktywowany podczas skanowania. Naciśnij [Ctrl+C] w trakcie trwania, aby zatrzymać..."
	arr["GERMAN","wpa3_online_attack_4"]="\${pending_of_translation} WPA3-Filter beim Scannen aktiviert. Nach den Start, drücken Sie [Ctrl+C], um es zu stoppen..."
	arr["TURKISH","wpa3_online_attack_4"]="\${pending_of_translation} WPA3 filtesi taraması etkin. Başladıktan sonra, durdurmak için [Ctrl+C] tuşlayınız..."
	arr["ARABIC","wpa3_online_attack_4"]="\${pending_of_translation} ...للإيقاف [Ctrl+C] في المسح. عند البدء ، اضغط على WPA3 تم تفعيل مرشح"

	arr["ENGLISH","wpa3_online_attack_5"]="WPA3 online dictionary attack takes considerably longer than an offline decryption attack, so it is recommended to only perform it over pure WPA3 networks. If your target network is in WPA2/WPA3 \"Mixed Mode\", it is recommended to carry out the traditional WPA2 attacks (Handshake, PMKID) instead of the online attack"
	arr["SPANISH","wpa3_online_attack_5"]="El ataque de diccionario online de WPA3 tarda bastante más tiempo que un ataque de descifrado offline, por lo que se recomienda solo realizarlo sobre redes puras WPA3. Si tu red objetivo está en WPA2/WPA3 \"Mixed Mode\", lo recomendable es realizar los ataques tradicionales de WPA2 (Handshake, PMKID) en lugar del ataque online "
	arr["FRENCH","wpa3_online_attack_5"]="\${pending_of_translation} L'attaque par dictionnaire en ligne WPA3 prend beaucoup plus de temps qu'une attaque de décryptage hors ligne, il est donc recommandé de ne l'exécuter que sur des réseaux WPA3 purs. Si votre réseau cible est en WPA2/WPA3 \"Mixed Mode\", il est recommandé d'effectuer les attaques WPA2 traditionnelles (Handshake, PMKID) au lieu de l'attaque en ligne"
	arr["CATALAN","wpa3_online_attack_5"]="\${pending_of_translation} L'atac de diccionari online de WPA3 triga força més temps que un atac de desxifrat offline, per la qual cosa es recomana només fer-ho sobre xarxes pures WPA3. Si la teva xarxa objectiu està a WPA2/WPA3 \"Mixed Mode\", el recomanable és realitzar els atacs tradicionals de WPA2 (Handshake, PMKID) en lloc de l'atac en línia"
	arr["PORTUGUESE","wpa3_online_attack_5"]="\${pending_of_translation} O ataque de dicionário online WPA3 demora consideravelmente mais do que um ataque de descriptografia offline, portanto, é recomendável executá-lo apenas em redes WPA3 puras. Se a sua rede alvo estiver em WPA2/WPA3 \"Mixed Mode\", é recomendável realizar os ataques WPA2 tradicionais (Handshake, PMKID) em vez do ataque online"
	arr["RUSSIAN","wpa3_online_attack_5"]="\${pending_of_translation} Онлайн-атака по словарю WPA3 занимает значительно больше времени, чем офлайн-атака с дешифрованием, поэтому рекомендуется выполнять ее только в чистых сетях WPA3. Если ваша целевая сеть находится в WPA2/WPA3 \"Mixed Mode\", рекомендуется проводить традиционные атаки WPA2 (рукопожатие, PMKID) вместо онлайн-атаки."
	arr["GREEK","wpa3_online_attack_5"]="\${pending_of_translation} Η επίθεση διαδικτυακού λεξικού WPA3 διαρκεί πολύ περισσότερο από μια επίθεση αποκρυπτογράφησης εκτός σύνδεσης, επομένως συνιστάται να εκτελείται μόνο μέσω καθαρών δικτύων WPA3. Εάν το δίκτυο-στόχος σας είναι σε WPA2/WPA3 \"Mixed Mode\", συνιστάται να πραγματοποιήσετε τις παραδοσιακές επιθέσεις WPA2 (Handshake, PMKID) αντί για την online επίθεση"
	arr["ITALIAN","wpa3_online_attack_5"]="\${pending_of_translation} L'attacco del dizionario online WPA3 richiede molto più tempo di un attacco di decrittazione offline, quindi si consiglia di eseguirlo solo su reti WPA3 pure. Se la rete di destinazione è in WPA2/WPA3 \"Modalità mista\", si consiglia di eseguire i tradizionali attacchi WPA2 (Handshake, PMKID) anziché l'attacco online"
	arr["POLISH","wpa3_online_attack_5"]="\${pending_of_translation} Atak słownikowy WPA3 online trwa znacznie dłużej niż atak z odszyfrowaniem offline, dlatego zaleca się przeprowadzanie go tylko w czystych sieciach WPA3. Jeśli Twoja sieć docelowa jest w trybie WPA2/WPA3 \"Mixed Mode\", zaleca się przeprowadzenie tradycyjnych ataków WPA2 (Handshake, PMKID) zamiast ataków online"
	arr["GERMAN","wpa3_online_attack_5"]="\${pending_of_translation} Der WPA3-Online-Wörterbuchangriff dauert erheblich länger als ein Offline-Entschlüsselungsangriff, daher wird empfohlen, ihn nur über reine WPA3-Netzwerke durchzuführen. Wenn sich Ihr Zielnetzwerk im WPA2/WPA3 \"Mixed Mode\", befindet, empfiehlt es sich, anstelle des Online-Angriffs die traditionellen WPA2-Angriffe (Handshake, PMKID) durchzuführen"
	arr["TURKISH","wpa3_online_attack_5"]="\${pending_of_translation} WPA3 çevrimiçi sözlük saldırısı, çevrimdışı bir şifre çözme saldırısından çok daha uzun sürer, bu nedenle yalnızca saf WPA3 ağları üzerinden gerçekleştirilmesi önerilir. Hedef ağınız WPA2/WPA3 \"Mixed Mode\", daysa, çevrimiçi saldırı yerine geleneksel WPA2 saldırılarını (Handshake, PMKID) gerçekleştirmeniz önerilir."
	arr["ARABIC","wpa3_online_attack_5"]="\${pending_of_translation} يستغرق هجوم القاموس عبر الإنترنت WPA3 وقتًا أطول بكثير من هجوم فك التشفير في وضع عدم الاتصال ، لذلك يوصى بأدائه عبر شبكات WPA3 فقط. إذا كانت شبكتك المستهدفة في \"Mixed Mode\" WPA2/WPA3 ،WPA2 التقليدية (Handshake ،PMKID) بدلاً من الهجوم عبر الإنترنت"

	arr["ENGLISH","wpa3_online_attack_6"]="The selected network is invalid. The target network must be WPA3 or WPA2/WPA3 in \"Mixed Mode\""
	arr["SPANISH","wpa3_online_attack_6"]="La red seleccionada no es válida. La red objetivo debe ser WPA3 o WPA2/WPA3 en \"Mixed Mode\""
	arr["FRENCH","wpa3_online_attack_6"]="\${pending_of_translation} Le réseau sélectionné n'est pas valide. Le réseau cible doit être WPA3 ou WPA2/WPA3 en \"Mixed Mode\""
	arr["CATALAN","wpa3_online_attack_6"]="\${pending_of_translation} La xarxa seleccionada no és vàlida. La xarxa objectiu ha de ser WPA3 o WPA2/WPA3 a \"Mixed Mode\""
	arr["PORTUGUESE","wpa3_online_attack_6"]="\${pending_of_translation} A rede selecionada é inválida. A rede de destino deve ser WPA3 ou WPA2/WPA3 em \"Mixed Mode\""
	arr["RUSSIAN","wpa3_online_attack_6"]="\${pending_of_translation} Выбранная сеть недействительна. Целевая сеть должна быть WPA3 или WPA2/WPA3 в \"Mixed Mode\""
	arr["GREEK","wpa3_online_attack_6"]="\${pending_of_translation} Το επιλεγμένο δίκτυο δεν είναι έγκυρο. Το δίκτυο προορισμού πρέπει να είναι WPA3 ή WPA2/WPA3 σε \"Mixed Mode\""
	arr["ITALIAN","wpa3_online_attack_6"]="\${pending_of_translation} La rete selezionata non è valida. La rete di destinazione deve essere WPA3 o WPA2/WPA3 in \"Mixed Mode\""
	arr["POLISH","wpa3_online_attack_6"]="\${pending_of_translation} Wybrana sieć jest nieprawidłowa. Sieć docelowa musi być WPA3 lub WPA2/WPA3 w \"Mixed Mode\""
	arr["GERMAN","wpa3_online_attack_6"]="\${pending_of_translation} Das ausgewählte Netzwerk ist ungültig. Das Zielnetzwerk muss WPA3 oder WPA2/WPA3 im \"Mixed Mode\" sein"
	arr["TURKISH","wpa3_online_attack_6"]="\${pending_of_translation} Seçilen ağ geçersiz. Hedef ağ, \"Mixed Mode\" da WPA3 veya WPA2/WPA3 olmalıdır"
	arr["ARABIC","wpa3_online_attack_6"]="\${pending_of_translation} الشبكة المحددة غير صالحة. يجب أن تكون الشبكة المستهدفة WPA3 أو WPA2/WPA3 \"Mixed Mode\""
}

#Override initialize_menu_and_print_selections function to add the new WPA3 menu
function wpa3_online_attack_override_initialize_menu_and_print_selections() {

	debug_print

	forbidden_options=()

	case ${current_menu} in
		"wpa3_attacks_menu")
			print_iface_selected
			print_all_target_vars
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
				if [ ${retry_handshake_capture} -eq 1 ]; then
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
