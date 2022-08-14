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
	language_strings "${language}" 49 wash_scan_dependencies[@] #TODO
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
			#TODO
			:
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

	arr["ENGLISH","wpa3_online_attack_3"]="5. Dictionary online WPA3 attack"
	arr["SPANISH","wpa3_online_attack_3"]="5. Ataque de diccionario online de WPA3"
	arr["FRENCH","wpa3_online_attack_3"]="\${pending_of_translation} "
	arr["CATALAN","wpa3_online_attack_3"]="\${pending_of_translation} "
	arr["PORTUGUESE","wpa3_online_attack_3"]="\${pending_of_translation} "
	arr["RUSSIAN","wpa3_online_attack_3"]="\${pending_of_translation} "
	arr["GREEK","wpa3_online_attack_3"]="\${pending_of_translation} "
	arr["ITALIAN","wpa3_online_attack_3"]="\${pending_of_translation} "
	arr["POLISH","wpa3_online_attack_3"]="\${pending_of_translation} "
	arr["GERMAN","wpa3_online_attack_3"]="\${pending_of_translation} "
	arr["TURKISH","wpa3_online_attack_3"]="\${pending_of_translation} "
	arr["ARABIC","wpa3_online_attack_3"]="\${pending_of_translation} "

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
