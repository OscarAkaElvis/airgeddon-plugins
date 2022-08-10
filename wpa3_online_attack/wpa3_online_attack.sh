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

	#TODO
	:
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
