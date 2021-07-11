#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034

plugin_name="Realtek chipset fixer"
plugin_description="A plugin to fix some problematic Realtek chipsets like RTL8812AU and others"
plugin_author="OscarAkaElvis"

plugin_enabled=1

plugin_minimum_ag_affected_version="10.0"
plugin_maximum_ag_affected_version="10.0"
plugin_distros_supported=("*")

#Custom var needed over all the plugin
realtek_chipset_regexp=".*Realtek.*RTL88.*|.*TP-Link TL-WN722N.*"

#Override for check_monitor_enabled function to detect correctly monitor mode
function realtek_chipset_fixer_override_check_monitor_enabled() {

	debug_print

	mode=$(iwconfig "${1}" 2> /dev/null | grep Mode: | awk '{print $4}' | cut -d ':' -f 2)

	current_iface_on_messages="${1}"

	if [[ ${mode} != "Monitor" ]]; then
		mode=$(iwconfig "${1}" 2> /dev/null | grep Mode: | awk '{print $1}' | cut -d ':' -f 2)
		if [[ ${mode} != "Monitor" ]]; then
			return 1
		fi
	fi
	return 0
}

#Override for check_interface_mode function to detect correctly card modes
#shellcheck disable=SC2154
function realtek_chipset_fixer_override_check_interface_mode() {

	debug_print

	current_iface_on_messages="${1}"
	if ! execute_iwconfig_fix "${1}"; then
		ifacemode="(Non wifi card)"
		return 0
	fi

	modemanaged=$(iwconfig "${1}" 2> /dev/null | grep Mode: | cut -d ':' -f 2 | cut -d ' ' -f 1)

	if [[ ${modemanaged} = "Managed" ]] || [[ ${modemanaged} = "Auto" ]]; then
		ifacemode="Managed"
		return 0
	fi

	modemonitor=$(iwconfig "${1}" 2> /dev/null | grep Mode: | awk '{print $4}' | cut -d ':' -f 2)

	if [[ ${modemonitor} = "Monitor" ]]; then
		ifacemode="Monitor"
		return 0
	else
		modemonitor=$(iwconfig "${1}" 2> /dev/null | grep Mode: | awk '{print $1}' | cut -d ':' -f 2)
		if [[ ${modemonitor} = "Monitor" ]]; then
			ifacemode="Monitor"
			return 0
		fi
	fi

	language_strings "${language}" 23 "red"
	language_strings "${language}" 115 "read"
	exit_code=1
	exit_script_option
}

#Override for set_chipset to add read_only feature to read the chipset for an interface without modifying chipset var
function realtek_chipset_fixer_override_set_chipset() {

	debug_print

	chipset=""
	sedrule1="s/^[0-9a-f]\{1,4\} \|^ //Ig"
	sedrule2="s/ Network Connection.*//Ig"
	sedrule3="s/ Wireless.*//Ig"
	sedrule4="s/ PCI Express.*//Ig"
	sedrule5="s/ \(Gigabit\|Fast\) Ethernet.*//Ig"
	sedrule6="s/ \[.*//"
	sedrule7="s/ (.*//"
	sedrule8="s|802\.11a/b/g/n/ac.*||Ig"

	sedruleall="${sedrule1};${sedrule2};${sedrule3};${sedrule4};${sedrule5};${sedrule6};${sedrule7};${sedrule8}"

	if [ -f "/sys/class/net/${1}/device/modalias" ]; then
		bus_type=$(cut -f 1 -d ":" < "/sys/class/net/${1}/device/modalias")

		if [ "${bus_type}" = "usb" ]; then
			vendor_and_device=$(cut -b 6-14 < "/sys/class/net/${1}/device/modalias" | sed 's/^.//;s/p/:/')
			if hash lsusb 2> /dev/null; then
				if [[ -n "${2}" ]] && [[ "${2}" = "read_only" ]]; then
					requested_chipset=$(lsusb | grep -i "${vendor_and_device}" | head -n 1 | cut -f 3 -d ":" | sed -e "${sedruleall}")
				else
					chipset=$(lsusb | grep -i "${vendor_and_device}" | head -n 1 | cut -f 3 -d ":" | sed -e "${sedruleall}")
				fi
			fi

		elif [[ "${bus_type}" =~ pci|ssb|bcma|pcmcia ]]; then
			if [[ -f /sys/class/net/${1}/device/vendor ]] && [[ -f /sys/class/net/${1}/device/device ]]; then
				vendor_and_device=$(cat "/sys/class/net/${1}/device/vendor"):$(cat "/sys/class/net/${1}/device/device")
				if [[ -n "${2}" ]] && [[ "${2}" = "read_only" ]]; then
					requested_chipset=$(lspci -d "${vendor_and_device}" | head -n 1 | cut -f 3 -d ":" | sed -e "${sedruleall}")
				else
					chipset=$(lspci -d "${vendor_and_device}" | head -n 1 | cut -f 3 -d ":" | sed -e "${sedruleall}")
				fi
			else
				if hash ethtool 2> /dev/null; then
					ethtool_output=$(ethtool -i "${1}" 2>&1)
					vendor_and_device=$(printf "%s" "${ethtool_output}" | grep "bus-info" | cut -f 3 -d ":" | sed 's/^ //')
					if [[ -n "${2}" ]] && [[ "${2}" = "read_only" ]]; then
						requested_chipset=$(lspci | grep "${vendor_and_device}" | head -n 1 | cut -f 3 -d ":" | sed -e "${sedruleall}")
					else
						chipset=$(lspci | grep "${vendor_and_device}" | head -n 1 | cut -f 3 -d ":" | sed -e "${sedruleall}")
					fi
				fi
			fi
		fi
	elif [[ -f /sys/class/net/${1}/device/idVendor ]] && [[ -f /sys/class/net/${1}/device/idProduct ]]; then
		vendor_and_device=$(cat "/sys/class/net/${1}/device/idVendor"):$(cat "/sys/class/net/${1}/device/idProduct")
		if hash lsusb 2> /dev/null; then
			if [[ -n "${2}" ]] && [[ "${2}" = "read_only" ]]; then
				requested_chipset=$(lsusb | grep -i "${vendor_and_device}" | head -n 1 | cut -f 3 -d ":" | sed -e "${sedruleall}")
			else
				chipset=$(lsusb | grep -i "${vendor_and_device}" | head -n 1 | cut -f 3 -d ":" | sed -e "${sedruleall}")
			fi
		fi
	fi
}

#Custom function. Check if an adapter is compatible to airmon
function check_airmon_compatibility() {

	if [ "${1}" = "interface" ]; then
		set_chipset "${interface}" "read_only"

		if [[ "${requested_chipset}" =~ ${realtek_chipset_regexp} ]]; then
			interface_airmon_compatible=0
		else
			if ! iw dev "${interface}" set bitrates legacy-2.4 1 > /dev/null 2>&1; then
				interface_airmon_compatible=0
			else
				interface_airmon_compatible=1
			fi
		fi
	else
		set_chipset "${secondary_wifi_interface}" "read_only"

		if [[ "${requested_chipset}" =~ ${realtek_chipset_regexp} ]]; then
			secondary_interface_airmon_compatible=0
		else
			if ! iw dev "${secondary_wifi_interface}" set bitrates legacy-2.4 1 > /dev/null 2>&1; then
				secondary_interface_airmon_compatible=0
			else
				secondary_interface_airmon_compatible=1
			fi
		fi
	fi
}

#Override for managed_option function to set the interface on managed mode and manage the possible name change correctly
#shellcheck disable=SC2154
function realtek_chipset_fixer_override_managed_option() {

	debug_print

	if ! check_to_set_managed "${1}"; then
		return 1
	fi

	disable_rfkill

	language_strings "${language}" 17 "blue"
	ifconfig "${1}" up

	if [ "${1}" = "${interface}" ]; then
		check_airmon_compatibility "interface"
		if [ "${interface_airmon_compatible}" -eq 0 ]; then
			if ! set_mode_without_airmon "${1}" "managed"; then
				echo
				language_strings "${language}" 1 "red"
				language_strings "${language}" 115 "read"
				return 1
			else
				ifacemode="Managed"
			fi
		else
			new_interface=$(${airmon} stop "${1}" 2> /dev/null | grep station | head -n 1)
			ifacemode="Managed"

			[[ ${new_interface} =~ \]?([A-Za-z0-9]+)\)?$ ]] && new_interface="${BASH_REMATCH[1]}"

			if [ "${interface}" != "${new_interface}" ]; then
				if check_interface_coherence; then
					interface=${new_interface}
					phy_interface=$(physical_interface_finder "${interface}")
					check_interface_supported_bands "${phy_interface}" "main_wifi_interface"
				fi
				current_iface_on_messages="${interface}"
				echo
				language_strings "${language}" 15 "yellow"
			fi
		fi
	else
		check_airmon_compatibility "secondary_interface"
		if [ "${secondary_interface_airmon_compatible}" -eq 0 ]; then
			if ! set_mode_without_airmon "${1}" "managed"; then
				echo
				language_strings "${language}" 1 "red"
				language_strings "${language}" 115 "read"
				return 1
			fi
		else
			new_secondary_interface=$(${airmon} stop "${1}" 2> /dev/null | grep station | head -n 1)
			[[ ${new_secondary_interface} =~ \]?([A-Za-z0-9]+)\)?$ ]] && new_secondary_interface="${BASH_REMATCH[1]}"

			if [ "${1}" != "${new_secondary_interface}" ]; then
				secondary_wifi_interface=${new_secondary_interface}
				current_iface_on_messages="${secondary_wifi_interface}"
				echo
				language_strings "${language}" 15 "yellow"
			fi
		fi
	fi

	echo
	language_strings "${language}" 16 "yellow"
	language_strings "${language}" 115 "read"
	return 0
}

#Override for monitor_option function to set the interface on monitor mode and manage the possible name change correctly
#shellcheck disable=SC2154
function realtek_chipset_fixer_override_monitor_option() {

	debug_print

	if ! check_to_set_monitor "${1}"; then
		return 1
	fi

	disable_rfkill

	language_strings "${language}" 18 "blue"
	ifconfig "${1}" up

	if [ "${1}" = "${interface}" ]; then
		check_airmon_compatibility "interface"
		if [ "${interface_airmon_compatible}" -eq 0 ]; then
			if ! set_mode_without_airmon "${1}" "monitor"; then
				echo
				language_strings "${language}" 20 "red"
				language_strings "${language}" 115 "read"
				return 1
			else
				ifacemode="Monitor"
			fi
		else
			if [ "${check_kill_needed}" -eq 1 ]; then
				language_strings "${language}" 19 "blue"
				${airmon} check kill > /dev/null 2>&1
				nm_processes_killed=1
			fi

			desired_interface_name=""
			new_interface=$(${airmon} start "${1}" 2> /dev/null | grep monitor)
			[[ ${new_interface} =~ ^You[[:space:]]already[[:space:]]have[[:space:]]a[[:space:]]([A-Za-z0-9]+)[[:space:]]device ]] && desired_interface_name="${BASH_REMATCH[1]}"

			if [ -n "${desired_interface_name}" ]; then
				echo
				language_strings "${language}" 435 "red"
				language_strings "${language}" 115 "read"
				return 1
			fi

			ifacemode="Monitor"
			[[ ${new_interface} =~ \]?([A-Za-z0-9]+)\)?$ ]] && new_interface="${BASH_REMATCH[1]}"

			if [ "${interface}" != "${new_interface}" ]; then
				if check_interface_coherence; then
					interface="${new_interface}"
					phy_interface=$(physical_interface_finder "${interface}")
					check_interface_supported_bands "${phy_interface}" "main_wifi_interface"
				fi
				current_iface_on_messages="${interface}"
				echo
				language_strings "${language}" 21 "yellow"
			fi
		fi
	else
		check_airmon_compatibility "secondary_interface"
		if [ "${secondary_interface_airmon_compatible}" -eq 0 ]; then
			if ! set_mode_without_airmon "${1}" "monitor"; then
				echo
				language_strings "${language}" 20 "red"
				language_strings "${language}" 115 "read"
				return 1
			fi
		else
			if [ "${check_kill_needed}" -eq 1 ]; then
				language_strings "${language}" 19 "blue"
				${airmon} check kill > /dev/null 2>&1
				nm_processes_killed=1
			fi

			secondary_interface_airmon_compatible=1
			new_secondary_interface=$(${airmon} start "${1}" 2> /dev/null | grep monitor)
			[[ ${new_secondary_interface} =~ ^You[[:space:]]already[[:space:]]have[[:space:]]a[[:space:]]([A-Za-z0-9]+)[[:space:]]device ]] && desired_interface_name="${BASH_REMATCH[1]}"

			if [ -n "${desired_interface_name}" ]; then
				echo
				language_strings "${language}" 435 "red"
				language_strings "${language}" 115 "read"
				return 1
			fi

			[[ ${new_secondary_interface} =~ \]?([A-Za-z0-9]+)\)?$ ]] && new_secondary_interface="${BASH_REMATCH[1]}"

			if [ "${1}" != "${new_secondary_interface}" ]; then
				secondary_wifi_interface="${new_secondary_interface}"
				current_iface_on_messages="${secondary_wifi_interface}"
				echo
				language_strings "${language}" 21 "yellow"
			fi
		fi
	fi

	echo
	language_strings "${language}" 22 "yellow"
	language_strings "${language}" 115 "read"
	return 0
}

#Override for prepare_et_interface function to assure the mode of the interface before the Evil Twin or Enterprise process
function realtek_chipset_fixer_override_prepare_et_interface() {

	debug_print

	et_initial_state=${ifacemode}

	if [ "${ifacemode}" != "Managed" ]; then
		check_airmon_compatibility "interface"
		if [ "${interface_airmon_compatible}" -eq 1 ]; then

			new_interface=$(${airmon} stop "${interface}" 2> /dev/null | grep station | head -n 1)
			ifacemode="Managed"
			[[ ${new_interface} =~ \]?([A-Za-z0-9]+)\)?$ ]] && new_interface="${BASH_REMATCH[1]}"
			if [ "${interface}" != "${new_interface}" ]; then
				if check_interface_coherence; then
					interface=${new_interface}
					phy_interface=$(physical_interface_finder "${interface}")
					check_interface_supported_bands "${phy_interface}" "main_wifi_interface"
				fi
				current_iface_on_messages="${interface}"
				echo
				language_strings "${language}" 15 "yellow"
			fi
		else
			if ! set_mode_without_airmon "${interface}" "managed"; then
				echo
				language_strings "${language}" 1 "red"
				language_strings "${language}" 115 "read"
				return 1
			else
				ifacemode="Managed"
			fi
		fi
	fi
}