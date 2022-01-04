#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

plugin_name="All chars accepted on Captive Portal"
plugin_description="Decreases security to accept any char as part of the password for Evil Twin Captive Portal attack"
plugin_author="OscarAkaElvis"

#Enabled 1 / Disabled 0 - Set this plugin as enabled - Default value 1
plugin_enabled=1

###### PLUGIN REQUIREMENTS ######

#Set airgeddon versions to apply this plugin (leave blank to set no limits, minimum version recommended is 10.0 on which plugins feature was added)
plugin_minimum_ag_affected_version="10.0"
plugin_maximum_ag_affected_version=""

#Set only one element in the array "*" to affect all distros, otherwise add them one by one with the name which airgeddon uses for that distro (examples "BlackArch", "Parrot", "Kali")
plugin_distros_supported=("*")

#Posthook for set_captive_portal_page to accept all chars on password
#shellcheck disable=SC2016
function allchars_captiveportal_posthook_set_captive_portal_page() {

	sed -i '/^password=\${password/d' "${tmpdir}${webdir}${checkfile}"
}
