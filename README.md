# airgeddon-plugins
Plugins for airgeddon

## airgeddon. Realtek chipset fixer

> An airgeddon plugin to fix some problematic Realtek chipsets.

This plugin for [airgeddon] tool, fix the non-standard behavior of some drivers for some Realtek chipsets used on many wireless cards.
List of the compatible working cards can be found at `airgeddon` Wiki [here]. If you are having troubles with your card using `airgeddon` and your chipset is listed below, keep reading.

#### List of known chipsets fixed with this plugin

For now, the known list of chipsets that this plugin fix to be used flawlessly with `airgeddon` tool is:

 - Realtek RTL8188EU <- _present in TP-Link TL-WN722N (2.4Ghz - USB)_
 - Realtek RTL8812AU <- _present in Alfa AWUS036ACH (2.4Ghz/5Ghz - USB)_
 - Realtek RTL8812BU <- _present in Comfast CF-913AC (2.4Ghz/5Ghz - USB)_
 - Realtek RTL8814AU <- _present in Alfa AWUS1900 (2.4Ghz/5Ghz - USB)_

There are more cards and devices using the chipsets listed here. We listed only some examples of cards containing these chipsets.

#### Which versions was this designed for?

This plugin was designed to be used on airgeddon v10.0 and __is not needed if you are using airgeddon v10.01 or higher__ because since that version, the compatibility problem was already addressed by default.

#### How to install an airgeddon plugin?

It is already explained on `airgeddon` Wiki on [this section] with more detail. Anyway, summarizing, it consists in just copying the `.sh` plugin file to the airgeddon's plugins directory.

Plugins system feature is available from `airgeddon>=10.0`.

#### What is fixed using this plugin?

Basically, this fix for the listed Realtek cards the ability to switch mode from monitor to managed and viceversa from airgeddon menus.

Known problems even using the plugin depending of your driver version and Kernel:

 - WPS wash scanning
 - DoS during Evil Twin attacks (while the interface is splitted into two logical interfaces)

This known problems are not related to airgeddon and can't be fixed on airgeddon's side. They are directly related to driver capabilities so for now they can't be fixed.

#### Contact / Improvements / Extension to other Realtek chipsets

If you have any other wireless card with a different Realtek chipset which is also messing up with airgeddon, feel free to contact me by [IRC] or on #airgeddon channel at Discord. Join clicking on the [Public Invitation link].

## airgeddon. All chars accepted on Captive Portal

> An airgeddon plugin to decreases security to accept any char as part of the password for Evil Twin Captive Portal attack.

This plugin is for [airgeddon] tool. To avoid injections on the Captive Portal, `airgeddon` by default is filtering some dangerous chars `*&/?<>` as a part of the password while using Evil Twin Captive Portal attack. That might the attack to fail if the password of the target network is using one of these filtered chars. Using this plugin, any character will be accepted as part of the password.

[airgeddon]: https://github.com/v1s1t0r1sh3r3/airgeddon
[here]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Cards%20and%20Chipsets
[this section]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Plugins%20System#how-can-i-install-a-plugin-already-done-by-somebody
[IRC]: https://webchat.freenode.net/
[Public Invitation link]: https://discord.gg/sQ9dgt9
