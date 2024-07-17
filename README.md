# ReconEnhance

ReconEnhance is an efficient tool for network reconnaissance that utilizes multiple threads to carry out partially automated enumeration of services. Its purpose is to save time during CTFs and penetration testing scenarios, such as OSCP. 

To begin, the tool conducts port scans and service detection scans, but only after obtaining explicit permission from the user. Based on the initial findings, the tool proceeds to conduct additional enumeration scans on the identified services, utilizing various tools with the user's explicit consent. For instance, if HTTP is detected, feroxbuster, along with several others, will be launcheed, given that the user grants permission.

Features

* Prompts the user before executing any command.
* Supports multiple targets in the form of IP addresses, IP ranges (CIDR notation), and resolvable hostnames. IPv6 is also supported.
* Advanced plugin system allowing for easy creation of new scans.
* Customizable port scanning plugins for flexibility in your initial scans.
* Customizable service scanning plugins for further enumeration.
* Suggested manual follow-up commands for when automation makes little sense.
* Ability to limit port scanning to a combination of TCP/UDP ports.
* An intuitive directory structure for results gathering.
* Full logging of commands that were run, along with errors if they fail.
* A powerful config file lets you use your favorite settings every time.
* A tagging system that lets you include or exclude certain plugins.
* Global and per-target timeouts in case you only have limited time.
* Four levels of verbosity, controllable by command-line options, and during scans using Up/Down arrows.
* Colorized output for distinguishing separate pieces of information. Can be turned off for accessibility reasons.
* A user-friendly graphical interface (GUI) to assist users in comprehending the outputs.

