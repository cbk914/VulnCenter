# VulnCenter

Application to manage vulnerability databases

Downloads and stores on a SQLite3 database, data from the following sources:

* CVE
* CAPEC
* ExploitDB

How to use

python vulncenter.py `<option>`

* "-s", "--search":"Search string to use in the databases"

* "-o", "--output":Format to use for the output file (txt, xml, json)

* "-f", "--output-file":"Filename to use for the output file"

"-g", "--debug":"Enable debug mode"
