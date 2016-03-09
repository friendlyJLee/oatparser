# oatparser
Tool for parsing Android OAT file without disassemble.

Although a OAT file is one ELF file, it is different from the traditional ELF file (execution/library), so it cannot parsed by the traditional ELF parsing tools (e.g. readelf and objdump). 

Currently oatpareser is only evaluated by the OAT files generated on Android 6.0.1 system.
