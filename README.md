# KerBOF
CS BOF for managing kerboers tickets. Inspired and modified from wavvs/nanorobeus [https://github.com/wavvs/nanorobeus] and ghostpack/rubeus [https://github.com/GhostPack/Rubeus]

## Commands

**luid** - get current logon ID

**sessions** *[/luid <0x0>| /all]* - get logon sessions

**klist** *[/luid <0x0> | /all]* - list Kerberos tickets

**dump** *[/luid <0x0> | /all]* - dump Kerberos tickets

**ptt** *\<base64\> [/luid <0x0>]* - import Kerberos ticket into a logon session

**purge** *[/luid <0x0>]* - purge Kerberos tickets

**tgtdeleg** *\<spn\>* - retrieve a usable TGT for the current user

**kerberoast** *\<spn\>* - perform Kerberoasting against specified SPN

## Credits
* Rubeus - https://github.com/GhostPack/Rubeus
* mimikatz - https://github.com/gentilkiwi/mimikatz
* kekeo - https://github.com/gentilkiwi/kekeo # kerbof
* nanorobeus - https://github.com/wavvs/nanorobeus
