# KerBOF
CS BOF for managing kerboers tickets. Thanks to wavvs/nanorobeus [https://github.com/wavvs/nanorobeus] for providing most of the code and inspiration. I modified much of the original code so felt like it needed a new name.

## COMMANDS
:warning:The /all flag is currently bugged. I've removed it from the BOF for the time being.

| COMMAND | DESCRIPTION |
| ------- | ----------- |
| **luid**| get current logon ID|
|**sessions** *[/luid <0x0>\| /all]*| get logon sessions|
|**klist** *[/luid <0x0> \| /all]*| list Kerberos tickets|
|**dump** *[/luid <0x0> \| /all]* | dump Kerberos tickets|
|**ptt** *\<base64\> [/luid <0x0>]* | import Kerberos ticket into a logon session|

## TODO
| COMMAND | DESCRIPTION|
| ------- | -------- |
|**purge** *[/luid <0x0>]* | purge Kerberos tickets|
|**tgtdeleg** *\<spn\>* | retrieve a usable TGT for the current user |
|**kerberoast** *\<spn\>* | perform Kerberoasting against specified SPN|

## Credits
* Rubeus - https://github.com/GhostPack/Rubeus
* mimikatz - https://github.com/gentilkiwi/mimikatz
* kekeo - https://github.com/gentilkiwi/kekeo # kerbof
* nanorobeus - https://github.com/wavvs/nanorobeus
