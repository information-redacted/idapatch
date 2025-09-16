idapatch
--------
An IDA plugin to patch IDA in memory.

This is an updated copy of MrExodia's idapatch plugin which can be found at: https://github.com/mrexodia/idapatch
This has only been tested against the SDK for IDA Pro 8.3 (idasdk-pro83)

Usage
-----
1. Copy idapatch.dll, idapatch64.dll to your IDA plugins directory
2. Create a idapatch.ini file and insert your configuration.

Configuration
-------------
Changes were made to the upstream configuration scheme;
 - The module field now takes 'dll' instead of 'wll' as 'ida.wll', 'ida64.wll' are now named .dll.
 - The 'exe' type now patches 'ida' instead of 'idaq'.
 - You can now specify a specific module to patch (such as another plugin, or dependency)
 - The `[idapatch_settings]` section was added to allow for global settings such as configuring the loop delay;
   - The default loop time is 2s, and can be changed by setting `loop_delay_ms`.

Example (taken from upstream, modified as per above scheme -- patch likely no-longer works!):

[UniSoft (exetools) qstpncpy crash fix (IDA 6.8)]
enabled=0 ; optional (default '1'), set to 0 to disable this patch
module=dll ; optional (default 'dll'), 'dll' will patch ida.dll or ida64.dll, 'exe' will patch ida.exe or ida64.exe, anything else will patch a module with that name (clp.dll will patch in clp.dll)
search=03 C8 3B C1 72 14 80 3D ; search pattern, nibble wildcards (so ?? for one wildcard byte)
replace=03 C8 3B C1 72 14 EB 30 ; replace pattern, nibble wildcards