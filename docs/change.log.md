CHANGE.LOG
	
	.___.__  .__               .__            ___________            
	|   |  | |  |  __ __  _____|__|__  __ ____\_   _____/___   ____  
	|   |  | |  | |  |  \/  ___/  \  \/ // __ \|    __)/  _ \ / ___\ 
	|   |  |_|  |_|  |  /\___ \|  |\   /\  ___/|     \(  <_> ) /_/  >
	|___|____/____/____//____  >__| \_/  \___  >___  / \____/\___  / 
                         \/              \/    \/       /_____/     
		Socks5 Proxy Based Administrator Level IMPLANT

1.0 Beta - MaskedMan
========
    *Date: 3/07/2020

            C2 Server: 
            =========

            * Added support for Sqlite3
            * Multi Threading added. Can connect and manage multiple clients at a single instance.
            * Socks5 Proxy Support Added.
            * Flask Added for HTTP/S based communications.
            * Added Config.ini for basic configuration settings.

                To;Do:
                ======
                * Add Signature database to detect shellcodes. Mainly related to metasploit and other public frameworks to avoid detections.
                * Extend database management to reset and other possible functionalities.
                * add support for plugins to host.
            
            Client:
            ======
            * Fill it here

                To;Do:
                =====
                * Fill it here

    
    *Date: 13/07/2020


            C2 Server:
            =========
            * Added better support for configuration.
            * Added `OPSEC_SAFETY` attribute in configuration in case OPSEC checks aren't required.
            * Added Signature database to detect shellcodes. Mainly related to metasploit and other public frameworks to avoid detections.
            * Added support for plugins. Yet to be enhanced more
            * Added base64 Send-Receive Encoded communication
            * Decoy page support added. `DECOY_PAGE` in configuration file.(Needed to be extended more)
            * Added Commands: resetdb, jobdel, remove.
            * Patched Bug(1.A) related to Multiple jobs deletion related to particular victim. 
            * Added Job-IDs to patch bug(1.A) and separate operations handeling.
            * Added `PLUGINS_PATH` in case custom path for plugins folder is set.
            * Added Support for OS detection.
                
                To;Do:
                ======
                * Add Extended support for database.(if needed)
                * Add encrypted communication.
                * Encrypt Plugins when start.
                * Add support for download and execute dll/exe.
                * Add plugin for advanced recon.
                * Add vt lookup support.
                * Add oneliner's and command line signature detections.
                * Add command exec support.

            Client:
            ======
            * Fill it here

                To;Do:
                =====
                * Fill it here

    
    *Date:  15/07/2020

            C2 Server: 
            =========
            * Added vt lookup support.
            * Added oneliner's and command line signature detections.
            * Added command exec support.
            * Added `UnldPlug` to arbitrarily unload plugins on client.
            * Added support for download and execute dll/exe. 
                
                To;Do:
                ======
                * Add Extended support for database.(if needed)
                * Add encrypted communication.
                * Add plugin for advanced recon.
                * Add plugin for Event Clearing
                * Encrypt Plugins when job is served to client. Each client/victim will have its own private keys. keys will be stored in db on first knock.

            Client:
            ======
            * Custom class for memory managment
            * Custom class for implant's apis
            * Cutom class for plugin load
            * Unhandled exception handlers, in-case corrupted shellcode or plugin gets loaded,it would still survive and run just like before
            * Sends corrupted shellcode message or plugin to c2
            * Memory safe considerations
            * Memory leaks patched ,only static memory are external global ones which requeires to be written to export(Socketip,destip,socketport,destport)
            * Shellcode injection is done.
                
                To;Do:
                =====
                * Evtx file parsing will be done this week
                * selfsocks will be done this week(as soon as i get c2 updates)
                * Persistence will be done this week
                * Shell(CreateProcess)is done,(need to fix a bug for sending results)
                * SSL/TLS support for selfsocks pushed to next week.
    *Date:  
            C2 Server: 
            =========
            * AES_CBC encryption integrated.
            * Added Random 12 Character long random keys for each client.
            * Separate keys for Communication and plugin encryption.
            * Full Duplex encrypted communication.
            * Patched Bug 1.B for `resetdb` relative db path in linux.
            * Added plugin support for ETW logs clearing.
            * Added Pellets for support of default config for plugins and plugins utils.

                To;Do:
                ======
                * Add Extended support for database.(if needed)
                * Add modular support for persistence and future expansation of implant.

            Client:
            ======

                To;Do:
                =====
