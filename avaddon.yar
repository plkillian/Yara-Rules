import "pe"

rule Avaddon
{
	meta:
		vti_default_score = 5
		vti_documents_score = 5
		vti_scripts_score = 5
		vti_browser_score = 5
		vti_msi_score = 5
		vti_static_score = 5
		id = "gzIxctaiGZf4jXkwWO0BR"
		fingerprint = "ab5c7c5ea9d7d0587e8b2b327c138b2ba21ad6fbbef63f67935dab60f116088f"
		version = "1.0"
		creation_date = "2021-05-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies Avaddon ransomware."
		category = "MALWARE"
		malware = "AVADDON"
		malware_type = "RANSOMWARE"
		mitre_att = "S0640"

	strings:
		$s1 = "\"ext\":" ascii wide
		$s2 = "\"rcid\":" ascii wide
		$s3 = "\"hdd\":" ascii wide
		$s4 = "\"name\":" ascii wide
		$s5 = "\"size\":" ascii wide
		$s6 = "\"type\":" ascii wide
		$s7 = "\"lang\":" ascii wide
		$s8 = "\"ip\":" ascii wide
		$code = { 83 7f 14 10 8b c7 c7 4? ?? 00 00 00 00 72 ?? 8b 07 6a 00 6a 00 
    8d ?? f8 51 6a 00 6a 01 6a 00 50 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 56 
        8b 7? ?? ff 15 ?? ?? ?? ?? 56 6a 00 50 ff 15 ?? ?? ?? ?? 8b f0 85 
        f6 74 ?? 83 7f 14 10 72 ?? 8b 3f }

	condition:
		uint16(0)==0x5a4d and (5 of ($s*) or $code)
}


rule BlackKingDom
{
	meta:
		vti_default_score = 5
		vti_documents_score = 5
		vti_scripts_score = 5
		vti_browser_score = 5
		vti_msi_score = 5
		vti_static_score = 5
		id = "su4arxDGFAZfSHRVAv689"
		fingerprint = "504f4b0c26223ecc9af94b8e95cc80b777ba25ced07af89192e1777895460b2e"
		version = "1.0"
		creation_date = "2021-03-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies (decompiled) Black KingDom ransomware."
		category = "MALWARE"
		malware_type = "RANSOMWARE"

	strings:
		$ = "BLACLIST" ascii wide
		$ = "Black KingDom" ascii wide
		$ = "FUCKING_WINDOW" ascii wide
		$ = "PleasStopMe" ascii wide
		$ = "THE AMOUNT DOUBLED" ascii wide
		$ = "WOWBICH" ascii wide
		$ = "clear_logs_plz" ascii wide
		$ = "decrypt_file.TxT" ascii wide
		$ = "disable_Mou_And_Key" ascii wide
		$ = "encrypt_file" ascii wide
		$ = "for_fortnet" ascii wide
		$ = "start_encrypt" ascii wide
		$ = "where_my_key" ascii wide

	condition:
		3 of them
}


rule CryLock
{
	meta:
		vti_default_score = 5
		vti_documents_score = 5
		vti_scripts_score = 5
		vti_browser_score = 5
		vti_msi_score = 5
		vti_static_score = 5
		id = "2l4H1zr9CK35G8zGAmRQAk"
		fingerprint = "f3084da9bc523ee78f0a85e439326c2f4a348330bf228192ca07c543f5fb04ed"
		version = "1.0"
		creation_date = "2020-09-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies CryLock aka Cryakl ransomware."
		category = "MALWARE"
		malware = "CRYLOCK"
		malware_type = "RANSOMWARE"

	strings:
		$ = "///END ENCRYPT ONLY EXTENATIONS" ascii wide
		$ = "///END UNENCRYPT EXTENATIONS" ascii wide
		$ = "///END COMMANDS LIST" ascii wide
		$ = "///END PROCESSES KILL LIST" ascii wide
		$ = "///END SERVICES STOP LIST" ascii wide
		$ = "///END PROCESSES WHITE LIST" ascii wide
		$ = "///END UNENCRYPT FILES LIST" ascii wide
		$ = "///END UNENCRYPT FOLDERS LIST" ascii wide
		$ = "{ENCRYPTENDED}" ascii wide
		$ = "{ENCRYPTSTART}" ascii wide

	condition:
		2 of them
}


rule Darkside
{
	meta:
		vti_default_score = 5
		vti_documents_score = 5
		vti_scripts_score = 5
		vti_browser_score = 5
		vti_msi_score = 5
		vti_static_score = 5
		id = "5qjcs58k9iHd3EU3xv66sV"
		fingerprint = "57bc5c7353c8c518e057456b2317e1dbf59ee17ce69cd336f1bacaf627e9efd5"
		version = "1.0"
		creation_date = "2021-05-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies Darkside ransomware."
		category = "MALWARE"
		malware = "DARKSIDE"
		malware_type = "RANSOMWARE"

	strings:
		$ = "darkside_readme.txt" ascii wide
		$ = "[ Welcome to DarkSide ]" ascii wide
		$ = { 66 c7 04 47 2a 00 c7 44 47 02 72 00 65 00 c7 44 47 06 63 00 79 00 c7 44 47 0a 63 00 6c 00 c7 44 47 0e 65 00 2a 00 66 c7 44 47 12 00 00 }
		$ = { c7 00 2a 00 72 00 c7 40 04 65 00 63 00 c7 40 08 79 00 63 00 c7 40 0c 6c 00 65 00 c7 40 10 2a 00 00 00 }

	condition:
		any of them
}


rule DearCry
{
	meta:
		vti_default_score = 5
		vti_documents_score = 5
		vti_scripts_score = 5
		vti_browser_score = 5
		vti_msi_score = 5
		vti_static_score = 5
		id = "6wHCvbraYF2t1m7FWnjepd"
		fingerprint = "ce3c2631969e462acd01b9dc26fd03985076add51f8478e76aca93f260a020d8"
		version = "1.0"
		creation_date = "2021-03-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies DearCry ransomware."
		category = "MALWARE"
		malware = "DEARCRY"
		malware_type = "RANSOMWARE"
		reference = "https://twitter.com/MsftSecIntel/status/1370236539427459076"

	strings:
		$pdb = "C:\\Users\\john\\Documents\\Visual Studio 2008\\Projects\\EncryptFile -svcV2\\Release\\EncryptFile.exe.pdb" ascii wide
		$key = {4D 49 49 42 43 41 4B 43 41 51 45 41 79 4C 42 43 6C 7A 39 68 73 46 47 52 66 39 66 6B 33 7A 30 7A 6D 59 32 72 7A 32 4A 31 
    71 71 47 66 56 34 38 44 53 6A 50 56 34 6C 63 77 6E 68 43 69 34 2F 35 2B 0A 43 36 55 73 41 68 6B 2F 64 49 34 2F 35 48 77 62 66 5A 
    42 41 69 4D 79 53 58 4E 42 33 44 78 56 42 32 68 4F 72 6A 44 6A 49 65 56 41 6B 46 6A 51 67 5A 31 39 42 2B 4B 51 46 57 6B 53 6F 31 
    75 62 65 0A 56 64 48 6A 77 64 76 37 34 65 76 45 2F 75 72 39 4C 76 39 48 4D 2B 38 39 69 5A 64 7A 45 70 56 50 4F 2B 41 6A 4F 54 74 
    73 51 67 46 4E 74 6D 56 65 63 43 32 76 6D 77 39 6D 36 30 64 67 79 52 2F 31 0A 43 4A 51 53 67 36 4D 6F 62 6C 6F 32 4E 56 46 35 30 
    41 4B 33 63 49 47 32 2F 6C 56 68 38 32 65 62 67 65 64 58 73 62 56 4A 70 6A 56 4D 63 30 33 61 54 50 57 56 34 73 4E 57 6A 54 4F 33 
    6F 2B 61 58 0A 36 5A 2B 56 47 56 4C 6A 75 76 63 70 66 4C 44 5A 62 33 74 59 70 70 6B 71 5A 7A 41 48 66 72 43 74 37 6C 56 30 71 4F
    34 37 46 56 38 73 46 43 6C 74 75 6F 4E 69 4E 47 4B 69 50 30 38 34 4B 49 37 62 0A 33 58 45 4A 65 70 62 53 4A 42 33 55 57 34 6F 34 
    43 34 7A 48 46 72 71 6D 64 79 4F 6F 55 6C 6E 71 63 51 49 42 41 77 3D 3D}

	condition:
		any of them
}


rule Ekans
{
	meta:
		vti_default_score = 5
		vti_documents_score = 5
		vti_scripts_score = 5
		vti_browser_score = 5
		vti_msi_score = 5
		vti_static_score = 5
		id = "6Kzy2bA2Zj7kvpXriuZ14m"
		fingerprint = "396b915c02a14aa809060946c9294f487a5107ab37ebefb6d5cde07de4113d43"
		version = "1.0"
		creation_date = "2020-03-01"
		first_imported = "2021-12-30"
		last_modified = "2023-12-24"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies Ekans aka Snake ransomware unpacked or in memory."
		category = "MALWARE"
		malware = "EKANS"
		malware_type = "RANSOMWARE"

	strings:
		$ = "already encrypted!" ascii wide
		$ = "error encrypting %v : %v" ascii wide
		$ = "faild to get process list" ascii wide
		$ = "There can be only one" ascii wide fullword
		$ = "total lengt: %v" ascii wide fullword

	condition:
		3 of them
}


rule Fusion
{
	meta:
		vti_default_score = 5
		vti_documents_score = 5
		vti_scripts_score = 5
		vti_browser_score = 5
		vti_msi_score = 5
		vti_static_score = 5
		id = "5zeDUSWAX6101brsHGmiNB"
		fingerprint = "a1e5d90fc057d3d32754d241df9b1847eaad9e67e4b54368c28ee179a796944e"
		version = "1.0"
		creation_date = "2021-06-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies Fusion ransomware, Go variant of Nemty/Nefilim."
		category = "MALWARE"
		malware = "FUSION"
		malware_type = "RANSOMWARE"

	strings:
		$s1 = "main.getdrives" ascii wide
		$s2 = "main.SaveNote" ascii wide
		$s3 = "main.FileSearch" ascii wide
		$s4 = "main.BytesToPublicKey" ascii wide
		$s5 = "main.GenerateRandomBytes" ascii wide
		$x1 = /Fa[i1]led to fi.Close/ ascii wide
		$x2 = /Fa[i1]led to fi2.Close/ ascii wide
		$x3 = /Fa[i1]led to get stat/ ascii wide
		$x4 = /Fa[i1]led to os.OpenFile/ ascii wide
		$pdb1 = "C:/OpenServer/domains/build/aes.go" ascii wide
		$pdb2 = "C:/Users/eugene/Desktop/test go/test.go" ascii wide
		$pdb3 = "C:/Users/eugene/Desktop/web/src/aes_" ascii wide

	condition:
		4 of ($s*) or 3 of ($x*) or any of ($pdb*)
}


rule Maze
{
	meta:
		vti_default_score = 5
		vti_documents_score = 5
		vti_scripts_score = 5
		vti_browser_score = 5
		vti_msi_score = 5
		vti_static_score = 5
		id = "4sTbmIEE40nSKc9rOEz4po"
		fingerprint = "305df5e5f0a4d5660dff22073881e65ff25528895abf26308ecd06dd70a97ec2"
		version = "1.0"
		creation_date = "2019-11-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies Maze ransomware in memory or unpacked."
		category = "MALWARE"
		malware = "MAZE"
		malware_type = "RANSOMWARE"
		mitre_att = "S0449"

	strings:
		$ = "Enc: %s" ascii wide
		$ = "Encrypting whole system" ascii wide
		$ = "Encrypting specified folder in --path parameter..." ascii wide
		$ = "!Finished in %d ms!" ascii wide
		$ = "--logging" ascii wide
		$ = "--nomutex" ascii wide
		$ = "--noshares" ascii wide
		$ = "--path" ascii wide
		$ = "Logging enabled | Maze" ascii wide
		$ = "NO SHARES | " ascii wide
		$ = "NO MUTEX | " ascii wide
		$ = "Encrypting:" ascii wide
		$ = "You need to buy decryptor in order to restore the files." ascii wide
		$ = "Dear %s, your files have been encrypted by RSA-2048 and ChaCha algorithms" ascii wide
		$ = "%s! Alert! %s! Alert! Dear %s Your files have been encrypted by %s! Attention! %s" ascii wide
		$ = "DECRYPT-FILES.txt" ascii wide fullword

	condition:
		5 of them
}


rule Pysa
{
	meta:
		vti_default_score = 5
		vti_documents_score = 5
		vti_scripts_score = 5
		vti_browser_score = 5
		vti_msi_score = 5
		vti_static_score = 5
		id = "240byxdCwyzaTk3xgjzbEa"
		fingerprint = "7f8819e9f76b9c97e90cd5da7ea788c9bb1eb135d8e1cb8974d6f17ecf51b3c3"
		version = "1.0"
		creation_date = "2021-03-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies Pysa aka Mespinoza ransomware."
		category = "MALWARE"
		malware = "PYSA"
		malware_type = "RANSOMWARE"
		mitre_att = "S0583"

	strings:
		$code = { 8a 0? 41 84 c0 75 ?? 2b ce 8b 35 ?? ?? ?? ?? 8d 41 01 50 5? 6a 07 6a 00 68 ?? ?? ?? 
    ?? ff 7? ?? ff d? 6a 05 68 ?? ?? ?? ?? 6a 07 6a 00 68 ?? ?? ?? ?? ff 7? ?? ff d? ff 7? ?? ff 
    15 ?? ?? ?? ?? 8b 4? ?? 33 cd 5e e8 ?? ?? ?? ?? 8b e5 5d c3 }
		$s1 = "n.pysa" ascii wide fullword
		$s2 = "%s\\Readme.README" ascii wide
		$s3 = "Every byte on any types of your devices was encrypted." ascii wide

	condition:
		$code or 2 of ($s*)
}


rule RagnarLocker
{
	meta:
		vti_default_score = 5
		vti_documents_score = 5
		vti_scripts_score = 5
		vti_browser_score = 5
		vti_msi_score = 5
		vti_static_score = 5
		id = "5066KiqBNrcicJGfWPfDx5"
		fingerprint = "fd403ea38a9c6c269ff7b72dea1525010f44253a41e72bf3fce55fa4623245a3"
		version = "1.0"
		creation_date = "2020-07-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies RagnarLocker ransomware unpacked or in memory."
		category = "MALWARE"
		malware = "RAGNAR LOCKER"
		malware_type = "RANSOMWARE"
		mitre_att = "S0481"

	strings:
		$ = "RAGNRPW" ascii wide
		$ = "---END KEY R_R---" ascii wide
		$ = "---BEGIN KEY R_R---" ascii wide

	condition:
		any of them
}



rule REvil_Cert
{
	meta:
		vti_default_score = 5
		vti_documents_score = 5
		vti_scripts_score = 5
		vti_browser_score = 5
		vti_msi_score = 5
		vti_static_score = 5
		id = "4KM2J6a6EP4OW0GGQEaBiI"
		fingerprint = "ab9783909f458776d59b75d74f885dfebcc543b690c5e46b738a28f25d651a9c"
		version = "1.0"
		creation_date = "2021-07-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies the digital certificate PB03 TRANSPORT LTD, used by REvil in the Kaseya supply chain attack."
		category = "MALWARE"
		malware = "REVIL"
		malware_type = "RANSOMWARE"
		mitre_att = "S0496"
		reference = "https://community.sophos.com/b/security-blog/posts/active-ransomware-attack-on-kaseya-customers"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial=="11:9a:ce:ad:66:8b:ad:57:a4:8b:4f:42:f2:94:f8:f0")
}


rule REvil_Dropper
{
	meta:
		vti_default_score = 5
		vti_documents_score = 5
		vti_scripts_score = 5
		vti_browser_score = 5
		vti_msi_score = 5
		vti_static_score = 5
		id = "77UKzYTt79Q5WVUpRQgOiK"
		fingerprint = "0b55e00e07c49e450fa643b5c8f4c1c03697c0f15d8f95c709e9b1a3cf2340ed"
		version = "1.0"
		creation_date = "2021-07-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies the dropper used by REvil in the Kaseya supply chain attack."
		category = "MALWARE"
		malware = "REVIL"
		malware_type = "RANSOMWARE"
		mitre_att = "S0496"
		reference = "https://community.sophos.com/b/security-blog/posts/active-ransomware-attack-on-kaseya-customers"
		hash = "d55f983c994caa160ec63a59f6b4250fe67fb3e8c43a388aec60a4a6978e9f1e"

	strings:
		$ = { 55 8b ec 56 8b 35 24 d0 40 00 68 04 1c 41 00 6a 65 6a 00 ff 
     d6 85 c0 0f 84 98 00 00 00 50 6a 00 ff 15 20 d0 40 00 85 c0 0f 84 
      87 00 00 00 50 ff 15 18 d0 40 00 68 14 1c 41 00 6a 66 6a 00 a3 a0 
      43 41 00 ff d6 85 c0 74 6c 50 33 f6 56 ff 15 20 d0 40 00 85 c0 74 
      5e 50 ff 15 18 d0 40 00 68 24 1c 41 00 ba 88 55 0c 00 a3 a4 43 41 
      00 8b c8 e8 9a fe ff ff 8b 0d a0 43 41 00 ba d0 56 00 00 c7 04 ?4 
      38 1c 41 00 e8 83 fe ff ff c7 04 ?4 ec 43 41 00 68 a8 43 41 00 56 
      56 68 30 02 00 00 56 56 56 ff 75 10 c7 05 a8 43 41 00 44 00 00 00 
      50 ff 15 28 d0 40 00 }
		$ = { 55 8b ec 83 ec 08 e8 55 ff ff ff 85 c0 75 04 33 c0 eb 67 68 
    98 27 41 00 68 68 b7 0c 00 a1 f4 32 41 00 50 e8 58 fe ff ff 83 c4 
    0c 89 45 f8 68 80 27 41 00 68 d0 56 00 00 8b 0d f0 32 41 00 51 e8 
    3c fe ff ff 83 c4 0c 89 45 fc c7 05 f8 32 41 00 44 00 00 00 68 3c 
    33 41 00 68 f8 32 41 00 6a 00 6a 00 6a 08 6a 00 6a 00 6a 00 8b 55 
    10 52 8b 45 fc 50 ff 15 28 c0 40 00 33 c0 }

	condition:
		any of them
}


rule Satan_Mutexes
{
	meta:
		vti_default_score = 5
		vti_documents_score = 5
		vti_scripts_score = 5
		vti_browser_score = 5
		vti_msi_score = 5
		vti_static_score = 5
		id = "4jKp8prwufSCRdyuJPHFX3"
		fingerprint = "4c325bd0f020e626a484338a3f88cbcf6c14bfa10201e52c2fde8c7c331988fb"
		version = "1.0"
		creation_date = "2020-01-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies Satan ransomware (and its variants) by mutex."
		category = "MALWARE"
		malware = "SATAN"
		malware_type = "RANSOMWARE"
		reference = "https://bartblaze.blogspot.com/2020/01/satan-ransomware-rebrands-as-5ss5c.html"

	strings:
		$ = "SATANAPP" ascii wide
		$ = "SATAN_SCAN_APP" ascii wide
		$ = "STA__APP" ascii wide
		$ = "DBGERAPP" ascii wide
		$ = "DBG_CPP" ascii wide
		$ = "run_STT" ascii wide
		$ = "SSS_Scan" ascii wide
		$ = "SSSS_Scan" ascii wide
		$ = "5ss5c_CRYPT" ascii wide

	condition:
		any of them
}


rule Sfile
{
	meta:
		vti_default_score = 5
		vti_documents_score = 5
		vti_scripts_score = 5
		vti_browser_score = 5
		vti_msi_score = 5
		vti_static_score = 5
		id = "64arpb3yJ0mZxamCG9jIVs"
		fingerprint = "7a2be690f14a9ea61917c2c31b4d44186295de7d8a1342f081ed9507a8ac46b0"
		version = "1.0"
		creation_date = "2020-09-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies Sfile aka Escal ransomware."
		category = "MALWARE"
		malware_type = "RANSOMWARE"

	strings:
		$pdb = "D:\\code\\ransomware_win\\bin\\ransomware.pdb" ascii wide
		$ = "%s SORTING time : %s" ascii wide
		$ = "%ws -> WorkModeDecryptFiles : %d of %d files decrypted +%d (%d MB)..." ascii wide
		$ = "%ws -> WorkModeEncryptFiles : %d of %d files encrypted +%d [bps : %d, size = %d MB] (%d skipped, ld = %d.%d.%d %d:%d:%d, lf = %ws)..." ascii wide
		$ = "%ws -> WorkModeEnded" ascii wide
		$ = "%ws -> WorkModeFindFiles : %d files / %d folders found (already (de?)crypted %d/%d) (lf = %ws)..." ascii wide
		$ = "%ws -> WorkModeSorting" ascii wide
		$ = "%ws ENCRYPTFILES count : %d (%d skipped), time : %s" ascii wide
		$ = "%ws FINDFILES RESULTS : dwDirectoriesCount = %d, dwFilesCount = %d MB = %d (FIND END)" ascii wide
		$ = "%ws FINDFILES time : %s" ascii wide
		$ = "DRIVE_FIXED : %ws" ascii wide
		$ = "EncryptDisk(%ws) DONE" ascii wide
		$ = "ScheduleRoutine() : gogogo" ascii wide
		$ = "ScheduleRoutine() : waiting for sacred time... Expecting %d hours, now id %d" ascii wide
		$ = "WARN! FileLength more then memory has %ws" ascii wide
		$ = "WaitForHours() : gogogo" ascii wide
		$ = "WaitForHours() : waiting for sacred time... Expecting %d hours, now id %d" ascii wide
		$ = "Your network has been penetrated." ascii wide
		$ = "--kill-susp" ascii wide
		$ = "--enable-shares" ascii wide

	condition:
		$pdb or 3 of them
}


rule WhiteBlack
{
	meta:
		vti_default_score = 5
		vti_documents_score = 5
		vti_scripts_score = 5
		vti_browser_score = 5
		vti_msi_score = 5
		vti_static_score = 5
		id = "7TdI06IvZtnFNYtUZ7ZD4X"
		fingerprint = "4b5caed33ff2cb41dea4dbe77f84a536d91b92b5837c439a50ebfdcce28fd701"
		version = "1.0"
		creation_date = "2022-01-01"
		first_imported = "2022-02-03"
		last_modified = "2022-02-03"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies WhiteBlack ransomware."
		category = "MALWARE"
		malware_type = "RANSOMWARE"
		malware = "WHITEBLACK"
		reference = "https://twitter.com/siri_urz/status/1377877204776976384"

	strings:
		$ = { 55 57 56 53 4? 83 ec 28 31 db bd 00 01 00 00 89 cf 31 c9 ff 15 ?? ?? ?? ?? 89 c1 e8 ?? ?? ?? ?? 4? 63 cf e8 ?? ?? ?? ?? 4? 89 c6 39 df 7e ?? e8 ?? ?? ?? ?? 99 f7 fd 88 14 1e 4? ff c3 eb ?? 4? 89 f0 4? 83 c4 28 5b 5e 5f 5d c3 4? 55 4? 54 55 57 56 53 4? 83 ec 28 4? 8d 15 ?? ?? ?? ?? 31 f6 4? 8d 2d ?? ?? ?? ?? 4? 89 cd e8 ?? ?? ?? ?? b9 00 00 00 02 4? 89 c3 e8 ?? ?? ?? ?? 4? 89 c7 4? 89 d9 4? b8 00 00 00 02 ba 01 00 00 00 4? 89 f9 e8 ?? ?? ?? ?? 85 c0 4? 89 c4 74 ?? 81 fe ff ff ff 3f 7f ?? 4? 89 e0 4? 89 fa 4? 89 e? e8 ?? ?? ?? ?? 4? 31 c0 89 f2 4? 89 d9 e8 ?? ?? ?? ?? 4? 01 e6 4? 63 c4 4? 89 f9 4? 89 d9 ba 01 00 00 00 e8 ?? ?? ?? ?? 4? 31 c0 89 f2 4? 89 d9 e8 ?? ?? ?? ?? eb ?? 4? 89 f9 4? 89 ef e8 ?? ?? ?? ?? 4? 89 d9 e8 ?? ?? ?? ?? 31 c0 4? 83 c9 ff f2 ae 4? 89 ce 4? f7 d6 4? 89 f1 4? 83 c1 09 e8 ?? ?? ?? ?? 4? 89 ea 4? 89 c1 e8 ?? ?? ?? ?? 4? 8d 15 ?? ?? ?? ?? 4? 89 c1 e8 ?? ?? ?? ?? 4? 89 e9 4? 89 c2 4? 83 c4 28 }

	condition:
		any of them
}


rule WickrMe
{
	meta:
		vti_default_score = 5
		vti_documents_score = 5
		vti_scripts_score = 5
		vti_browser_score = 5
		vti_msi_score = 5
		vti_static_score = 5
		id = "6yM5V73btyHP2BBFhj8cXv"
		fingerprint = "1c7f8412455ea211f7a1606f49151be31631c17f37a612fb3942aff075c7ddaa"
		version = "1.0"
		creation_date = "2021-04-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies WickrMe (aka Hello) ransomware."
		category = "MALWARE"
		malware = "WICKRME"
		malware_type = "RANSOMWARE"
		reference = "https://www.trendmicro.com/en_ca/research/21/d/hello-ransomware-uses-updated-china-chopper-web-shell-sharepoint-vulnerability.html"

	strings:
		$ = "[+] Config Service..." ascii wide
		$ = "[+] Config Services Finished" ascii wide
		$ = "[+] Config Shadows Finished" ascii wide
		$ = "[+] Delete Backup Files..." ascii wide
		$ = "[+] Generate contact file {0} successfully" ascii wide
		$ = "[+] Generate contact file {0} failed! " ascii wide
		$ = "[+] Get Encrypt Files..." ascii wide
		$ = "[+] Starting..." ascii wide
		$ = "[-] No Admin Rights" ascii wide
		$ = "[-] Exit" ascii wide

	condition:
		4 of them
}


rule WinLock
{
	meta:
		vti_default_score = 5
		vti_documents_score = 5
		vti_scripts_score = 5
		vti_browser_score = 5
		vti_msi_score = 5
		vti_static_score = 5
		id = "3MQTREUk3DgifGki8sa7hl"
		fingerprint = "6d659e5dc636a9535d07177776551ae3b32eae97b86e3e7dd01d74d0bbe33c82"
		version = "1.0"
		creation_date = "2020-08-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies WinLock (aka Blocker) ransomware variants generically."
		category = "MALWARE"
		malware = "WINLOCK"
		malware_type = "RANSOMWARE"

	strings:
		$s1 = "twexx32.dll" ascii wide
		$s2 = "s?cmd=ul&id=%s" ascii wide
		$s3 = "card_ukash.png" ascii wide
		$s4 = "toneo_card.png" ascii wide
		$pdb = "C:\\Kuzja 1.4\\vir.vbp" ascii wide
		$x1 = "AntiWinLockerTray.exe" ascii wide
		$x2 = "Computer name:" ascii wide
		$x3 = "Current Date:" ascii wide
		$x4 = "Information about blocking" ascii wide
		$x5 = "Key Windows:" ascii wide
		$x6 = "Password attempts:" ascii wide
		$x7 = "Registered on:" ascii wide
		$x8 = "ServiceAntiWinLocker.exe" ascii wide
		$x9 = "Time of Operation system:" ascii wide
		$x10 = "To removing the system:" ascii wide

	condition:
		3 of ($s*) or $pdb or 5 of ($x*)
}


rule XiaoBa
{
	meta:
		vti_default_score = 5
		vti_documents_score = 5
		vti_scripts_score = 5
		vti_browser_score = 5
		vti_msi_score = 5
		vti_static_score = 5
		id = "7HQbk7TyDS3DhwWOktZe9t"
		fingerprint = "d41a019709801bbbc4284b27fd7f582ed1db624415cb28b88a7cdf5b0c3331b2"
		version = "1.0"
		creation_date = "2019-09-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies XiaoBa ransomware unpacked or in memory."
		category = "MALWARE"
		malware = "XIAOBA"
		malware_type = "RANSOMWARE"

	strings:
		$ = "BY:TIANGE" ascii wide
		$ = "Your disk have a lock" ascii wide
		$ = "Please enter the unlock password" ascii wide
		$ = "Please input the unlock password" ascii wide
		$ = "I am very sorry that all your files have been encrypted" ascii wide

	condition:
		any of them
}


rule Zeppelin
{
	meta:
		vti_default_score = 5
		vti_documents_score = 5
		vti_scripts_score = 5
		vti_browser_score = 5
		vti_msi_score = 5
		vti_static_score = 5
		id = "RIttcGgKqwaotJyTgah7j"
		fingerprint = "a4da7defafa7f510df1c771e3d67bf5d99f3684a44f56d2b0e6f40f0a7fea84f"
		version = "1.0"
		creation_date = "2019-11-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies Zeppelin ransomware and variants (Buran, Vega etc.)"
		category = "MALWARE"
		malware = "ZEPPELIN"
		malware_type = "RANSOMWARE"

	strings:
		$s1 = "TUnlockAndEncryptU" ascii wide
		$s2 = "TDrivesAndShares" ascii wide
		$s3 = "TExcludeFoldersU" ascii wide
		$s4 = "TExcludeFiles" ascii wide
		$s5 = "TTaskKillerU" ascii wide
		$s6 = "TPresenceU" ascii wide
		$s7 = "TSearcherU" ascii wide
		$s8 = "TReadme" ascii wide
		$s9 = "TKeyObj" ascii wide
		$x = "TZeppelinU" ascii wide

	condition:
		2 of ($s*) or $x
}