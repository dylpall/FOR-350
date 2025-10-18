rule is_Downloader2 { //image_downloader.exe
	meta:
		description = "Detects Image Downloader based on file headers, unique strings, files, and addresses"
		author = "Dylan Pallatroni"
		editor = "N/A"
		date = "2025-10-17"
	strings:
		$name = "ImageDownloader/"
		$ip = "165.73.244.11"
		$image = "frontpage.jpg"
		$ft_pe = { 4D 5A }
	condition:
		$name and 
		$ip and
		$image and
		$ft_pe at 0 
}

rule is_OfficeAutoOpen { //SecurityAdvisory.docm
	meta:
		description = "Detects Microsoft Office files with VBA Macros set to AutoOpen using a file header and files associated with VBA"
		author = "Dylan Pallatroni"
		editor = "N/A"
		date = "2025-10-17"
	strings:    
		$zip = { 50 4B 03 04 }
		$vba_data = "vbaData.xml"
		$vba_rel = "vbaProject.bin.rels"
		$vba = "vbaProject.bin"
	condition:
		$zip at 0 and
		all of ($vba*)
}

rule is_Packed2 { //Volt.wav
	meta:
		description = "Detects Packed file using a unique string, packer headers, file headers, and file trailers"
		author = "Dylan Pallatroni"
		editor = "N/A"
		date = "2025-10-17"
	strings:
		$packer = "SR"
		$ft_jpeg = { FF D8 FF }
		$tr_jpeg = { FF D9 }
		$string = "Google"
	condition:
		$string and
		$packer and
		$ft_jpeg at 0 and
		$tr_jpeg at (filesize - 2)
}
rule is_based64 { //frontpage.jpg
	meta:
		description = "Detects Encoded File using its file headers, command structure, unique IP address, and filepath"
		author = "Dylan Pallatroni"
		editor = "N/A"
		date = "2025-10-17"	
	strings:
		$ft_jpeg = { FF D8 FF }
		$tr_jpeg = { FF D9 }
		$command = "cmd /c powershell invoke-webrequest -uri" base64
		$address = "'http://108.181.155.31/asefa.bat'" base64 
		$path = "'c:\\programdata\\asefa.bat'" base64
	condition:
		$ft_jpeg at 0 and
		$tr_jpeg at (filesize - 2) and
		$command and 
		$address and 
		$path

}
