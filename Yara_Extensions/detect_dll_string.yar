rule detect_dll_extension {
    meta:
        author = ""
        description = "Detects presence of .dll string in file text"
        date = ""
        version = "1.0"
    strings:
        $ext = ".dll"
    condition:
        $ext
}
