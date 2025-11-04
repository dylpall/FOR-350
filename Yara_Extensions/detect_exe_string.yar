rule detect_exe_extension {
    meta:
        author = ""
        description = "Detects presence of .exe string in file text"
        date = ""
        version = "1.0"
    strings:
        $ext = ".exe"
    condition:
        $ext
}
