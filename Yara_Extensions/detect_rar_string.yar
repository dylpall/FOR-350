rule detect_rar_extension {
    meta:
        author = ""
        description = "Detects presence of .rar string in file text"
        date = ""
        version = "1.0"
    strings:
        $ext = ".rar"
    condition:
        $ext
}
