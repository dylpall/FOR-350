rule detect_lnk_extension {
    meta:
        author = ""
        description = "Detects presence of .lnk string in file text"
        date = ""
        version = "1.0"
    strings:
        $ext = ".lnk"
    condition:
        $ext
}
