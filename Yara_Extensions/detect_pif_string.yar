rule detect_pif_extension {
    meta:
        author = ""
        description = "Detects presence of .pif string in file text"
        date = ""
        version = "1.0"
    strings:
        $ext = ".pif"
    condition:
        $ext
}
