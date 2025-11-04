rule detect_htm_extension {
    meta:
        author = ""
        description = "Detects presence of .htm string in file text"
        date = ""
        version = "1.0"
    strings:
        $ext = ".htm"
    condition:
        $ext
}
