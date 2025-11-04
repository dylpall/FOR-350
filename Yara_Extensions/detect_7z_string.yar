rule detect_7z_extension {
    meta:
        author = ""
        description = "Detects presence of .7z string in file text"
        date = ""
        version = "1.0"
    strings:
        $ext = ".7z"
    condition:
        $ext
}
