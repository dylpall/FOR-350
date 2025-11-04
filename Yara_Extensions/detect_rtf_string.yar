rule detect_rtf_extension {
    meta:
        author = ""
        description = "Detects presence of .rtf string in file text"
        date = ""
        version = "1.0"
    strings:
        $ext = ".rtf"
    condition:
        $ext
}
