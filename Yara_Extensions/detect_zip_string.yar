rule detect_zip_extension {
    meta:
        author = ""
        description = "Detects presence of .zip string in file text"
        date = ""
        version = "1.0"
    strings:
        $ext = ".zip"
    condition:
        $ext
}
