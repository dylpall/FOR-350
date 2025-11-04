rule detect_docx_extension {
    meta:
        author = ""
        description = "Detects presence of .docx string in file text"
        date = ""
        version = "1.0"
    strings:
        $ext = ".docx"
    condition:
        $ext
}
