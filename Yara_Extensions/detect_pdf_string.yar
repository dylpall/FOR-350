rule detect_pdf_extension {
    meta:
        author = ""
        description = "Detects presence of .pdf string in file text"
        date = ""
        version = "1.0"
    strings:
        $ext = ".pdf"
    condition:
        $ext
}
