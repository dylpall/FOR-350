rule detect_xlsx_extension {
    meta:
        author = ""
        description = "Detects presence of .xlsx string in file text"
        date = ""
        version = "1.0"
    strings:
        $ext = ".xlsx"
    condition:
        $ext
}
