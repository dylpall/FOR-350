rule detect_html_extension {
    meta:
        author = ""
        description = "Detects presence of .html string in file text"
        date = ""
        version = "1.0"
    strings:
        $ext = ".html"
    condition:
        $ext
}
