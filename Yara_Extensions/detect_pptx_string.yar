rule detect_pptx_extension {
    meta:
        author = ""
        description = "Detects presence of .pptx string in file text"
        date = ""
        version = "1.0"
    strings:
        $ext = ".pptx"
    condition:
        $ext
}
