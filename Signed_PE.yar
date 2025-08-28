import "pe"

rule pe_signed {
    meta:
        description = "Try to find a valid signature in a pefile(not a full chain verification)"
        author = "XiAnzheng"

    condition:
        pe.number_of_signatures > 0 and pe.is_signed
}