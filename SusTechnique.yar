import "pe"

rule Sus_Obf_Enc_Spoof_Hide_PE {

    meta:
        author = "XiAnzheng"
        source_url = "https://github.com/XiAnzheng-ID/Yara-Rules"
        description = "Check for Suspicious, Obfuscating, Encrypting, Spoofing, or Hiding Technique(can create FP)"
        date = "2024-11-18"
        yarahub_license = "CC0 1.0"
        yarahub_uuid = "fa466824-f124-45bc-8398-eaecef7271f9"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "ffea1266b09abbf0ceb59119746d8630"


    condition:
        // Missing or suspicious Import/Export tables combination
        pe.number_of_imports == 0
        or (pe.number_of_imports == 0 and pe.entry_point_raw == 0)
        or (pe.size_of_optional_header < 0xE0 or pe.size_of_optional_header > 0xF0)
        or ((pe.number_of_exports != 0 and pe.number_of_imports == 0) or (pe.number_of_exports == 0 and pe.number_of_imports != 0))

        // Suspicious Entry Point
        or (pe.entry_point < pe.image_base or pe.entry_point > (pe.image_base + pe.size_of_image))

        // Suspicious Section Headers Number
        or (pe.number_of_sections == 0 or pe.number_of_sections < 0 or pe.number_of_sections > 10)

        // Overlay File
        or (filesize > pe.size_of_image + 0x1000)

        // Invalid Header PE
        or (pe.size_of_headers < 0x200 or pe.size_of_headers > 0x400)
}