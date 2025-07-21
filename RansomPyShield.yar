rule RansomPyShield_Antiransomware {

    meta:
        author = "XiAnzheng"
        source_url = "https://github.com/XiAnzheng-ID/RansomPyShield-Antiransomware"
        description = "Check for Suspicious String and Import combination that Ransomware mostly abuse(can create FP)"
        date = "2024-11-07"
        updated = "2024-11-20"
        yarahub_license = "CC0 1.0"
        yarahub_uuid = "3295ce35-cb35-4203-bb37-7503ddf111c5"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "16f76e17d64f5ee805031ddf9f862f59"

    strings:
		// Commonly used by ransomware
        $tor1 = ".onion" nocase wide ascii
        $tor2 = "torproject.org" nocase wide ascii
		$string1 = "encrypted" nocase wide ascii
        $string2 = "decrypted" nocase wide ascii
        $string3 = "infected" nocase wide ascii
        $string4 = "locked" nocase wide ascii
        $string5 = "victim" nocase wide ascii
        $string6 = "encrypt" nocase wide ascii
        $string7 = "decrypt" nocase wide ascii
        $string8 = "bitcoin" nocase wide ascii
		$string9 = "ethereum" nocase wide ascii
        $string10 = "monero" nocase wide ascii
        $string11 = "cryptocurrency" nocase wide ascii
		 
		// Base64 encoded 
        $b64_encrypted = /ZW5jcnlwdGVk={0,2}/ nocase ascii
		$b64_decrypt = /ZGVjcnlwdA={0,2}/ nocase ascii
		$b64_bitcoin = /Yml0Y29pbg={0,2}/ nocase ascii
		$b64_ethereum = /ZXRoZXJldW0={0,2}/ nocase ascii
		$b64_monero = /bW9uZXJv={0,2}/ nocase ascii
		$b64_victim = /dmljdGlt={0,2}/ nocase ascii
		$b64_locked = /bG9ja2Vk={0,2}/ nocase ascii
		$b64_cryptocurrency = /Y3J5cHRvY3VycmVuY3k={0,2}/ nocase ascii
		$b64_infected = /aW5mZWN0ZWQ={0,2}/ nocase ascii

    condition:
		any of them
}
