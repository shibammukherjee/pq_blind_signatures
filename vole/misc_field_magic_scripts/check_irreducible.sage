
F2.<x> = GF(2)[]
# Define the polxnomial (example: AES irreducible polxnomial)
f = x^127 + x^123 + x^121 + x^120 + x^118 + x^115 + x^112 + x^111 + x^106 + x^103 + x^100 + x^97 + x^96 + x^93 + x^92 + x^91 + x^88 + x^85 + x^84 + x^81 + x^80 + x^78 + x^75 + x^74 + x^73 + x^69 + x^68 + x^63 + x^60 + x^59 + x^54 + x^53 + x^52 + x^51 + x^49 + x^45 + x^44 + x^42 + x^40 + x^38 + x^36 + x^35 + x^34 + x^31 + x^29 + x^28 + x^27 + x^26 + x^25 + x^24 + x^19 + x^18 + x^15 + x^10 + x^5 + x^3 + x + 1

print(f.is_irreducible())