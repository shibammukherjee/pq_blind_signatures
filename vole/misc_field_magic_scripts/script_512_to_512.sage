R.<x> = GF(2)[]
E.<y> = GF(2^512, modulus=x^512 + x^8 + x^5 + x^2 + 1)
F.<y> = GF(2^512, modulus=x^512 + x^8 + x^5 + x^2 + 1)

mod_512 = x^512 + x^8 + x^5 + x^2 + 1

P.<z> = PolynomialRing(F)
f = z**512 + z**8 + z**5 + z**2 + 1


print(f.roots()[0])
poly = f.roots()[0][0].polynomial()

# int_value = sum([int(c) << i for i, c in enumerate(poly.coefficients(sparse=False))])
# print(f"0x{int_value:032x}")

poly_over_GF2 = R(poly)
# for i in range(1,512):
#     poly_pow = (poly_over_GF2**i) % mod_512
#     int_value = sum([int(c) << i for i, c in enumerate(poly_pow.coefficients(sparse=False))])
#     print(f"0x{int_value:032x}")
# for i in range(512):
#     poly_pow = (poly_over_GF2^i) % mod_512
#     coeffs = poly_pow.coefficients(sparse=False)
#     # Pad to 512 bits
#     coeffs += [0] * (512 - len(coeffs))
#     # Convert to integer
#     int_value = sum([int(c) << j for j, c in enumerate(coeffs)])
#     # Break into 16 32-bit words (little-endian order)
#     words = [(int_value >> (32 * j)) & 0xFFFFFFFF for j in range(16)]
#     word_strs = [f"0x{w:08x}" for w in words]
#     print("{" + ", ".join(word_strs) + "},")

for i in range(1,512):
    poly_pow = (poly_over_GF2^i) % mod_512
    coeffs = poly_pow.coefficients(sparse=False)
    coeffs += [0] * (512 - len(coeffs))
    
    # Convert bit list to 64 bytes (little-endian)
    bytes_le = []
    for j in range(0, 512, 8):
        byte = sum([int(coeffs[j + k]) << k for k in range(8)])
        bytes_le.append(byte)
    
    # Format as C-style uint8 array
    byte_strs = [f"0x{int(b):02x}" for b in bytes_le]
    print("{" + ", ".join(byte_strs) + "},")


# print(hex(Integer(f.roots()[0][0].polynomial().integer_representation())))

#if False:
#    K.<x> = GF(2^4, modulus= X^4+X+1)
#    F = GF(2^128, 'y', modulus = X^128 + X^7 + X^2 + X + 1)
#    print(F, F.modulus())
#    print(F.gens())
#    H = Hom(K, F)
#    morph = H.list()[0]
#    g = morph.im_gens()[0]
#    print(morph)
#    y^14 + y^8 + y^7 + y^6 + y^3 + y^2 + 1
#    y^14 + y^8 + y^7 + y^6 + y^3 + y^2 + 1
#    y^14 + y^13 + y^11 + y^7 + 1