R.<x> = GF(2)[]
E.<y> = GF(2^4, modulus=x^4 + x + 1)
F.<y> = GF(2^256, modulus=x^256 + x^10 + x^5 + x^2 + 1)

mod_256 = x^256 + x^10 + x^5 + x^2 + 1

P.<z> = PolynomialRing(F)
f = z**4 + z + 1



# print(f.roots()[0])
# poly = f.roots()[0][0].polynomial()
# int_value = sum([int(c) << i for i, c in enumerate(poly.coefficients(sparse=False))])
# print(f"0x{int_value:032x}")


print(f.roots()[0])
poly = f.roots()[0][0].polynomial()

# int_value = sum([int(c) << i for i, c in enumerate(poly.coefficients(sparse=False))])
# print(f"0x{int_value:032x}")

poly_over_GF2 = R(poly)
for i in range(1,4):
    poly_pow = (poly_over_GF2**i) % mod_256
    int_value = sum([int(c) << i for i, c in enumerate(poly_pow.coefficients(sparse=False))])
    print(f"0x{int_value:064x}")
    t = "{"
    for j in range(0,32):
        t += f"0x{((int_value >> j*8) & 0xff):02x}" + ", "
    t += "}"
    print(t)

#print(hex(Integer(f.roots()[0][0].polynomial().integer_representation())))

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