# degree=4
# R = GF(2)['x']
# for p in R.polynomials(degree):
#      if p.is_irreducible():
#          print(p)


F.<a> = GF(2^128, modulus=x^128 + x^7 + x^2 + x + 1)
R.<x> = PolynomialRing(F)

def irreducible_degree_4():
    while True:
        f = x^4 + sum([F.random_element() * x^i for i in range(4)])
        
        if f.is_irreducible():
            return f

irreducible_poly = irreducible_degree_4()
print(irreducible_poly)