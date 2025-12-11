
R.<x> = GF(2)[]
modulus = x^512 + x^8 + x^5 + x^2 + 1
# a = x^411 + x^311 + x^211 + x^111 + x^11 + x^1
# b = x^410 + x^310 + x^210 + x^110 + x^10 + 1
# a = x^382 + x^311 + x^211 + x^111 + x^11 + x^1
# b = x^381 + x^310 + x^210 + x^110 + x^10 + 1
a = x^511 + x^411 + x^311 + x^211 + x^111 + x^11 + x^1
b = x^510 + x^410 + x^310 + x^210 + x^110 + x^10 + 1

# product = a * b
terms = []

print("\nIntermediate Terms:")
for i in range(b.degree() + 1):
    if b[i] == 1:
        term = a * x^i
        terms.append(term)
        print(f"b[{i}] = 1 → Shift a(x) by x^{i}: {term}")
    else:
        print(f"b[{i}] = 0 → Skip")

# XOR (add in GF(2)) all the terms
product = sum(terms, R.zero())
print("\nFinal XOR (carry-less sum):")
for i, term in enumerate(terms):
    print(f"{' ' if i==0 else '⊕'} {term}")
print("= ", product)

print("Initial product degree:", product.degree())
print("Before reduction:\n", product)

# # Now reduce step by step
# while product.degree() >= 512:
#     deg = product.degree()
#     print(deg)
#     # Compute shift
#     shift = deg - 512
#     # Shifted modulus to align highest term
#     reduction_poly = x^shift * (x^512 + x^8 + x^5 + x^2 + 1)
#     # Subtract (XOR in GF(2))
#     product += reduction_poly  # + is XOR in GF(2)
#     print(f"\nReducing term x^{deg} with x^{shift} * (modulus tail)")
#     print("Intermediate result:", product)

# # Final result after full reduction
# print("\nFinal reduced result:")
# print(product)
