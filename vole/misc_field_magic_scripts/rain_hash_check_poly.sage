# Step 1: Define the base field GF(2^128)
F.<a> = GF(2^128, name='a', modulus=x^128 + x^7 + x^2 + x + 1)  # primitive default irreducible

# Step 2: Define the polynomial ring over GF(2^128)
R.<x> = PolynomialRing(F)

# Step 3: Define the input polynomials with symbolic coefficients
# (you can assign actual values to a_i and b_i instead of using variables)
# a_coeffs = [F.random_element() for _ in range(4)]  # a0, a1, a2, a3
# b_coeffs = [F.random_element() for _ in range(4)]  # b0, b1, b2, b3

a_coeffs = [F.fetch_int(1), F.fetch_int(2), F.fetch_int(4), F.fetch_int(8)]  # a0, a1, a2, a3
b_coeffs = [F.fetch_int(16), F.fetch_int(32), F.fetch_int(64), F.fetch_int(128)]  # b0, b1, b2, b3

# Define the polynomials (replace vars with actual GF(2^128) elements if desired)
A = sum(a_coeffs[i] * x^i for i in range(4))
B = sum(b_coeffs[i] * x^i for i in range(4))

print("A(x) =", A)
print("B(x) =", B)

# Step 4: Multiply step-by-step (manual)
print("\nStep-by-step multiplication:")

# Dictionary to collect terms by degree
from collections import defaultdict
terms = defaultdict(F.zero)  # default to zero of GF(2^128)

# Loop over all terms
for i in range(4):
    for j in range(4):
        coeff = a_coeffs[i] * b_coeffs[j]
        deg = i + j
        terms[deg] += coeff
        print(f"Term: ({a_coeffs[i]})*x^{i} * ({b_coeffs[j]})*x^{j} = ({coeff})*x^{deg}")

# Step 5: Build the resulting polynomial
P = sum(terms[d] * x^d for d in sorted(terms.keys()))
print("\nFull product polynomial A(x) * B(x):")
show(P)


# # Step 4: Multiply polynomials
# P = A * B
# show(P)

# Step 5: Define the reduction polynomial: x^4 + a^123 * x^2 + x + 1
mod_poly = x^4 + a^123 * x^2 + x + 1


while P.degree() >= 4:
    # Get the leading term
    deg = P.degree()
    coeff = P.leading_coefficient()
    
    # Determine the term to eliminate: coeff * x^deg
    # We divide by x^4 to get the shift needed
    shift = deg - 4
    # Multiply reduction polynomial by coeff * x^shift
    to_subtract = coeff * x^shift * mod_poly
    print(f"\nReducing term: {coeff} * x^{deg} by subtracting:\n")
    show(to_subtract)
    print("\n")

    # Subtract from P
    P = P - to_subtract
    print("Intermediate reduced polynomial:")
    show(P)

# Final reduced result
print("\nFinal reduced polynomial:")
show(P)



# # Step 6: Reduce the product modulo the irreducible polynomial
# Q = P % mod_poly

# # Output the result
# print("Resultant reduced polynomial Q(x):")
# show(Q)