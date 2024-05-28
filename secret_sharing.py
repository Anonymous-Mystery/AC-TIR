import numpy as np

# The function used to generate polynomials by given the degree and number of polynomials
def generate_random_polynomial(degree, num_polynomials):
    polynomials = []
    
    for i in range(num_polynomials):
        coefficients = np.random.randint(low = 1, high = 10, size = degree + 1)
        
        polynomial = np.poly1d(coefficients)
        polynomials.append(polynomial)
    
    return polynomials

# The function used to insert the x value into the polynomials and return the f(x) values
def evaluate_polynomial(polynomial, x):
    result = np.polyval(polynomial, x)
    return result
  
# The function used to recover the lagrange polynomial basis from a set of x values    
def lagrange_basis_polynomials(x_values):
    n = len(x_values)
    L = []
        
    for i in range(n):
        basis_poly_i = np.poly1d([1])
        for j in range(n):
            if i != j:
                #term = -x_values[j] / (x_values[i] - x_values[j]) if x_values[i] != x_values[j] else 1
                #basis_poly_i *= np.poly1d([term])
                basis_poly_i *= np.poly1d([1, -x_values[j]]) / (x_values[i] - x_values[j])
        L.append(basis_poly_i) 
    
    return L
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
        
