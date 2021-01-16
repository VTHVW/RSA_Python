
def extended_euclidean(a,b):
	"""
    Returns (gcd, x, y) such that:
       gcd  = greatest common divisor of (a, b)
       x, y = coefficients such that ax + by = gcd
    """
	a, b = abs(a), abs(b)
	s, s_1, t, t_1 = 1, 0, 0, 1
	while b != 0:
		q, a, b = a // b, b, a % b
		s, s_1 = s_1, s - q * s_1
		t, t_1 = t_1, t - q * t_1
	return a, s, t

def euclidean(a,b):
	if(a<b):
		a,b = b,a

	a, b = abs(a), abs(b)
	while a != 0:
		a, b = b % a, a
	return b