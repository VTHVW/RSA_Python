
def extended_euclidean(a,b):
	"""Calculate GCD(a,b) with the extended Euclidean algorithm.

	Args:
		a (Integer): an integer > 0.
		b (Integer): an integer > 0 and < a.

    Returns:
		GCD (Integer): greatest common divisor of (a, b) [see euclidean(a,b) for more].
		s   (Integer): coefficients such that sx + ty = gcd.
		t   (Integer): coefficients such that sx + ty = gcd.
    """
	a, b = abs(a), abs(b)
	# s and t are Bézout's identity series
	# see more: https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
	#			https://en.wikipedia.org/wiki/B%C3%A9zout%27s_identity
	#			https://en.wikipedia.org/wiki/Euclidean_algorithm#Extended_Euclidean_algorithm
	# s=s[-2]
	# s_1=s[-1]
	# t=t[-2]
	# t_1=t[-1]
	s, s_1, t, t_1 = 1, 0, 0, 1
	while b != 0:
		q, a, b = a // b, b, a % b
		s, s_1 = s_1, s - q * s_1
		t, t_1 = t_1, t - q * t_1
	return a, s, t

def euclidean(a,b):
	"""Calculate GCD(a,b) with the Euclidean algorithm.

	Args:
		a (Integer): an integer > 0.
		b (Integer): an integer > 0.

	Returns:
		Integer: GCD(a,b) = m ∈ ℕ : (m|a ⋀ m|b) ⋀ (∄ n ∈ ℕ : (n|a ⋀ n|b) ⋀ n>m).
	"""
	if(a<b):
		a,b = b,a

	a, b = abs(a), abs(b)
	while a != 0:
		a, b = b % a, a
	return b