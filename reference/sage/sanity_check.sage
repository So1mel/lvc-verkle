import platform
import sys
from sage.version import version as SAGE_VERSION

q = 17
A = matrix(Integers(q), [[1, 0, 2], [0, 1, 5]])
z = vector(Integers(q), [1, 1, 1])
y = A * z

centered = [ZZ(value) if ZZ(value) <= q // 2 else ZZ(value) - q for value in z]
norm_squared = sum(value * value for value in centered)

print("SageMath reference environment is ready.")
print("Sage version =", SAGE_VERSION)
print("Python version =", sys.version.split()[0])
print("Platform =", platform.platform())
print("A * z mod q =", y)
print("centered(z) =", centered)
print("||z||^2 =", norm_squared)

assert len(SAGE_VERSION) > 0
assert len(sys.version.split()[0]) > 0
assert len(platform.platform()) > 0
assert y == vector(Integers(q), [3, 6])
assert centered == [1, 1, 1]
assert norm_squared == 3
