"""Suite of utility methods"""

from cryptography.hazmat.primitives import padding

def padder128(data):
    """ pad ip to 256 bits... because this can vary too"""
    padder1b = padding.PKCS7(128).padder()
    p1b = padder1b.update(data)
    p1b += padder1b.finalize()
    return p1b
