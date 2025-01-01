import sys
import os

# Ajouter le dossier parent au chemin Python
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import elgamal


# 3.2 Homomorphic encryption : multiplicative version
def testing_3_2():
    """
    NE FONCTIONNE  PAS CORRECTEMENT OU BIEN LE MESSAGE N'EST PAS SENSE ETRE LISIBLE
    """
    m1 = 0x2661b673f687c5c3142f806d500d2ce57b1182c9b25bfe4fa09529424b
    m2 = 0x1c1c871caabca15828cf08ee3aa3199000b94ed15e743c3
    # Generate keys
    priv, pub = elgamal.EG_generate_keys()
    (r1, c1) = elgamal.EGM_encrypt(m1, pub)
    (r2, c2) = elgamal.EGM_encrypt(m2, pub)
    (r3, c3) = (r1 * r2) % elgamal.PARAM_P, (c1 * c2) % elgamal.PARAM_P
    m3 = elgamal.EG_decrypt(r3, c3, priv)
    
    if m3 == (m1 * m2) % elgamal.PARAM_P:
        print("Success")
    
    print(elgamal.int_to_bytes(m3))
    
# 3.3 Homomorphic encryption : additive version    
def testing_3_3():
    m1,m2,m3,m4,m5=1,0,1,1,0
    
    (priv, pub) = elgamal.EG_generate_keys()
    (r1, c1) = elgamal.EGA_encrypt(m1, pub)
    (r2, c2) = elgamal.EGA_encrypt(m2, pub)
    (r3, c3) = elgamal.EGA_encrypt(m3, pub)
    (r4, c4) = elgamal.EGA_encrypt(m4, pub)
    (r5, c5) = elgamal.EGA_encrypt(m5, pub)
    
    (r,c) = ((r1 * r2 * r3 * r4 * r5) % elgamal.PARAM_P, (c1 * c2 * c3 * c4 * c5) % elgamal.PARAM_P)
    
    m = elgamal.EG_decrypt(r, c, priv)
    
    brute_forced_m = elgamal.bruteLog(m)
    
    if m1+m2+m3+m4+m5 == brute_forced_m:
        print("Success = ", brute_forced_m)
