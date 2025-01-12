from algebra import mod_inv, int_to_bytes
from random import randint

PARAM_P = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597

PARAM_Q = 0x8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3

PARAM_G = 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659


### call bruteLog with p = PARAM_P and g = PARAM_G

def bruteLog(c,g=PARAM_G, p=PARAM_P):
    """
    Permet de retrouver le logarithme discret de c en base g modulo p
    Paramètres :
    c : nombre à retrouver
    Return : le logarithme 
    """
    i = 1
    s = 1
    for i in range(p):
        if s == c:
            return i
        s = (s * g) % p
        if s == c:
            return i + 1
    return -1

def EG_generate_keys(p=PARAM_P, q=PARAM_Q, g=PARAM_G):
    """
    Paramètres: (par défaut du MODP Group 24)
    p : grand nombre premier avec
    q : grand nombre premier avec p = kq + 1
    g : générateur 
    Return : (priv, pub) où priv clé privée et pub clé publique
    """
    priv = randint(1, q-2)
    pub = pow(g, priv, p)
    return (priv,pub)
## multiplicative version
# (c1,c2) = (g^r,m * pub^r)
def EGM_encrypt(message,pub):
    """
    Chiffre un message avec la clé publique en utilisant la version multiplicative
    Paramètres : 
    message : message à chiffré : int
    pub : clé publique
    Return :
    (c1, c2) : message chiffré
    """
    r = randint(2, PARAM_Q - 2)
    c1 = pow(PARAM_G, r, PARAM_P)
    c2 = (message * pow(pub, r, PARAM_P)) % PARAM_P
    return c1, c2

## additive version
#(c1,c2) = (g^r,g^m * pub^r)
def EGA_encrypt(message,pub):
    """
    Chiffre un message avec la clé publique en utilisant la version additive
    Paramètres :
    message : message à chiffré
    pub : clé publique
    Return :
    (c1, c2) : message chiffré
    """
    r = randint(2, PARAM_Q - 2)
    c1 = pow(PARAM_G, r, PARAM_P)
    c2 = (pow(PARAM_G, message, PARAM_P) * pow(pub, r, PARAM_P)) % PARAM_P
    return c1, c2


def EG_decrypt(c1,c2,priv):
    """
    Déchiffre un message avec la clé privée
    Paramètres :
    c1,c2 : message chiffré
    priv : clé privée
    Return : message déchiffré
    """
    c_u = pow(c1, priv, PARAM_P)
    message = c2 * mod_inv(c_u, PARAM_P) % PARAM_P
    return message

if __name__ == '__main__':
    print("---Version multiplicative---\n")
    m1 = 0x2661b673f687c5c3142f806d500d2ce57b1182c9b25bfe4fa09529424b
    m2 = 0x1c1c871caabca15828cf08ee3aa3199000b94ed15e743c3
    # Generate keys
    priv, pub = EG_generate_keys()
    (r1, c1) = EGM_encrypt(m1, pub)
    (r2, c2) = EGM_encrypt(m2, pub)
    (r3, c3) = (r1 * r2) % PARAM_P, (c1 * c2) % PARAM_P
    m3 = EG_decrypt(r3, c3, priv)
    
    if m3 == (m1 * m2) % PARAM_P:
        print("Success")
    
    print(int_to_bytes(m3))
    
    print("---Version additive---\n")
    
    m1,m2,m3,m4,m5=1,0,1,1,0
    
    (priv, pub) = EG_generate_keys()
    (r1, c1) = EGA_encrypt(m1, pub)
    (r2, c2) = EGA_encrypt(m2, pub)
    (r3, c3) = EGA_encrypt(m3, pub)
    (r4, c4) = EGA_encrypt(m4, pub)
    (r5, c5) = EGA_encrypt(m5, pub)
    
    (r,c) = ((r1 * r2 * r3 * r4 * r5) % PARAM_P, (c1 * c2 * c3 * c4 * c5) % PARAM_P)
    
    m = EG_decrypt(r, c, priv)
    
    brute_forced_m = bruteLog(m)
    
    if m1+m2+m3+m4+m5 == brute_forced_m:
        print("Success = ", brute_forced_m)