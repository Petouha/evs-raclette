from algebra import mod_inv
from Crypto.Hash import SHA256
from random import randint

## parameters from MODP Group 24 256-bit POS -- Extracted from RFC 5114

# Pour les modulo
PARAM_P = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597
# Pour générer clé privé
PARAM_Q = 0x8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3
# Générateur
PARAM_G = 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659

def H(message):
    h = SHA256.new(message)
    return (int(h.hexdigest(), 16))

# Génère un nonce aléatoire pour la signature
def DSA_generate_nonce():
    return randint(1, PARAM_Q - 2)

# x => clé privée : nombre entre 1 et q-2 |  X =>  clé publique : G^x = X 
def DSA_generate_keys(p=PARAM_P, q=PARAM_Q, g=PARAM_G):
    """
    Paramètres: (par défaut du MODP Group 24)
    p : grand nombre premier avec
    q : grand nombre premier avec p = kq + 1
    g : générateur 
    Return : (x, X) où x clé privée et X clé publique
    """
    x = randint(1, q-2)
    X = pow(g, x, p)
    return (x,X)


def DSA_sign(message:bytes, privatekey, k=None, p=PARAM_P, q=PARAM_Q, g=PARAM_G):
    """
    Signe un message avec la clé privée
    Paramètres : 
    message : message à signer en bytes
    privatekey : clé privée
    p,q,g : paramètres du groupe (par défaut du MODP Group 24)
    k : nonce doit être valide(par défaut génération aléatoirement)
    Return : (r,s) signature du message
    """
    while True:
        if k is None:
            k = DSA_generate_nonce()
        r = pow(g, k, p) % q
        if r == 0:
            continue
        s = (mod_inv(k, q) * (H(message) + privatekey * r)) % q
        if s != 0:
            break
    return (r, s)   

def DSA_verify(X,r,s,message:bytes):
    """
    Vérifie la signature d'un message
    Paramètres :
    X : clé publique
    r,s : signature
    message : message à vérifier en bytes
    """
    if not (0 < r < PARAM_Q) or not (0 < s < PARAM_Q):
        return False

    w = mod_inv(s, PARAM_Q)
    u1 = (H(message) * w) % PARAM_Q
    u2 = (r * w) % PARAM_Q

    t1 = pow(PARAM_G, u1, PARAM_P)
    t2 = pow(X, u2, PARAM_P)
    v = ((t1 * t2) % PARAM_P) % PARAM_Q
    return v == r


if __name__ == '__main__':
    m = "An important message !"
    k = 0x7e7f77278fe5232f30056200582ab6e7cae23992bca75929573b779c62ef4759
    x = 0x49582493d17932dabd014bb712fc55af453ebfb2767537007b0ccff6e857e6a3



    (sig_r,sig_s) = DSA_sign(m.encode(),x,k)

    r = 0x5ddf26ae653f5583e44259985262c84b483b74be46dec74b07906c5896e26e5a
    s = 0x194101d2c55ac599e4a61603bc6667dcc23bd2e9bdbef353ec3cb839dcce6ec1

    print(f"sig_r = r : {sig_r == r} et sig_s = s : {sig_s == s}")



    if DSA_verify(pow(PARAM_G,x,PARAM_P),sig_r,sig_s,m.encode()) : 
        print("Signature valide")
    else:
        print("Signature invalide")