from rfc7748 import x25519, add, computeVcoordinate, mult
from Crypto.Hash import SHA256
from random import randint
from algebra import mod_inv

p = 2**255 - 19 # nombre premier défissant le champ fini
ORDER = (2**252 + 27742317777372353535851937790883648493) # ordre du groupe

BaseU = 9
BaseV = computeVcoordinate(BaseU)


def H(message):
    h = SHA256.new(message)
    return (int(h.hexdigest(), 16))

def ECDSA_generate_nonce():
    return randint(1, ORDER - 1)


def ECDSA_generate_keys(priv=None):
    """
    Génère une paire de clés privée/publique
    priv : par défaut générée aléatoirement, ajouté pour les tests uniquement
    Return : (priv, pub)
    """
    if priv is None:
        priv = randint(1, ORDER - 1)
    pub = mult(priv, BaseU, BaseV,p)
    return (priv, pub)


def ECDSA_sign(message,priv,nonce=None):
    """
    Signe un message avec la clé privée
    Paramètres :
    message : message à signer en bytes
    privatekey : clé privée
    nonce: par défaut généré aléatoirement, ajouté pour les tests uniquement
    Return : (r,s) signature du message
    """
    hash = H(message)
    if nonce is None:        
        nonce = ECDSA_generate_nonce()
    
    # multiplication scalaire en utilisant le nonce
    (i,j) = mult(nonce, BaseU, BaseV,p)
    
    r=i % ORDER
    
    if  r == 0:
        ECDSA_sign(message,priv)
    
    s = mod_inv(nonce, ORDER)*(hash + r*priv) % ORDER
    
    if s == 0:
        ECDSA_sign(message,priv)
    return (r,s)


def ECDSA_verify(message,r,s,pub):
    """
    Vérifie la signature d'un message => (H(m)*s^-1 mod ORDER)*G +(r*s^-1 mod ORDER)*pub
    Paramètres :
    message : message en bytes
    r,s : signature
    pub : clé publique
    Return : True si la signature est valide, False sinon
    """
    if r < 1 or r > ORDER - 1:
        return False
    if s < 1 or s > ORDER - 1:
        return False
    
    hash = H(message)
    inv_s = mod_inv(s, ORDER)
    
    # divise l'equation en deux parties pour la clarté
    u1 = (hash * inv_s) % ORDER
    u2 = (r * inv_s) % ORDER
    
    # calcul des points 
    u1 = mult(u1, BaseU, BaseV,p) # (H(m)*s^-1 mod ORDER)*G
    u2 = mult(u2, pub[0], pub[1],p) # (r*s^-1 mod ORDER)*pub
    
    # addition des points
    (i,j) = add(u1[0], u1[1], u2[0], u2[1],p)
    
    return i % ORDER == r
    


if __name__ == "__main__":
    m= "A very very important message !".encode()
    k = 0x2c92639dcf417afeae31e0f8fddc8e48b3e11d840523f54aaa97174221faee6
    x = 0xc841f4896fe86c971bedbcf114a6cfd97e4454c9be9aba876d5a195995e2ba8
    
    r_expected = 0x429146a1375614034c65c2b6a86b2fc4aec00147f223cb2a7a22272d4a3fdd2
    s_expected = 0xf23bcdebe2e0d8571d195a9b8a05364b14944032032eeeecd22a0f6e94f8f33
    
    (priv,pub) = ECDSA_generate_keys(x)
    (r,s) = ECDSA_sign(m,priv,k)
    
    if r == r_expected and s == s_expected:
        print("Signature OK")
    
    if ECDSA_verify(m,r,s,pub):
        print("Verification OK")
    