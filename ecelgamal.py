from rfc7748 import x25519, add, sub, computeVcoordinate, mult
from algebra import mod_inv, int_to_bytes
from random import randint


p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

BaseU = 9
BaseV = computeVcoordinate(BaseU)

def bruteECLog(C1, C2, p):
    s1, s2 = 1, 0
    for i in range(p):
        if s1 == C1 and s2 == C2:
            return i
        s1, s2 = add(s1, s2, BaseU, BaseV, p)
    return -1

def EGencode(message):
    if message == 0:
        return (1,0)
    if message == 1:
        return (BaseU, BaseV)

def ECEG_generate_keys():
    priv = randint(1, ORDER - 1)
    pub = mult(priv, BaseU, BaseV, p)
    return (priv,pub)    


def ECEG_encrypt(message:int,pub:tuple):
    """
    Chiffre un message avec la clé publique pub.
    paramètres :
    message : message à chiffrer
    pub : clé publique
    return : (C1, C2) message chiffré
    """
    message_point = EGencode(message) # on encode le message en point de la courbe
    r = randint(1, ORDER - 1)
    # En utilisant le nonce r, on chiffre le message avec la clé publique en faisaint
    # C1 = k * G et C2 = M + k * Q
    C1 = mult(r, BaseU, BaseV, p)
    r_Q = mult(r, pub[0], pub[1], p)
    C2 = add(message_point[0], message_point[1], r_Q[0], r_Q[1], p)
    return (C1, C2)
    


def ECEG_decrypt(message,priv):
    """
    Déchiffre un message avec la clé privée priv.
    paramètres :
    message : message chiffré (C1, C2) avec C1 et C2 des points de la courbe
    priv : clé privée
    return : message déchiffré
    """
    C1, C2 = message
    # En utilisant la clé privée, on déchiffre le message en faisant
    # M = C2 - k * C1
    k_C1 = mult(priv, C1[0], C1[1], p)
    M = sub(C2[0], C2[1], k_C1[0], k_C1[1], p)
    return M

if __name__ == "__main__":
    messages = [1, 0, 1, 1, 0]    

    # Génération des clés
    priv, pub = ECEG_generate_keys()

    # Chiffrement des messages
    chiffres = []
    for m in messages:
        chiffres.append(ECEG_encrypt(m, pub))

    # Initialisation des points pour l'addition
    r = 1, 0  # Point à l'infini
    c = 1, 0  # Point à l'infini

    # Addition des points
    for chiffre in chiffres:
        r = add(r[0],r[1], chiffre[0][0], chiffre[0][1], p)  # C1
        c = add(c[0],c[1], chiffre[1][0], chiffre[1][1], p)  # C2

    # Déchiffrement
    dechiffre = ECEG_decrypt((r,c) ,priv)

    # Recherche brute pour récupérer la somme des messages
    m = bruteECLog(dechiffre[0], dechiffre[1], p)
    print(f"Somme des messages : {m}")

    # Vérification
    if m == 3:
        print("OK")
    else:
        print("Erreur")
