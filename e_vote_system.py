import ecdsa, ecelgamal,dsa, elgamal
from algebra import int_to_bytes


def elgamal_dsa():
    """
    Implementation en utilisant elgamal pour le chiffrement et dsa pour la signature.
    """   
    print("-----Implémnetation du vote avec ElGamal et DSA-----\n")
    # Génération des clés du système de vote pour le chiffrement
    priv_system_vote, pub_system_vote = elgamal.EG_generate_keys()
    
    def voters_generate(pub_system_vote):
        """
        La fonction qui englobe les votants.
        Paramètres:
        pub_system_vote : clé publique du système de vote
        Return:
        votes : une liste des bulletins de vote composé d'un dict avec (chiffre,signature,cle_publique_votant) pour chaque votant
        """
        return_votes = []
        for i in range(5):
            # Génération des clés du votant
            priv_voter, pub_voter = dsa.DSA_generate_keys()
            # Génération du vote pour les 5 candidats sous forme d'une liste qui contient un seul 1 et des 0
            generated_votes = [0]*5
            generated_votes[dsa.randint(0, 4)] = 1
            print(f"Les votes du votant {i} : {generated_votes}")
            
            # Chiffrement de chaque vote à mettre dans une liste
            encrypted_votes = []
            for vote in generated_votes:
                encrypted_votes.append(elgamal.EGA_encrypt(vote, pub_system_vote))
        
            # Signature de tous les votes, on concatène les chiffres des votes pour avoir un seul message puis on le hash et on signe
            all_votes = ""
            for votes in encrypted_votes: # concaténation des votes pour les hasher
                all_votes += str(votes[0]) + str(votes[1]) 
            
            hashed_all_votes = int_to_bytes(dsa.H(all_votes.encode()))
            signature = dsa.DSA_sign(hashed_all_votes, priv_voter)
            
            # Ajout du vote chiffré, de la signature et de la clé publique du votant dans le dictionnaire puis dans la liste
            dict_vote = {'votes': encrypted_votes, 'signature': signature, 'pub_voter': pub_voter}
            return_votes.append(dict_vote)
        return return_votes
            
    def voting_system(priv_system_vote):
        """
        Le système de votes qui va déchiffrer les votes et les compter.
        Paramètres:
        priv_system_vote : clé privée du système de vote
        Return:
        result : les résultats du vote
        """
        # Génération des votes
        voters = voters_generate(pub_system_vote)
        # Initialisation des résultats du vote
        results_encrypted = [(1,1)]*5
        results = []
        
        for i,votes in enumerate(voters):
            # Vérification de la signature du votant
            # Commencer par concaténer les votes pour les hasher
            concat_votes = ""
            
            for vote in votes['votes']:
                tuple1,tuple2 = vote
                concat_votes += str(tuple1) + str(tuple2)
            
            hashed_votes = int_to_bytes(dsa.H(concat_votes.encode()))
            # Si la signature n'est pas valide, on passe au votant suivant
            if not dsa.DSA_verify(votes['pub_voter'], votes['signature'][0],votes['signature'][1], hashed_votes):
                print(f"La signature du votant {i} n'est pas valide")
                continue
            # Multiplier les votes pour chaque candidat
            encrypted_votes = votes['votes']
            for j,vote in enumerate(encrypted_votes):
                (tuple1,tuple2) = results_encrypted[j]
                results_encrypted[j] = (tuple1 * vote[0] % elgamal.PARAM_P, tuple2 * vote[1] % elgamal.PARAM_P) 
        
        # Déchiffrement des votes et affichage des résultats en utilisant la fonction bruteLog
        for result in results_encrypted:
            decrypted = elgamal.EG_decrypt(result[0],result[1], priv_system_vote)
            results.append(elgamal.bruteLog(decrypted))
        
        print(f"Les résultats du vote sont : {results}")
            
                
                
    voting_system(priv_system_vote)
    print("\n-----FIN-----\n")

def elgamal_ecdsa():
    """
    Implementation en utilisant elgamal pour le chiffrement et ec dsa pour la signature.
    """   
    print("-----Implémnetation du vote avec ElGamal et ECDSA-----\n")
    # Génération des clés du système de vote pour le chiffrement
    priv_system_vote, pub_system_vote = elgamal.EG_generate_keys()
    
    def voters_generate(pub_system_vote):
        """
        La fonction qui englobe les votants.
        Paramètres:
        pub_system_vote : clé publique du système de vote
        Return:
        votes : une liste des bulletins de vote composé d'un dict avec (chiffre,signature,cle_publique_votant) pour chaque votant
        """
        return_votes = []
        for i in range(5):
            # Génération des clés du votant
            priv_voter, pub_voter = ecdsa.ECDSA_generate_keys()
            # Génération du vote pour les 5 candidats sous forme d'une liste qui contient un seul 1 et des 0
            generated_votes = [0]*5
            generated_votes[dsa.randint(0, 4)] = 1
            print(f"Les votes du votant {i} : {generated_votes}")
            
            # Chiffrement de chaque vote à mettre dans une liste
            encrypted_votes = []
            for vote in generated_votes:
                encrypted_votes.append(elgamal.EGA_encrypt(vote, pub_system_vote))
        
            # Signature de tous les votes, on concatène les chiffres des votes pour avoir un seul message puis on le hash et on signe
            all_votes = ""
            for votes in encrypted_votes: # concaténation des votes pour les hasher
                all_votes += str(votes[0]) + str(votes[1]) 
            
            hashed_all_votes = (dsa.H(all_votes.encode()))

            signature = ecdsa.ECDSA_sign(hashed_all_votes, priv_voter)
            
            # Ajout du vote chiffré, de la signature et de la clé publique du votant dans le dictionnaire puis dans la liste
            dict_vote = {'votes': encrypted_votes, 'signature': signature, 'pub_voter': pub_voter}
            return_votes.append(dict_vote)
        return return_votes
            
    def voting_system(priv_system_vote):
        """
        Le système de votes qui va déchiffrer les votes et les compter.
        Paramètres:
        priv_system_vote : clé privée du système de vote
        Return:
        result : les résultats du vote
        """
        # Génération des votes
        voters = voters_generate(pub_system_vote)
        # Initialisation des résultats du vote
        results_encrypted = [(1,1)]*5
        results = []
        
        for i,votes in enumerate(voters):
            # Vérification de la signature du votant
            # Commencer par concaténer les votes pour les hasher
            concat_votes = ""
            
            for vote in votes['votes']:
                tuple1,tuple2 = vote
                concat_votes += str(tuple1) + str(tuple2)
            
            hashed_votes = (ecdsa.H(concat_votes.encode()))
            # Si la signature n'est pas valide, on passe au votant suivant
            if not ecdsa.ECDSA_verify(hashed_votes, votes['signature'][0],votes['signature'][1],votes['pub_voter']):
                print(f"La signature du votant {i} n'est pas valide")
                continue
            # Multiplier les votes pour chaque candidat
            encrypted_votes = votes['votes']
            for j,vote in enumerate(encrypted_votes):
                (tuple1,tuple2) = results_encrypted[j]
                results_encrypted[j] = (tuple1 * vote[0] % elgamal.PARAM_P, tuple2 * vote[1] % elgamal.PARAM_P) 
        
        # Déchiffrement des votes et affichage des résultats en utilisant la fonction bruteLog
        for result in results_encrypted:
            decrypted = elgamal.EG_decrypt(result[0],result[1], priv_system_vote)
            results.append(elgamal.bruteLog(decrypted))
        
        print(f"Les résultats du vote sont : {results}")
            
                
                
    voting_system(priv_system_vote)
    print("\n-----FIN-----\n")


elgamal_dsa()
elgamal_ecdsa()