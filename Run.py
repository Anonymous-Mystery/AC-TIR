'''
:Date:            11/2023
'''
import re, random
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT, ZR
from ACTIR import ACTIR
from Coconut import Coconut
from Coconut_Prime import Coconut_Prime

def run1(actir, q, n, t, attr):
    pp = actir.Setup(q, n, t)
    mpk, pk, sk = actir.KeyGen(pp)
    pk_u, sk_u, ct, pi_s = actir.IssueCred_1(pp, attr)
    sigma_hat = actir.IssueCred_2(pp, pk_u, ct, pi_s, sk)
    sigma_share = actir.IssueCred_3(pp, attr, pk, sk_u, sigma_hat)

    sigma_share['s'] = sigma_share['s'][:t]

    sigma = actir.AggCred(pp, mpk, sigma_share, attr)
    SIGMA, CT, pi_v = actir.ProveCred(pp, mpk, attr, sigma)
    VLR = actir.RevokeCred(pp, mpk, sk, SIGMA, CT, pi_v)
    result = actir.VerifyCred(pp, mpk, SIGMA, CT, pi_v, VLR)
    
    if result == 0:
        print('Our ACTIR verfication is not passed.')
    if result == 1:
        print('Our ACTIR verfication is successful!')

def run2(coconut, q, n, t, attr):
    pp = coconut.Setup(q, n, t)
    mpk, pk, sk = coconut.KeyGen(pp)
    pk_u, sk_u, ct, pi_s = coconut.IssueCred_1(pp, attr)
    sigma_hat = coconut.IssueCred_2(pp, pk_u, ct, pi_s, sk)
    sigma_share = coconut.IssueCred_3(pp, sk_u, sigma_hat)

    sigma_share['s'] = sigma_share['s'][:t]

    sigma = coconut.AggCred(pp, mpk, sigma_share, attr)
    SIGMA, pi_v = coconut.ProveCred(pp, mpk, attr, sigma)
    result = coconut.VerifyCred(pp, mpk, SIGMA, pi_v)
    
    if result == 0:
        print('The Coconut verfication is not passed.')
    if result == 1:
        print('The Coconut verfication is successful!')

def run3(coconut_prime, q, n, t, attr):
    pp = coconut_prime.Setup(q, n, t)
    mpk, pk, sk = coconut_prime.KeyGen(pp)
    ct, pi_s = coconut_prime.IssueCred_1(pp, attr)
    sigma_hat = coconut_prime.IssueCred_2(pp, ct, pi_s, sk)
    sigma_share = coconut_prime.IssueCred_3(pp, pk, ct, sigma_hat)

    sigma_share['s'] = sigma_share['s'][:t]

    sigma = coconut_prime.AggCred(pp, mpk, sigma_share, attr)
    SIGMA, pi_v = coconut_prime.ProveCred(pp, mpk, attr, sigma)
    result = coconut_prime.VerifyCred(pp, mpk, SIGMA, pi_v)
    
    if result == 0:
        print('The Coconut_Prime verfication is not passed.')
    if result == 1:
        print('The Coconut_Prime verfication is successful!')

def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('MNT224')
    
    actir = ACTIR(pairing_group)
    coconut = Coconut(pairing_group)
    coconut_prime = Coconut_Prime(pairing_group)
    
    # Set the number of authorities and threshold
    n = 10
    t = 6
    
    # Set the number of attributes
    q = 10
    
    # Select random q + 1 attributes
    attr = []
    for i in range(q + 1):  
        attr.append(pairing_group.random(ZR))

    run1(actir, q, n, t, attr) 
    run2(coconut, q, n, t, attr)
    run3(coconut_prime, q, n, t, attr)
           
if __name__ == "__main__":
    debug = True
    main()
