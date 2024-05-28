'''
| From: "Coconut: Threshold Issunance Selective Disclosure Credentials with Applications to Distributed Ledgers"
| type:           Anonymous Credential scheme
| setting:        Type-III Pairing

:Authors:         
:Date:            12/01/2024
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from secret_sharing import generate_random_polynomial, evaluate_polynomial, lagrange_basis_polynomials
import re, numpy, hashlib

debug = False

class Coconut_Prime(ABEnc):       
    def __init__(self, group_obj, verbose = False):
        ABEnc.__init__(self)
        self.name = "Coconut'"
        self.group = group_obj       

    def Setup(self, q, n, t):
        # pick generators
        g1, g2 = self.group.random(G1), self.group.random(G2)
        
        h = []        
        for i in range(q):
            h.append(self.group.random(G1))
                      
        pp = {'g1': g1, 'h': h, 'g2': g2, 'q': q, 'n': n, 't': t}
        return pp
 
    def KeyGen(self, pp):       
        # Chosse q + 2 random polynomials with degree t - 1
        random_polynomials = generate_random_polynomial(pp['t'] - 1, pp['q'] + 1)    
        
        # evaluate the results with x = 0, set the master public key and master secret key
        mpk = []
        for i, poly in enumerate(random_polynomials):
            y = int(evaluate_polynomial(poly, 0))
            mpk.append(pp['g2'] ** y)
        
        # evaluate the result with x = i + 1, set the public key and secret key for each authority
        pk, sk = {}, {}
        for i in range(pp['n']):
            PK1, PK2, SK = [], [], []
            for j, poly in enumerate(random_polynomials):
                y = int(evaluate_polynomial(poly, i + 1))
                SK.append(y)     
                PK2.append(pp['g2'] ** y)                                
                if j >= 1:  
                    PK1.append(pp['g1'] ** y)     
                else:
                    continue                               
            pk[i] = [PK1, PK2]
            sk[i] = SK
        return mpk, pk, sk
        
    def IssueCred_1(self, pp, attr):              
        # Compute a commitment
        o = self.group.random(ZR)
        c_m = pp['g1'] ** o 
        
        for i in range(pp['q']):
            c_m *= pp['h'][i] ** attr[i] 
            
        # Compute g_hat and commitments of each attribute
        g_hat = self.group.hash(c_m, G1)   
        
        K, C = [], []     
        for i in range(pp['q']):
            k = self.group.random(ZR)        
            K.append(k)           
            C.append(pp['g1'] ** k * g_hat ** attr[i])
                      
        ct = {'c_m': c_m, 'C': C, 'K': K}
            
        # Calculate NIZK arguments for a set of values             
        # NIZK on c_m value
        r1, s1 = [], []
        for i in range(pp['q'] + 1):
            r1.append(self.group.random(ZR))      
                    
        prod = pp['g1'] ** r1[0]
        for i in range(pp['q']):            
            prod *= pp['h'][i] ** r1[i + 1]
        
        c1 = self.group.hash(str(prod), ZR)       
        s1.append(r1[0] - o * c1) 
                     
        for i in range(pp['q']):
            s1.append(r1[i + 1] - attr[i] * c1)   
        
        # NIZK on C value
        r21, r22, s21, s22, c2 = [], [], [], [], []
        
        for i in range(pp['q']):
            r21.append(self.group.random(ZR))
            r22.append(self.group.random(ZR))
            c2.append(self.group.hash(str(pp['g1'] ** r21[i] * g_hat ** r22[i]), ZR))
            s21.append(r21[i] - K[i] * c2[i])
            s22.append(r22[i] - attr[i] * c2[i])
                       
        pi_s = {'c1': c1, 'c2': c2, 's1': s1, 's21': s21, 's22': s22}
            
        return ct, pi_s

    def IssueCred_2(self, pp, ct, pi_s, sk):
        C_hat = []
        
        for m in range(pp['n']):    
            # Recompute g_hat
            g_hat = self.group.hash(ct['c_m'], G1)
               
            # Verify the NIZKP pi_s    
            verify = 0
                                                   
            prod1 = pp['g1'] ** pi_s['s1'][0]
            for i in range(pp['q']):
                prod1 *= pp['h'][i] ** pi_s['s1'][i + 1]
                    
            if pi_s['c1'] == self.group.hash(str(ct['c_m'] ** pi_s['c1'] * prod1), ZR):
                verify += 1
                #print('The verification of c1 is correct!')
            else:
                verify += 0 
                #print('The verification of c1 is wrong.')            
                           
            for i in range(pp['q']):           
                if pi_s['c2'][i] == self.group.hash(str(ct['C'][i] ** pi_s['c2'][i] * pp['g1'] ** pi_s['s21'][i] * g_hat ** pi_s['s22'][i]), ZR):  
                    verify += 1
                    #print('The verification of c2 is correct!')
                else:
                    verify += 0 
                    #print('The verification of c2 is wrong.')            
                                                
            # Calculate the blinded signature share
            prod = g_hat ** sk[m][0]
            for j in range(pp['q']):
                prod *= ct['C'][j] ** sk[m][j + 1]    
            C_hat.append(prod)
        
        sigma_hat = {'g_hat': g_hat, 'C_hat': C_hat}  
                    
        return sigma_hat  
    
    def IssueCred_3(self, pp, pk, ct, sigma_hat):
        # The user compute the the signature share  
        s = []        

        for i in range(pp['n']):
            prod = sigma_hat['C_hat'][i]
            for j in range(pp['q']):
                prod *= pk[i][0][j] ** (-ct['K'][j])                      
            s.append(prod) 

        sigma_share = {'g_hat': sigma_hat['g_hat'], 's': s}            
        return sigma_share

    def AggCred(self, pp, mpk, sigma_share, attr):
        # Calculate the langrange polynomial basis for the t authorities
        x_values = []
        for i in range(pp['t']):
            x_values.append(i + 1)
           
        basis_polynomials = lagrange_basis_polynomials(x_values)
        
        # Compute the aggregated signature sigma
        s = 1
        for i, basis_poly in enumerate(basis_polynomials):
            if int(basis_poly(0)) > 0: 
                s *= sigma_share['s'][i] ** int(basis_poly(0))
            elif int(basis_poly(0)) < 0:
                s *= (sigma_share['s'][i] ** int(-basis_poly(0))) ** (-1)     
                     
        # Verify the signature sigma
        verify = 0
        prod = mpk[0]
        for i in range(pp['q']):
            prod *= mpk[i + 1] ** attr[i]
        
        if pair(sigma_share['g_hat'], prod) == pair(s, pp['g2']):
            verify += 1
            #print('The verification of the sigma share is correct!')
        else:
            verify += 0
            #print('The verification of the sigma share is wrong.')
            
        sigma = {'g_hat': sigma_share['g_hat'], 's': s}    
        return sigma

    def ProveCred(self, pp, mpk, attr, sigma):
        # Rerandomize the signature sigma
        r, r_prime = self.group.random(ZR), self.group.random(ZR)
        
        g_hat_prime = sigma['g_hat'] ** r_prime
        s_prime = sigma['s'] ** r_prime * g_hat_prime ** r
        k = mpk[0] * pp['g2'] ** r 
        for i in range(pp['q']):
            k *= mpk[i + 1] ** attr[i]
        
        SIGMA = {'g_hat_prime': g_hat_prime, 's_prime': s_prime, 'k': k}
                               
        # Compute a NIZK argument pi_v                
        # NIZK on k value
        r0, s02 = [], []
        for i in range(pp['q'] + 2):
            r0.append(self.group.random(ZR))
        
        prod = mpk[0] ** r0[0]
        for i in range(pp['q']):
            prod *= mpk[i + 1] ** r0[i + 1]
        
        prod *= pp['g2'] ** r0[pp['q'] + 1]
        
        c0 = self.group.hash(str(prod), ZR)
        s01 = r0[0] - c0

        for i in range(pp['q']):
            s02.append(r0[i + 1] - attr[i] * c0)
        s03 = r0[pp['q'] + 1] - r * c0
               
        pi_v = {'c0': c0, 's01': s01, 's02': s02, 's03': s03}
        
        return SIGMA, pi_v
        
    def VerifyCred(self, pp, mpk, SIGMA, pi_v):    
        # Verify the NIZKP pi_v    
        verify = 0
                
        prod = mpk[0] ** pi_v['s01'] * pp['g2'] ** pi_v['s03']
        
        for i in range(pp['q']):
            prod *= mpk[i + 1] ** pi_v['s02'][i]
            
        if pi_v['c0'] == self.group.hash(str(SIGMA['k'] ** pi_v['c0'] * prod), ZR):
            verify += 1
            #print('The verification of c0 is correct!')
        else:
            verify += 0 
            #print('The verification of c0 is wrong.')
                                       
        # Verify the correctness and the revocation status            
        if SIGMA['g_hat_prime'] != 1:
            verify += 1
            #print('The verification of g_hat_prime is correct!')
        else:
            verify += 0 
            #print('The verification of g_hat_prime is wrong.')
            
        if pair(SIGMA['s_prime'], pp['g2']) == pair(SIGMA['g_hat_prime'], SIGMA['k']):            
            verify += 1
            #print('The verification of first pairing is correct!')
        else:
            verify += 0 
            #print('The verification of first pairing is wrong.')
                              
        if verify == 3:
            return 1
        else:
            return 0
                    
        
        
              
        
