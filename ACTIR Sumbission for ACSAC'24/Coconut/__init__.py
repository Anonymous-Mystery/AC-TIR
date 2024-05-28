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

class Coconut(ABEnc):       
    def __init__(self, group_obj, verbose = False):
        ABEnc.__init__(self)
        self.name = "Coconut"
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
            PK, SK = [], []
            for j, poly in enumerate(random_polynomials):
                y = int(evaluate_polynomial(poly, i + 1))
                SK.append(y)
                PK.append(pp['g2'] ** y)
            pk[i] = PK
            sk[i] = SK
            
        return mpk, pk, sk
        
    def IssueCred_1(self, pp, attr):
        # Create a El-Gamal encryption key pair
        d = self.group.random(ZR)
        gamma = pp['g1'] ** d
        
        pk_u = gamma
        sk_u = d
        
        # Compute a commitment
        o = self.group.random(ZR)
        c_m = pp['g1'] ** o 
        
        for i in range(pp['q']):
            c_m *= pp['h'][i] ** attr[i] 
            
        # Compute g_hat and encryptions of each attribute
        g_hat = self.group.hash(c_m, G1)   
        
        K, C1, C2 = [], [], []       
        for i in range(pp['q']):
            k = self.group.random(ZR)        
            K.append(k)
            C1.append(pp['g1'] ** k)
            C2.append(gamma ** k * g_hat ** attr[i])
                      
        ct = {'c_m': c_m, 'C1': C1, 'C2': C2}
            
        # Calculate NIZK arguments for a set of values
        # NIZK on gamma value
        r0 = self.group.random(ZR)
        c0 = self.group.hash(str(pp['g1'] ** r0), ZR)
        s0 = r0 - d * c0
               
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
        
        # NIZK on C1 values
        r2, s2, c2 = [], [], []
        for i in range(pp['q']): 
            r2.append(self.group.random(ZR))
            c2.append(self.group.hash(str(pp['g1'] ** r2[i]), ZR))  
            s2.append(r2[i] - K[i] * c2[i])
                    
        # NIZK on C2 values
        r31, r32, s31, s32, c3 = [], [], [], [], [] 
        for i in range(pp['q']): 
            r31.append(self.group.random(ZR))
            r32.append(self.group.random(ZR))
            c3.append(self.group.hash(str(gamma ** r31[i] * g_hat ** r32[i]), ZR))                   
            s31.append(r31[i] - K[i] * c3[i])
            s32.append(r32[i] - attr[i] * c3[i])  
                       
        pi_s = {'c0': c0, 'c1': c1, 'c2': c2, 'c3': c3, 's0': s0, 's1': s1, 's2': s2, 's31': s31, 's32': s32}
            
        return pk_u, sk_u, ct, pi_s

    def IssueCred_2(self, pp, pk_u, ct, pi_s, sk):
        C1_hat = []
        C2_hat = []
        
        for m in range(pp['n']):
            # Recompute g_hat
            g_hat = self.group.hash(ct['c_m'], G1)
               
            # Verify the NIZKP pi_s    
            verify = 0
                
            if pi_s['c0'] == self.group.hash(str(pk_u ** pi_s['c0'] * pp['g1'] ** pi_s['s0']), ZR):
                verify += 1
                #print('The verification of c0 is correct!')
            else:
                verify += 0 
                #print('The verification of c0 is wrong.')
                            
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
                if pi_s['c2'][i] == self.group.hash(str(ct['C1'][i] ** pi_s['c2'][i] * pp['g1'] ** pi_s['s2'][i]), ZR):
                    verify += 1
                    #print('The verification of c2 is correct!')
                else:
                    verify += 0 
                    #print('The verification of c2 is wrong.')        
        
            for i in range(pp['q']):                                   
                if pi_s['c3'][i] == self.group.hash(str(ct['C2'][i] ** pi_s['c3'][i] * pk_u ** pi_s['s31'][i] * g_hat ** pi_s['s32'][i]), ZR):   
                    verify += 1
                    #print('The verification of c3 is correct!')
                else:
                    verify += 0 
                    #print('The verification of c3 is wrong.')            
                                                
            # Calculate the blinded PS signature share

            a, b = 1, 1
            b *= g_hat ** sk[m][0]
            for j in range(pp['q']):
                a *= ct['C1'][j] ** sk[m][j + 1]    
                b *= ct['C2'][j] ** sk[m][j + 1] 
            C1_hat.append(a)
            C2_hat.append(b)     
        
        sigma_hat = {'g_hat': g_hat, 'C1_hat': C1_hat, 'C2_hat': C2_hat}  
                    
        return sigma_hat  
    
    def IssueCred_3(self, pp, sk_u, sigma_hat):
        # The user compute the the signature share  
        s = []
        for i in range(pp['n']):
            s.append(sigma_hat['C2_hat'][i] * (sigma_hat['C1_hat'][i] ** (-sk_u)) ) 

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
        s_prime = sigma['s'] ** r_prime
        k = mpk[0] * pp['g2'] ** r
        for i in range(pp['q']):
            k *= mpk[i + 1] ** attr[i]
        v = g_hat_prime ** r
        
        SIGMA = {'g_hat_prime': g_hat_prime, 's_prime': s_prime, 'k': k, 'v': v}
                               
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
        
        # NIZK on v value
        r1 = self.group.random(ZR)
        c1 = self.group.hash(str(g_hat_prime ** r1), ZR)
        s1 = r1 - r * c1
        
        pi_v = {'c0': c0, 'c1': c1, 's01': s01, 's02': s02, 's03': s03, 's1': s1}
        
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
        
        
        if pi_v['c1'] == self.group.hash(str(SIGMA['v'] ** pi_v['c1'] * SIGMA['g_hat_prime'] ** pi_v['s1']), ZR):
            verify += 1
            #print('The verification of c1 is correct!')
        else:
            verify += 0 
            #print('The verification of c1 is wrong.')

                        
        # Verify the correctness and the revocation status            
        if SIGMA['g_hat_prime'] != 1:
            verify += 1
            #print('The verification of g_hat_prime is correct!')
        else:
            verify += 0 
            #print('The verification of g_hat_prime is wrong.')
            
        if pair(SIGMA['s_prime'] * SIGMA['v'], pp['g2']) == pair(SIGMA['g_hat_prime'], SIGMA['k']):            
            verify += 1
            #print('The verification of first pairing is correct!')
        else:
            verify += 0 
            #print('The verification of first pairing is wrong.')
                              
        if verify == 4:
            return 1
        else:
            return 0
                    
        
        
              
        
