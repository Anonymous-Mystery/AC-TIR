'''
| From: "AC-TIR: Practical Anonymous Credentials with Threshold Issuance and Revocation"
| type:           Anonymous Credential scheme
| setting:        Type-III Pairing

:Authors:         
:Date:            06/01/2024
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from secret_sharing import generate_random_polynomial, evaluate_polynomial, lagrange_basis_polynomials
import re, numpy, hashlib

debug = False

class ACTIR(ABEnc):       
    def __init__(self, group_obj, verbose = False):
        ABEnc.__init__(self)
        self.name = "Our scheme"
        self.group = group_obj       

    def Setup(self, q, n, t):
        # pick generators
        g, h = self.group.random(G1), self.group.random(G2)
        
        G = []        
        for i in range(q + 1):
            G.append(self.group.random(G1))
                      
        pp = {'g': g, 'h': h, 'G': G, 'q': q, 'n': n, 't': t}
        return pp
 
    def KeyGen(self, pp):       
        # Chosse q + 2 random polynomials with degree t - 1
        random_polynomials = generate_random_polynomial(pp['t'] - 1, pp['q'] + 2)    
        
        # evaluate the results with x = 0, set the master public key and master secret key
        mpk, msk = [], []
        for i, poly in enumerate(random_polynomials):
            y = int(evaluate_polynomial(poly, 0))
            mpk.append(pp['h'] ** y)
        
        # evaluate the result with x = i + 1, set the public key and secret key for each authority
        pk, sk = {}, {}
        for i in range(pp['n']):
            PK, SK = [], []
            for j, poly in enumerate(random_polynomials):
                y = int(evaluate_polynomial(poly, i + 1))
                SK.append(y)
                PK.append(pp['h'] ** y)
            pk[i] = PK
            sk[i] = SK
            
        return mpk, pk, sk
        
    def IssueCred_1(self, pp, attr):
        # Create a linear encryption key pair
        d1, d2 = self.group.random(ZR), self.group.random(ZR)
        u = pp['g'] ** d2
        v = pp['g'] ** d1
        w = u ** d1
        
        pk_u = {'u': u, 'v': v, 'w': w}
        sk_u = {'d1': d1, 'd2': d2}
        
        # Compute a commitment
        o = self.group.random(ZR)
        c_m = pp['g'] ** o 
        
        for i in range(pp['q'] + 1):
            c_m *= pp['G'][i] ** attr[i]
            
        # Compute g_hat and encryptions of each attribute
        g_hat = self.group.hash(c_m, G1)    
        
        U, V, W = [], [], []
        
        s_1, s_2 = [], []
        for i in range(pp['q'] + 1):
            s1, s2 = self.group.random(ZR), self.group.random(ZR)
            U.append(u ** s1)
            V.append(v ** s2)
            W.append(g_hat ** attr[i] * w ** (s1 + s2))
            s_1.append(s1)
            s_2.append(s2)
        
        ct = {'c_m': c_m, 'U': U, 'V': V, 'W': W, 'g_hat': g_hat}
            
        # Calculate NIZK arguments for a set of values
        # NIZK on u^d1 value
        r0 = self.group.random(ZR)
        c0 = self.group.hash(str(u ** r0), ZR)
        s0 = r0 - d1 * c0
        
        # NIZK on v^d2 value
        r1 = self.group.random(ZR)
        c1 = self.group.hash(str(v ** r1), ZR)
        s1 = r1 - d2 * c1
        
        # NIZK on g^attr[0] value
        r2 = self.group.random(ZR)
        c2 = self.group.hash(str(pp['g'] ** r2), ZR)
        s2 = r2 - attr[0] * c2
              
        # NIZK on c_m value
        r3, s3 = [], []
        for i in range(pp['q'] + 2):
            r3.append(self.group.random(ZR))      
                    
        prod = pp['g'] ** r3[0]
        for i in range(pp['q'] + 1):            
            prod *= pp['G'][i] ** r3[i + 1]
        
        c3 = self.group.hash(str(prod), ZR)       
        s3.append(r3[0] - o * c3) 
                     
        for i in range(pp['q'] + 1):
            s3.append(r3[i + 1] - attr[i] * c3)
        
        # NIZK on u^{s_1} value
        r4, s4, c4 = [], [], []
        for i in range(pp['q'] + 1): 
            r4.append(self.group.random(ZR))
            c4.append(self.group.hash(str(u ** r4[i]), ZR))  
            s4.append(r4[i] - s_1[i] * c4[i])

        # NIZK on v^{s_2} value 
        r5, s5, c5 = [], [], []
        for i in range(pp['q'] + 1): 
            r5.append(self.group.random(ZR))
            c5.append(self.group.hash(str(v ** r5[i]), ZR))  
            s5.append(r5[i] - s_2[i] * c5[i])       
             
        #NIZK on g_hat^{attr[i]} * w^{s_1 + s_2} values
        r61, s61, r62, s62, c6 = [], [], [], [], []    
        for i in range(pp['q'] + 1): 
            r61.append(self.group.random(ZR))
            r62.append(self.group.random(ZR))
            c6.append(self.group.hash(str(g_hat ** r61[i] * w ** r62[i]), ZR))                   
            s61.append(r61[i] - attr[i] * c6[i])
            s62.append(r62[i] - (s_1[i] + s_2[i]) * c6[i])      
        
        pi_s = {'g_m0': pp['g'] ** attr[0], 'c0': c0, 'c1': c1, 'c2': c2, 'c3': c3, 'c4': c4, 'c5': c5, 'c6': c6, 's0': s0, 's1': s1, 's2': s2, 's3': s3, 's4': s4, 's5': s5, 's61': s61, 's62': s62}
            
        return pk_u, sk_u, ct, pi_s

    def IssueCred_2(self, pp, pk_u, ct, pi_s, sk):
        U_hat = []
        V_hat = []
        W_hat = []
        for m in range(pp['n']):        
            verify = 0
            # Verify g_hat
            if ct['g_hat'] == self.group.hash(ct['c_m'], G1):
                verify += 1
                #print('The verification of g_hat is correct!')
            else:
                verify += 0
                #print('The verification of g_hat is wrong.')
        
            # Verify the NIZKP pi_s    
            if pi_s['c0'] == self.group.hash(str(pk_u['w'] ** pi_s['c0'] * pk_u['u'] ** pi_s['s0']), ZR):
                verify += 1
                #print('The verification of c0 is correct!')
            else:
                verify += 0 
                #print('The verification of c0 is wrong.')
            
            if pi_s['c1'] == self.group.hash(str(pk_u['w'] ** pi_s['c1'] * pk_u['v'] ** pi_s['s1']), ZR):    
                verify += 1
                #print('The verification of c1 is correct!')
            else:
                verify += 0 
                #print('The verification of c1 is wrong.')
        
            if pi_s['c2'] == self.group.hash(str(pi_s['g_m0'] ** pi_s['c2'] * pp['g'] ** pi_s['s2']), ZR):
                verify += 1
                #print('The verification of c2 is correct!')
            else:
                verify += 0 
                #print('The verification of c2 is wrong.')
        
            prod = pp['g'] ** pi_s['s3'][0]
            for i in range(pp['q'] + 1):
                prod *= pp['G'][i] ** pi_s['s3'][i + 1]
                    
            if pi_s['c3'] == self.group.hash(str(ct['c_m'] ** pi_s['c3'] * prod), ZR):
                verify += 1
                #print('The verification of c3 is correct!')
            else:
                verify += 0 
                #print('The verification of c3 is wrong.')

            for i in range(pp['q'] + 1):            
                if pi_s['c4'][i] == self.group.hash(str(ct['U'][i] ** pi_s['c4'][i] * pk_u['u'] ** pi_s['s4'][i]), ZR):
                    verify += 1
                    #print('The verification of c4 is correct!')
                else:
                    verify += 0 
                    #print('The verification of c4 is wrong.')

            for i in range(pp['q'] + 1):            
                if pi_s['c5'][i] == self.group.hash(str(ct['V'][i] ** pi_s['c5'][i] * pk_u['v'] ** pi_s['s5'][i]), ZR):
                    verify += 1
                    #print('The verification of c5 is correct!')
                else:
                    verify += 0 
                    #print('The verification of c5 is wrong.')

            for i in range(pp['q'] + 1):            
                if pi_s['c6'][i] == self.group.hash(str(ct['W'][i] ** pi_s['c6'][i] * ct['g_hat'] ** pi_s['s61'][i] * pk_u['w'] ** pi_s['s62'][i]), ZR): 
                    verify += 1
                    #print('The verification of c6 is correct!')
                else:
                    verify += 0 
                    #print('The verification of c6 is wrong.')
            
            # Calculate the blinded PS signature share               
            a, b, c = 1, 1, 1
            c *= ct['g_hat'] ** sk[m][0]
            for j in range(pp['q'] + 1):
                r1, r2 = self.group.random(ZR), self.group.random(ZR)
                a *= ct['U'][j] ** sk[m][j + 1] * pk_u['u'] ** r1   
                b *= ct['V'][j] ** sk[m][j + 1] * pk_u['v'] ** r2
                c *= ct['W'][j] ** sk[m][j + 1] * pk_u['w'] ** (r1 + r2)  
            U_hat.append(a)
            V_hat.append(b)
            W_hat.append(c)      
        
        sigma_hat = {'g_hat': ct['g_hat'], 'U_hat': U_hat, 'V_hat': V_hat, 'W_hat': W_hat}  
                    
        return sigma_hat  
    
    def IssueCred_3(self, pp, attr, pk, sk_u, sigma_hat):
        # The user compute the the signature share  
        s = []
        verify = 0
        for i in range(pp['n']):
            s.append(sigma_hat['W_hat'][i] / (sigma_hat['U_hat'][i] ** sk_u['d1'] * sigma_hat['V_hat'][i] ** sk_u['d2'])) 
            # Verify the signature share   
            #for j in range(pp['q'] + 1):            
            #    prod = pk[i][0]     
            #    prod *= pk[i][j + 1] ** attr[j]
            #    if pair(sigma_hat['g_hat'], prod) == pair(s[i], pp['h']):
            #        verify += 1
            #    else:
            #        verify += 0
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
        for i in range(pp['q'] + 1):
            prod *= mpk[i + 1] ** attr[i]
        
        if pair(sigma_share['g_hat'], prod) == pair(s, pp['h']):
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
        s_prime = (sigma['s'] * sigma['g_hat'] ** r) ** r_prime
        k = mpk[0] * pp['h'] ** r
        for i in range(pp['q'] + 1):
            k *= mpk[i + 1] ** attr[i]

        SIGMA = {'g_hat_prime': g_hat_prime, 's_prime': s_prime, 'k': k}
                
        # Calculate a threshold ElGamal Ciphertext c1, c2
        k0 = self.group.random(ZR)
        c1 = pp['h'] ** k0
        c2 = mpk[1] ** k0 * pp['h'] ** attr[0]
        
        CT = {'c1': c1, 'c2': c2}
                
        # Compute a NIZK argument pi_v
        # NIZK on c1 value
        r0 = self.group.random(ZR)    
        a0 = self.group.hash(str(pp['h'] ** r0), ZR)    
        s0 = r0 - k0 * a0    
            
        # NIZK on c2 value    
        r11, r12 = self.group.random(ZR), self.group.random(ZR)
        a1 = self.group.hash(str(mpk[1] ** r11 * pp['h'] ** r12), ZR)   
        s11 = r11 - k0 * a1
        s12 = r12 - attr[0] * a1      
        
        # NIZK on g_hat_prime ^ m0 value
        r2 = self.group.random(ZR)
        a2 = self.group.hash(str(g_hat_prime ** r2), ZR)
        s2 = r2 - attr[0] * a2
        
        # NIZK on k value
        r3, s32 = [], []
        for i in range(pp['q'] + 3):
            r3.append(self.group.random(ZR))
        
        prod = mpk[0] ** r3[0]
        for i in range(pp['q'] + 1):
            prod *= mpk[i + 1] ** r3[i + 1]
        
        prod *= pp['h'] ** r3[pp['q'] + 2]
        
        a3 = self.group.hash(str(prod), ZR)
        s31 = r3[0] - a3

        for i in range(pp['q'] + 1):
            s32.append(r3[i + 1] - attr[i] * a3)
        s33 = r3[pp['q'] + 2] - r * a3
        
        pi_v = {'g_hat_prime_m0': g_hat_prime ** attr[0], 'a0': a0, 'a1': a1, 'a2': a2, 'a3': a3, 's0': s0, 's11': s11, 's12': s12, 's2': s2, 's31': s31, 's32': s32, 's33': s33}
        
        return SIGMA, CT, pi_v
        
    def RevokeCred(self, pp, mpk, sk, SIGMA, CT, pi_v):
        # Calculate the langrange polynomial basis for the t authorities
        x_values = []
        for i in range(pp['t']):
            x_values.append(i + 1)
            
        basis_polynomials = lagrange_basis_polynomials(x_values)
        
        # Compute the revocation tag h^m0
        prod = 1
        for i, basis_poly in enumerate(basis_polynomials):
            if int(basis_poly(0)) > 0: 
                prod *= CT['c1'] ** (sk[i][1] * int(basis_poly(0))) 
            elif int(basis_poly(0)) < 0:        
                prod *= (CT['c1'] ** (sk[i][1] * int(-basis_poly(0)))) ** (-1)   
        tag = CT['c2'] / prod
        
        VLR = []
        VLR.append(tag)
        
        return VLR
        
    def VerifyCred(self, pp, mpk, SIGMA, CT, pi_v, VLR):    
        # Verify the NIZKP pi_v    
        verify = 0
        
        if pi_v['a0'] == self.group.hash(str(CT['c1'] ** pi_v['a0'] * pp['h'] ** pi_v['s0']), ZR):
            verify += 1
            #print('The verification of a0 is correct!')
        else:
            verify += 0     
            #print('The verification of a0 is wrong.')      
            
        if pi_v['a1'] == self.group.hash(str(CT['c2'] ** pi_v['a1'] * mpk[1] ** pi_v['s11'] * pp['h'] ** pi_v['s12']), ZR):    
            verify += 1
            #print('The verification of a1 is correct!')
        else:
            verify += 0 
            #print('The verification of a1 is wrong.')
            
        if pi_v['a2'] == self.group.hash(str(pi_v['g_hat_prime_m0'] ** pi_v['a2'] * SIGMA['g_hat_prime'] ** pi_v['s2']), ZR):      
            verify += 1
            #print('The verification of a2 is correct!')
        else:
            verify += 0 
            #print('The verification of a2 is wrong.')
        
        prod = mpk[0] ** pi_v['s31'] * pp['h'] ** pi_v['s33']
        
        for i in range(pp['q'] + 1):
            prod *= mpk[i + 1] ** pi_v['s32'][i]
            
        if pi_v['a3'] == self.group.hash(str(SIGMA['k'] ** pi_v['a3'] * prod), ZR):
            verify += 1
            #print('The verification of a3 is correct!')
        else:
            verify += 0 
            #print('The verification of a3 is wrong.')
            
        # Verify the correctness and the revocation status            
        if pi_v['g_hat_prime_m0'] != 1:
            verify += 1
            #print('The verification of g_hat_prime_m0 is correct!')
        else:
            verify += 0 
            #print('The verification of g_hat_prime_m0 is wrong.')
            
        if pair(SIGMA['s_prime'], pp['h']) == pair(SIGMA['g_hat_prime'], SIGMA['k']):            
            verify += 1
            #print('The verification of first pairing is correct!')
        else:
            verify += 0 
            #print('The verification of first pairing is wrong.')
            
        if pair(pi_v['g_hat_prime_m0'], pp['h']) == pair(SIGMA['g_hat_prime'], VLR[0]):            
            verify += 1
            #print('The verification of revocation is correct!')
        else:
            verify += 0   
            #print('The verification of revocation is wrong.')      
                
        if verify == 7:
            return 1
        else:
            return 0
                    
        
        
              
        
