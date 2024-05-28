'''
:Date:            4/2023
'''

from charm.toolbox.pairinggroup import PairingGroup, GT, ZR
from ACTIR import ACTIR
from Coconut import Coconut
from Coconut_Prime import Coconut_Prime
import time


#--------------------------------------------------- Measure average time module ----------------------------------------------
def measure_average_times_actir(actir, q, n, t, attr, N = 3):   
    sum_Setup = 0
    sum_KeyGen = 0
    sum_IssueCred_1 = 0
    sum_IssueCred_2 = 0
    sum_IssueCred_3 = 0
    sum_AggCred = 0
    sum_ProveCred = 0
    sum_RevokeCred = 0
    sum_VerifyCred = 0

    for i in range(N):
        # setup time
        start_Setup = time.time()
        pp = actir.Setup(q, n, t)
        end_Setup = time.time()
        time_Setup = end_Setup - start_Setup
        sum_Setup += time_Setup

        # Key generation time
        start_KeyGen = time.time()
        mpk, pk, sk = actir.KeyGen(pp)
        end_KeyGen = time.time()
        time_KeyGen = end_KeyGen - start_KeyGen 
        sum_KeyGen += time_KeyGen 

        # IssueCred_1 time
        start_IssueCred_1 = time.time()
        pk_u, sk_u, ct, pi_s = actir.IssueCred_1(pp, attr)
        end_IssueCred_1 = time.time()
        time_IssueCred_1 = end_IssueCred_1 - start_IssueCred_1
        sum_IssueCred_1 += time_IssueCred_1

        # IssueCred_2 time
        start_IssueCred_2 = time.time()
        sigma_hat = actir.IssueCred_2(pp, pk_u, ct, pi_s, sk)
        end_IssueCred_2 = time.time()
        time_IssueCred_2 = end_IssueCred_2 - start_IssueCred_2
        sum_IssueCred_2 += time_IssueCred_2
        
        # IssueCred_3 time
        start_IssueCred_3 = time.time()
        sigma_share = actir.IssueCred_3(pp, attr, pk, sk_u, sigma_hat)
        end_IssueCred_3 = time.time()
        time_IssueCred_3 = end_IssueCred_3 - start_IssueCred_3
        sum_IssueCred_3 += time_IssueCred_3        

        sigma_share['s'] = sigma_share['s'][:t]
                      
        # Aggregate Credential time
        start_AggCred = time.time()
        sigma = actir.AggCred(pp, mpk, sigma_share, attr)
        end_AggCred = time.time()
        time_AggCred = end_AggCred - start_AggCred
        sum_AggCred += time_AggCred 
        
        # Prove Credential time
        start_ProveCred = time.time()
        SIGMA, CT, pi_v = actir.ProveCred(pp, mpk, attr, sigma)
        end_ProveCred = time.time()
        time_ProveCred = end_ProveCred - start_ProveCred
        sum_ProveCred += time_ProveCred
        
        # Revoke Credential time
        start_RevokeCred = time.time()
        VLR = actir.RevokeCred(pp, mpk, sk, SIGMA, CT, pi_v)
        end_RevokeCred = time.time()
        time_RevokeCred = end_RevokeCred - start_RevokeCred
        sum_RevokeCred += time_RevokeCred                

        # Verify Credential time
        start_VerifyCred = time.time()
        result = actir.VerifyCred(pp, mpk, SIGMA, CT, pi_v, VLR)
        end_VerifyCred = time.time()
        time_VerifyCred = end_VerifyCred - start_VerifyCred
        sum_VerifyCred += time_VerifyCred
    
    # compute average time
    time_Setup = sum_Setup/N
    time_KeyGen = sum_KeyGen/N
    time_IssueCred_1 = sum_IssueCred_1/N
    time_IssueCred_2 = sum_IssueCred_2/N
    time_IssueCred_3 = sum_IssueCred_3/N 
    time_AggCred = sum_AggCred/N 
    time_ProveCred = sum_ProveCred/N 
    time_RevokeCred = sum_RevokeCred/N    
    time_VerifyCred = sum_VerifyCred/N        

    return [time_Setup, time_KeyGen, time_IssueCred_1, time_IssueCred_2, time_IssueCred_3, time_AggCred, time_ProveCred, time_RevokeCred, time_VerifyCred]


def measure_average_times_coconut(coconut, q, n, t, attr, N = 5):   
    sum_Setup = 0
    sum_KeyGen = 0
    sum_IssueCred_1 = 0
    sum_IssueCred_2 = 0
    sum_IssueCred_3 = 0
    sum_AggCred = 0
    sum_ProveCred = 0
    sum_VerifyCred = 0

    for i in range(N):
        # setup time
        start_Setup = time.time()
        pp = coconut.Setup(q, n, t)
        end_Setup = time.time()
        time_Setup = end_Setup - start_Setup
        sum_Setup += time_Setup

        # Key generation time
        start_KeyGen = time.time()
        mpk, pk, sk = coconut.KeyGen(pp)
        end_KeyGen = time.time()
        time_KeyGen = end_KeyGen - start_KeyGen 
        sum_KeyGen += time_KeyGen 

        # IssueCred_1 time
        start_IssueCred_1 = time.time()
        pk_u, sk_u, ct, pi_s = coconut.IssueCred_1(pp, attr)
        end_IssueCred_1 = time.time()
        time_IssueCred_1 = end_IssueCred_1 - start_IssueCred_1
        sum_IssueCred_1 += time_IssueCred_1

        # IssueCred_2 time
        start_IssueCred_2 = time.time()
        sigma_hat = coconut.IssueCred_2(pp, pk_u, ct, pi_s, sk)
        end_IssueCred_2 = time.time()
        time_IssueCred_2 = end_IssueCred_2 - start_IssueCred_2
        sum_IssueCred_2 += time_IssueCred_2
        
        # IssueCred_3 time
        start_IssueCred_3 = time.time()
        sigma_share = coconut.IssueCred_3(pp, sk_u, sigma_hat)
        end_IssueCred_3 = time.time()
        time_IssueCred_3 = end_IssueCred_3 - start_IssueCred_3
        sum_IssueCred_3 += time_IssueCred_3        

        sigma_share['s'] = sigma_share['s'][:t]
                     
        # Aggregate Credential time
        start_AggCred = time.time()
        sigma = coconut.AggCred(pp, mpk, sigma_share, attr)
        end_AggCred = time.time()
        time_AggCred = end_AggCred - start_AggCred
        sum_AggCred += time_AggCred 
        
        # Prove Credential time
        start_ProveCred = time.time()
        SIGMA, pi_v = coconut.ProveCred(pp, mpk, attr, sigma)
        end_ProveCred = time.time()
        time_ProveCred = end_ProveCred - start_ProveCred
        sum_ProveCred += time_ProveCred
                     
        # Verify Credential time
        start_VerifyCred = time.time()
        result = coconut.VerifyCred(pp, mpk, SIGMA, pi_v)
        end_VerifyCred = time.time()
        time_VerifyCred = end_VerifyCred - start_VerifyCred
        sum_VerifyCred += time_VerifyCred
    
    # compute average time
    time_Setup = sum_Setup/N
    time_KeyGen = sum_KeyGen/N
    time_IssueCred_1 = sum_IssueCred_1/N
    time_IssueCred_2 = sum_IssueCred_2/N
    time_IssueCred_3 = sum_IssueCred_3/N 
    time_AggCred = sum_AggCred/N 
    time_ProveCred = sum_ProveCred/N   
    time_VerifyCred = sum_VerifyCred/N        

    return [time_Setup, time_KeyGen, time_IssueCred_1, time_IssueCred_2, time_IssueCred_3, time_AggCred, time_ProveCred, time_VerifyCred]
    

def measure_average_times_coconut_prime(coconut_prime, q, n, t, attr, N = 5):   
    sum_Setup = 0
    sum_KeyGen = 0
    sum_IssueCred_1 = 0
    sum_IssueCred_2 = 0
    sum_IssueCred_3 = 0
    sum_AggCred = 0
    sum_ProveCred = 0
    sum_VerifyCred = 0

    for i in range(N):
        # setup time
        start_Setup = time.time()
        pp = coconut_prime.Setup(q, n, t)
        end_Setup = time.time()
        time_Setup = end_Setup - start_Setup
        sum_Setup += time_Setup

        # Key generation time
        start_KeyGen = time.time()
        mpk, pk, sk = coconut_prime.KeyGen(pp)
        end_KeyGen = time.time()
        time_KeyGen = end_KeyGen - start_KeyGen 
        sum_KeyGen += time_KeyGen 

        # IssueCred_1 time
        start_IssueCred_1 = time.time()
        ct, pi_s = coconut_prime.IssueCred_1(pp, attr)
        end_IssueCred_1 = time.time()
        time_IssueCred_1 = end_IssueCred_1 - start_IssueCred_1
        sum_IssueCred_1 += time_IssueCred_1

        # IssueCred_2 time
        start_IssueCred_2 = time.time()
        sigma_hat = coconut_prime.IssueCred_2(pp, ct, pi_s, sk)
        end_IssueCred_2 = time.time()
        time_IssueCred_2 = end_IssueCred_2 - start_IssueCred_2
        sum_IssueCred_2 += time_IssueCred_2
        
        # IssueCred_3 time
        start_IssueCred_3 = time.time()
        sigma_share = coconut_prime.IssueCred_3(pp, pk, ct, sigma_hat)
        end_IssueCred_3 = time.time()
        time_IssueCred_3 = end_IssueCred_3 - start_IssueCred_3
        sum_IssueCred_3 += time_IssueCred_3        

        sigma_share['s'] = sigma_share['s'][:t]
                     
        # Aggregate Credential time
        start_AggCred = time.time()
        sigma = coconut_prime.AggCred(pp, mpk, sigma_share, attr)
        end_AggCred = time.time()
        time_AggCred = end_AggCred - start_AggCred
        sum_AggCred += time_AggCred 
        
        # Prove Credential time
        start_ProveCred = time.time()
        SIGMA, pi_v = coconut_prime.ProveCred(pp, mpk, attr, sigma)
        end_ProveCred = time.time()
        time_ProveCred = end_ProveCred - start_ProveCred
        sum_ProveCred += time_ProveCred
                     
        # Verify Credential time
        start_VerifyCred = time.time()
        result = coconut_prime.VerifyCred(pp, mpk, SIGMA, pi_v)
        end_VerifyCred = time.time()
        time_VerifyCred = end_VerifyCred - start_VerifyCred
        sum_VerifyCred += time_VerifyCred
    
    # compute average time
    time_Setup = sum_Setup/N
    time_KeyGen = sum_KeyGen/N
    time_IssueCred_1 = sum_IssueCred_1/N
    time_IssueCred_2 = sum_IssueCred_2/N
    time_IssueCred_3 = sum_IssueCred_3/N 
    time_AggCred = sum_AggCred/N 
    time_ProveCred = sum_ProveCred/N   
    time_VerifyCred = sum_VerifyCred/N        

    return [time_Setup, time_KeyGen, time_IssueCred_1, time_IssueCred_2, time_IssueCred_3, time_AggCred, time_ProveCred, time_VerifyCred]    
#----------------------------------print running time module (IssueCred in total)-----------------------------------------------
'''
def print_running_time_actir(scheme_name, times):
    record = '{:<22}'.format(scheme_name) + format(times[0] * 1000, '7.2f') + '   ' + format(times[1] * 1000, '7.2f') + '     ' + format((times[2] + times[3] + times[4]) * 1000, '7.2f') + '      ' + format(times[5] * 1000, '7.2f') + '      ' + format(times[6] * 1000, '7.2f') + '      ' + format(times[7] * 1000, '7.2f') + '        ' + format(times[8] * 1000, '7.2f')
    print(record)
    return record
    
def print_running_time_coconut(scheme_name, times):
    record = '{:<22}'.format(scheme_name) + format(times[0] * 1000, '7.2f') + '   ' + format(times[1] * 1000, '7.2f') + '     ' + format((times[2] + times[3] + times[4]) * 1000, '7.2f') + '      ' + format(times[5] * 1000, '7.2f') + '      ' + format(times[6] * 1000, '7.2f') + '      ' + format(0, '7.2f') + '        ' + format(times[7] * 1000, '7.2f')
    print(record)
    return record
'''
#----------------------------------print running time module (IssueCred separate) ----------------------------------------------

def print_running_time_actir(scheme_name, n, times):
    record = '{:<10}'.format(scheme_name) + format(times[0] * 1000, '7.2f') + '   ' + format(times[1] * 1000, '7.2f') + '   ' + format((times[2]) * 1000, '7.2f') + '     ' + format((times[3]) / n * 1000, '7.2f') + '    ' + format((times[4]) * 1000, '7.2f') + '   ' + format(times[5] * 1000, '7.2f') + '      ' + format(times[6] * 1000, '7.2f') + '      ' + format(times[7] * 1000, '7.2f') + '        ' + format(times[8] * 1000, '7.2f')
    print(record)
    return record
    
def print_running_time_coconut(scheme_name, n, times):
    record = '{:<10}'.format(scheme_name) + format(times[0] * 1000, '7.2f') + '   ' + format(times[1] * 1000, '7.2f') + '   ' + format((times[2]) * 1000, '7.2f') + '    ' + format((times[3])/ n * 1000, '7.2f') + '    ' + format((times[4]) * 1000, '7.2f') + '    ' + format(times[5] * 1000, '7.2f') + '      ' + format(times[6] * 1000, '7.2f') + '      ' + format(0, '7.2f') + '        ' + format(times[7] * 1000, '7.2f')
    print(record)
    return record    
    
#-------------------------------------------------- run all module ------------------------------------------------------------
def run(pairing_group, q, n, t, attr):   
  
    actir = ACTIR(pairing_group)       
    actir_times = measure_average_times_actir(actir, q, n, t, attr)               

    coconut = Coconut(pairing_group)
    coconut_times = measure_average_times_coconut(coconut, q, n, t, attr)
    
    coconut_prime = Coconut_Prime(pairing_group)
    coconut_prime_times = measure_average_times_coconut_prime(coconut_prime, q, n, t, attr)
    
    print('\n')
    print('*'*70)
    print('Running times (ms) curve MNT224: attribute universe = {}  authority number = {} threshold number = {}'.format(q, n, t))
    print('*'*100)
    #algos = ['Setup', 'KeyGen', 'IssueCred', 'AggCred', 'ProveCred', 'RevokeCred', 'VerifyCred']   
    algos = ['Setup', 'KeyGen', 'Issue1', 'Issue2', 'Issue3', 'AggCred', 'ProveCred', 'RevokeCred', 'VerifyCred']  
    algo_string = 'Scheme {:<3}'.format('') + '  ' + algos[0] + '    ' + algos[1] + '     ' + algos[2] + '     ' + algos[3] + '     ' + algos[4] + '     ' + algos[5] + '    ' + algos[6] + '    ' + algos[7] + '    ' + algos[8]
    print('-'*100)
    print(algo_string)
    print('-'*100)
    record1 = print_running_time_actir(actir.name, n, actir_times)  
    record2 = print_running_time_coconut(coconut.name, n, coconut_times)              
    record3 = print_running_time_coconut(coconut_prime.name, n, coconut_prime_times)       
    print('-'*100)          
   
    with open('Results/Results2.txt', 'a') as f:
        f.write('*' * 120 + '\n') 
        f.write('Scheme: ' + 'Running times (ms) curve MNT224: attribute universe = {}  authority number = {} threshold number = {} '.format(q, n, t) + '\n')
        f.write(algo_string + '\n')
        f.write(record1 + '\n')       
        f.write(record2 + '\n')     
        f.write(record3 + '\n')     
        #f.write('\n')     
    open('Results/Results2.txt', 'r')  
    with open('Results/Results2.txt', 'a') as f:     
        f.write('*' * 120 + '\n')            
    return             

# -------------------------------------------------- Main functions module ---------------------------------------------------    
                  
def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('MNT224')
           
    # Set the number of authorities and threshold
    n = [10, 20]
    t = 6
    
    # Set the number of attributes
    q = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

    # Select random q + 1 attributes
    attr = []
    for n1 in n:
        for i in q:  
            for j in range(i + 1):
                attr.append(pairing_group.random(ZR))
    
            run(pairing_group, i, n1, t, attr)  
        
if __name__ == "__main__":
    debug = True
    main()                 
           
