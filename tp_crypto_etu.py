# -*- coding: utf-8 -*-
# Ecrivez votre programme ci-dessous.
# Bouton Fullscreen pour passer en plein ecran
# Ensuite Save + Run puis Save + Evaluate
# Faical RAHMANI
import os
from random import randint
from math import log, sqrt


################################################
###                                          ###
### Implémentez ici les fonctions demandées  ###
###                                          ###
################################################


# ********************
#
# fonctions arithmétiques de base
#
# ********************


#
# euclid(a,b)
# retourne l'unique PGCD positif des deux entiers relatifs a et b passés en
# paramètres en utilisant l'algorithme d'Euclide;
#

def euclid(a, b):
	a = abs(a)
	b = abs(b)
	while b != 0:
		a, b = b, a % b
	return a


#
# extended_euclid(a,b):
# les paramètres a et b sont des entiers relatifs. Cette fonction retourne un
# triplet d,u,v (dans cet ordre) avec d l'unique PGCD positif des deux entiers
# a et b et (u,v) un couple de coefficients de Bezout vérifiant a.u+b.v=d.
# L'algorithme utilisé est l'algorithme d'Euclide étendu vu en cours;
#

def extended_euclid(a, b):
	u = [1, 0]
	v = [0, 1]
	while b != 0:
		q = a // b
		a, b = b, a % b
		u[0], u[1] = u[1], u[0] - q * u[1]
		v[0], v[1] = v[1], v[0] - q * v[1]

	return (a, u[0], v[0]) if a > 0 else (-a, -u[0], -v[0])


#
# modular_inverse(a,n):
# fonction qui prend en entrée deux entiers a et n dans Z et qui retourne
# l'unique inverse modulaire de a modulo n compris entre 0 et n-1. Si a n'est
# pas inversible modulo n, alors 0 est renvoyé;

def modular_inverse(a, n):
    n = abs(n)
    pgcd, u, v = extended_euclid(a, n)
    if pgcd != 1:
        return 0
    else:
        return u + n if u < 0 else u


#
# naive_euler_function(n): fonction qui prend en entrée un entier positif n>1
# et qui retourne l'indicatrice d'Euler de n en testant un par un tous les
# entiers compris entre 1 et n;
#

def naive_euler_function(n):
	p = 0
	for i in range(1, n):
		if euclid(i, n) == 1:
			p = p + 1
	return p


#
# square_and_multiply(a,k,n):
# fonction qui prend en entrée trois entiers a, k et n avec k positif et
# qui calcule akmodn avec l'algorithme Square and Multiply
#

def square_and_multiply(a, k, n):
    k = bin(k)[2::]
    n = abs(n)
    h = 1
    for i in range(len(k)):
        h = (h*h)%n
        if k[i] == '1' :
            h = (h*a)%n
    return h

#
# euler_function(L1,L2):
# fonction qui prend en entrée deux listes L1=[p1,p2,…,pk] et L2=[α1,α2,…,αk]
# de même longueur avec L1 une liste de nombres premiers distincts et L2 une liste
# d'entiers strictement positifs. La fonction retourne l'indicatrice d'Euler
# de n avec n=p1^a1 x p2^a2 x … x pk^ak selon la formule vue en cours.
#

def euler_function(L1, L2):
	phin = 1
	for i in range(len(L1)):
		phin = phin * (L1[i] - 1)*(L1[i] ** (L2[i]-1))
	return phin



#
# inversibles(n): fonction qui prend en entrée un entier positif n et qui
# retourne la liste de tous les éléments inversibles modulo n (les inverses
# ne sont pas demandés);
#

def inversibles(n):
	L = []
	for i in range(1,n):
		if euclid(i, n) == 1:
			L.append(i)
	return L


#
# miller_rabin(n,d): fonction qui prend en entrée deux entiers positifs n et d
# et qui teste (avec le test de Miller-Rabin) si n est un nombre premier.
# La probabilité d'erreur de l'algorithme doit être inférieure à 1/4^d.
#


def miller_rabin(n, d):
	
   # on sait que 2 et 3 sont des premiers 
   if n == 2 or n ==3 :
       return True
   # les pairs ne sont pas des premiers
   if n % 2 == 0 or n <= 1:
       return False
   # traiter le cas d'un nombre impair    
   s, u = 0, n - 1
   while u % 2 == 0:
       s += 1
       u //= 2
          
   for _ in range(d):
       a = randint(2, n-1)     
       x = square_and_multiply(a,u,n)            
       if x == 1 or x == n - 1:
           continue                
       for _ in range(s - 1):      
           x = square_and_multiply(x, 2, n)        
           if x == n - 1:
               break               
       else:
           return False 
       
   return True 


#
# generate_prime(k,d): fonction qui prend en entrée deux entiers positifs k et
# d et qui retourne un nombre premier ayant exactement k bits. L'algorithme
# pourra se tromper sur la primalité du nombre avec une probabilité inférieure
# à 1/4^d
#

def generate_prime(k, d):
    pr = randint(2**(k-1)+2**(k-2),(2**k)-1)
    while not miller_rabin(pr,d):
        pr = randint(2**(k-1)+2**(k-2),(2**k)-1)
    return pr
            

# ********************
#
# Protocole RSA
#
# ********************

#
# generate_key(k): fonction qui prend en entrée un entier positif et pair k et
# qui retourne les éléments [p,q,n=pq,phi(n),d,e] (dans cet ordre) avec (n,e)
# la clé publique du protocole RSA et (p,q,phi(n),d) la clé privée associée.
# Les entiers p et q devront être des nombres premiers distincts avec
# exactement k/2 bits et n aura exactement k bits. Pour tester la primalité,
# vous pourrez prendre comme paramètre d=40 (pour Miller-Rabin).
#

def generate_key(k):
    p, q, n, phin, d, e = 0, 0, 0, 0, 0, 0
    
    p = generate_prime(k/2,40)
    q = generate_prime(k/2,40)
    while p == q:
       q = generate_prime(k/2,40)
    n = p*q
    phin = (p-1)*(q-1)
    while True:
      e = randint(2 ** (k - 1), 2 ** (k))
      if euclid(e, phin) == 1:
         break
    d = modular_inverse(e,phin)    
        
    return p, q, n, phin, d, e


#
# encipher(m,n,e): fonction de chiffrement RSA qui retourne le chiffré du
# message m (élément inversible de Z/nZ)  en utilisant la clé publique RSA (n,e).
#

def encipher(m, n, e):
	return square_and_multiply(m,e,n)


#
# decipher(c,d,n): fonction de déchiffrement RSA qui retourne le message clair
# associé au chiffré c (élément inversible de Z/nZ) en utilisant la clé privée d.
#

def decipher(c, n, d):
	return square_and_multiply(c,d,n)


# ********************
#
# fonction de factorisation lorsque l'exposant secret est petit
#
# ********************

#
# generate_key_wiener(k): fonction qui prend en entrée un entier positif et
# pair k et qui retourne les éléments [p,q,n=pq,phi(n),d,e] (dans cet ordre)
# avec (n,e) la clé publique du protocole RSA et (p,q,phi(n),d) la clé privée
# associée. Les entiers p et q devront être des nombres premiers distincts avec
# exactement k/2 bits et n aura exactement k bits. Pour tester la primalité,
# vous pourrez prendre comme paramètre d=40 (pour Miller-Rabin).
# La clé privée d doit satisfaire l'inégalité
# d^2 <= sqrt(N)/6
# pour appliquer l'attaque de Wiener.
#


#def generate_key_wiener(k):
#	p, q, n, phin, d, e = 0, 0, 0, 0, 0, 0
#	return p, q, n, phin, d, e


#
# find_secret_key_wiener(n,e): fonction qui retourne la clé secrète d associée
# à la clé publique RSA (n,e) en appliquant l'attaque de Wener.
# Si l'attaque échoue, elle doit retourner -1.
# L'attaque échoue lorsque toutes les réduites ont été calculées mais qu'aucune
# n'a révélé la clé secrète.
#

#def find_secret_key_wiener(n, e):
#	return -1


#################################################
###
### Fonctions pré implémentées pour tester vos fonctions.
### Ces  fonctions sont appelées dans le programme principal.
### Il suffit donc de commenter/décommenter les lignes du programme principal
### pour exécuter ou non ces fonctions
###
#################################################

def test_euclid():
	print("****** euclid ******")
	print("1:", euclid(0, 15) == 15)
	print("2:", euclid(15, 0) == 15)
	print("3:", euclid(15, 9) == 3)
	print("4:", euclid(9, 15) == 3)
	print("5:", euclid(-9, 15) == 3)
	print("6:", euclid(9, -15) == 3)
	print("7:", euclid(-9, -15) == 3)
	print("8:", euclid(1000, 1) == 1)


def test_extended_euclid():
	print("****** extended_euclid ******")
	a = 0
	b = 15
	d, u, v = extended_euclid(a, b)
	print("1:", d >= 0 and a * u + b * v == d)
	a = 15
	b = 0
	d, u, v = extended_euclid(a, b)
	print("2:", d >= 0 and a * u + b * v == d)
	a = 15
	b = 9
	d, u, v = extended_euclid(a, b)
	print("3:", d >= 0 and a * u + b * v == d)
	a = 9
	b = 15
	d, u, v = extended_euclid(a, b)
	print("4:", d >= 0 and a * u + b * v == d)
	a = -15
	b = 9
	d, u, v = extended_euclid(a, b)
	print("5:", d >= 0 and a * u + b * v == d)
	a = -9
	b = -15
	d, u, v = extended_euclid(a, b)
	print("6:", d >= 0 and a * u + b * v == d)
	a = 1000
	b = 1
	d, u, v = extended_euclid(a, b)
	print("7:", d >= 0 and a * u + b * v == d)


def test_modular_inverse():
	print("****** modular_inverse ******")
	print("1:", modular_inverse(7, 13) == 2)
	print("2:", modular_inverse(7, -13) == 2)
	print("3:", modular_inverse(-7, 13) == 11)
	print("4:", modular_inverse(-7, -13) == 11)
	print("5:", modular_inverse(0, 13) == 0)
	print("6:", modular_inverse(8, 14) == 0)


def test_naive_euler_function():
	print("****** naive_euler_function ******")
	print("1:", naive_euler_function(2) == 1)
	print("2:", naive_euler_function(3) == 2)
	print("3:", naive_euler_function(4) == 2)
	print("4:", naive_euler_function(5) == 4)
	print("5:", naive_euler_function(6) == 2)
	print("6:", naive_euler_function(7) == 6)
	print("7:", naive_euler_function(8) == 4)
	print("8:", naive_euler_function(9) == 6)
	print("9:", naive_euler_function(10) == 4)
	print("10:", naive_euler_function(11) == 10)
	print("11:", naive_euler_function(12) == 4)


def test_square_and_multiply():
	print("****** square_and_multiply ******")
	print("1:", square_and_multiply(2, 0, 10) == 2 ** 0 % 10)
	print("2:", square_and_multiply(2, 1, 10) == 2 ** 1 % 10)
	print("3:", square_and_multiply(2, 30, 10) == 2 ** 30 % 10)
	print("4:", square_and_multiply(-2, 30, 10) == (-2) ** 30 % 10)
	print("5:", square_and_multiply(2, 30, -10) == 2 ** 30 % 10)


def test_euler_function():
	print("****** euler_function ******")
	L1 = [2, 3, 5, 7]
	L2 = [1, 2, 3, 1]
	n = 1
	for i in range(len(L1)):
		n *= L1[i] ** L2[i]
	print("1:", euler_function(L1, L2) == naive_euler_function(n))


def test_inversibles():
	print("****** inversibles ******")
	n = 30
	L = inversibles(n)
	L = list(set(L))
	test = True
	for i in L:
		test = test and (euclid(i, n) == 1)
	test = test and (len(L) == naive_euler_function(n))
	print("1:", test)


def test_miller_rabin():
	print("****** miller_rabin ******")
	p = 40
	for n in range(2, 50):
		print("miller_rabin(", n, ",", p, ")=", miller_rabin(n, p))


def test_generate_prime():
	print("****** generate_prime ******")
	L = [2, 3, 4, 5, 10, 20, 30, 40, 50, 100, 200, 500, 1000]
	for k in L:
		n = generate_prime(k, 40)
		print("k=", k, ":", miller_rabin(n, 40) and n >= 2 ** (k - 1) and n < 2 ** k)


def test_generate_key():
	print("****** generate_key ******")
	k = 1000
	k2 = k // 2
	p, q, n, phin, d, e = generate_key(k)
	print("p premier:", miller_rabin(p, 80))
	print("q premier:", miller_rabin(q, 80))
	print("p!=q:", p != q)
	print("p et q ont ", k2, " bits:", p < 2 ** k2 and p >= 2 ** (k2 - 1) and q < 2 ** k2 and q >= 2 ** (k2 - 1))
	print("pq == n : ", p * q == n)
	print("n a ", k, " bits:", n < 2 ** k and n >= 2 ** (k - 1))
	print("(p-1)*(q-1) == phin : ", (p - 1) * (q - 1) == phin)
	print("PGCD(e,phin)==1: ", euclid(e, phin) == 1)
	print("ed =1 mod phin", (e * d) % phin == 1)


def test_encipher_decipher():
	print("****** cipher and decipher ******")
	m = 12
	p, q, n, phin, d, e = generate_key(100)
	c = encipher(m, n, e)
	print("chiffrement de ", m, ":", c)
	print("déchiffrement de ", c, ":", decipher(c, n, d))
	print("correction:", m == decipher(c, n, d))


def test_generate_key_wiener():
	print("****** generate_key_wiener ******")
	k = 1000
	k2 = k // 2
	p, q, n, phin, d, e = generate_key(k)
	print("p premier:", miller_rabin(p, 80))
	print("q premier:", miller_rabin(q, 80))
	print("p!=q:", p != q)
	print("p et q ont ", k2, " bits:", p < 2 ** k2 and p >= 2 ** (k2 - 1) and q < 2 ** k2 and q >= 2 ** (k2 - 1))
	print("pq == n : ", p * q == n)
	print("n a ", k, " bits:", n < 2 ** k and n >= 2 ** (k - 1))
	print("(p-1)*(q-1) == phin : ", (p - 1) * (q - 1) == phin)
	print("PGCD(e,phin)==1: ", euclid(e, phin) == 1)
	print("ed =1 mod phin", (e * d) % phin == 1)
	print("d petit?", d ** 4 <= n / 36)


def test_find_secret_key_wiener():
	k = 2048
	n = 16747165677462056268129145673947726240459167554525390427207159395993453000412183817298102860527898142910980701588445020644941145805116775073182765201051830658288067723342446665847168294157719004570163135739276668828351930479547412612594135619543858901369062191314795450495428380522108074218794060535536356592138121107663286013519189114238869709616935920389316831813468517260484298689301155973125504906656085030120148402632309215701203906133026921718504369385331652360593110141946503363972583239132180748669819595559600472615134122497474549146510790007668803843600381198681082882364826755976582516613910936975979013871
	e = 11128373102609799542544441302828906185353756638043397894550913960194075754391596859914258000621295742150055322916626918812199599007226691503109252865552440406874266822913138293576453618640005259030355795466109735043635474571938327025321393788952398379938372959756973855938843546304843025021648701455601779381263630943136784777192178949701863346353125979113684616665675341188420144284801542794261168962580808715631317706540116396413898324366850057883144232844701629915163397237632971224152403270060682881415062296916011400455119942247206772358262213758789471499399657187276847642522521737818722671274821976773800747647
	d = 113012046295998254056212353895685804770209460690814597059625630226095001152430229979116178525589683080297406306375886790863
	print("Nombre de bits:", k)
	print("Nombre de bits de la clé secrète:", int(log(d, 2)) + 1)
	dprime = find_secret_key_wiener(n, e)
	print("small exponent:", dprime)
	print("test égalité:", d == dprime)


################################################
###                                          ###
### Programme principal                      ###
###                                          ###
################################################

if __name__ == "__main__":  # NE PAS SUPPRIMER CETTE LIGNE
	# Votre programme principal ne sera pas evalue.
	# Utilisez-le pour tester votre programme en faisant
	# les appels de votre choix.
	# Respectez bien ce niveau d'indentation.

	print("Debut du programme principal")
# commentez/décommentez les tests
###test_euclid()
###test_extended_euclid()
###test_modular_inverse()
###test_naive_euler_function()
###test_square_and_multiply()
###test_euler_function()
###test_inversibles()
###test_miller_rabin()
###test_generate_prime()
###test_generate_key()
###test_encipher_decipher()
#test_generate_key_wiener()
#test_find_secret_key_wiener()

