1. Opisati proceduru umetanja elementa u niz.
Ako u listi ima još slobodnih lokacija, funkcija pomjera sve elemente od tekuće pozicije do kraja
liste za jedno mjesto udesno, a zatim tekućoj poziciji dodjeljuje novi element x.
Umetanje – sa određene pozicije moraju se pomjeriti svi elementi u nizu
Veličina liste se povećava za 1, ako se operacija uspješno obavi vraća true, a ako ne vraća false
Ako se nalazi na kraju izvodi se u vremenu O(1)
Ako se nalazi na početku izvodi se u vremenu O(n) – treba pomjeriti sve elemente udesno
U prosječnom slučaju za n/2 traje O(n)

UMETNI (L, x)
if (velicina[L] < kapacitet[L]) then
for i in velicina[L] downto tekuci [L] +1 do
	L[i] < L[ i – 1]
end_for 
L[tekuci[L]] < x
velicina[L] < velicina[L] + 1
return true
else
return false
end_if


2. Opisati koristi steka u evaluaciji postfiksnih izraza na primjeru postfiksne notacije izraza
(5+30*(8-6)+(45+60)/3).
Ovaj gore primjer, predstavlja primjer izraza sa potpunim zagrada. U aritmetičkim izrazima sa
potpunim zagradama, redoslijed izvršavanja operatora prema opadujućem nivou ugnježdavanja.
Prvo se izvršavaju operatori sa najvećim nivom, pa onda manjim i na kraju sa nivoem 1.
U gornjem primjeru prvo ce se izvrsiti nivo 3 podizraz a to su: (8-6) i (45+60).
Ako su istog nivoa dva podizraza izvrasavanje se vrsi sa lijeva ka desnoj strani.
Ide se na sljedeci a to je: (8-6) + (45+60)
Sljedeci je: 5+30
Pa onda: 5+30 * (8-6) + (45+60)
I na kraju : (5+30*(8-6)+(45+60)/3)


3. Na koji nacin se moze implementirati stek, uz pomoc povezanih listi (dati pseudokod)
Problem efikasnijeg korištenja memorijskih resursa kod implementacije steka se može riješiti
implementacijom steka pomoću povezanih listi

Operacija umetanja novog elementa na stek pomoću liste:
	
STAVI-NA-STEK (S, x) - U prvom koraku se alocira prostor za novi čvor, a zatim se u
informacioni dio upisuje novi element x. Na kraju se novi čvor povezuje sa prethodnim
čelom liste, dok se pokazivač vrh ažurira tako da pokazuje na novi čvor

STAVI-NA-STEK(S,x)
p🡨GETNODE()
info(p) 🡨 x
sljedeci(p) 🡨 vrh[S]
vrh[S] 🡨 p
									 
Operacija skidanja elementa na steka:
SKINI-SA-STEKA (S) - Ako pokazivač vrh ima vrijednost NIL, signalizira se da je stek prazan.
U suprotnom, u privremeni objekat x se upisuje informacioni sadržaj elementa na čelu liste, te
se u privremenom pokazivaču p čuva adresa trenutnog čela liste. Nakon toga se ažurira
pokazivač vrh, tako da pokazuje na sljedbenika čvora na čelu, čime se u logičkom smislu
element sa vrha steka izbacuje iz liste. Na kraju je potrebno taj čvor i fizički ukloniti, te vratiti
informacioni sadržaj skinutog elementa.
									 
SKINI-SA-STEKA(S)
if(vrh[S] = NIL) then
ERROR (“Stek je prazan!”) 
end_if
x <-- info(vrh[S])
p <-- vrh[S]
vrh [S] <-- sljedeci(vrh[S])
FREENODE (p)
return x


4. Opisati notacije procjene slozenosti algoritma I na koji nacin funckioniraju Big O, Theta,
Omega.
									 
NOTACIJA BIG-O
Notacija za klasifikaciju algoritma koja se odnosi na stepen rasta vremenske složenosti
Za funkciju f(n) kažemo da je O(g(n)), ako postoje pozitivne konstante c i n0 tako
da je ispunjeno:
f n <= cg n , ∀ n >= n0
Ovim se definira da je cg(n) veća od f(n) za sve vrijednosti od n >= n0. Ustvari sa big-O notacijom se
definiše gornja granica složenosti algoritma, jer je funkcija f(n) s obzirom na (*) asimptotski ograničena
sa g(n)
Može se sa sigurnošću tvrditi da f(n) nema veći red veličine rasta nego g(n). Može
postojati beskonačno puno funkcija g(n) za datu funkciju f(n).
									 
NOTACIJA BIG-OMEGA
Izražavanjem vremenske složenosti dobija se uvid u ponašanje algoritma prije svega za velike
vrijednosti n
Ponekad je podesno koristiti i donju granicu složenosti algoritma što se označava sa big-OMEGA
Za funkciju f(n) kažemo da je OMEGA(g(n)), ako postoje pozitivne konstante c i n0 tako da je ispunjeno:
f n >= cg n , n >= n0
									 
NOTACIJA BIG-THETA
Ponekad je podesno koristiti i gornju i donju granicu složenosti algoritma što se označava sa
big-THETA
Na ovaj način se asimptotski određuju granice performansi i sa gornje i sa donje strane
Za funkciju f(n) kažemo da je THETA(g(n)), ako postoje pozitivne konstante c1, c2 i n0 tako da je
ispunjeno:
c1g n <= f n <= c2g n , n >= n0
									 
Može se zaključiti da je f(n) = O-(g(n)) ako je ujedno, f(n) = O(g(n)) if(n)= OMEGA(g(n))


5. Opisati procedure umetanja sa steka uz obrazlozenje funkcije STAVI-NA-STEK, uz pomoc povezanih listi.
STAVI-NA-STEK (S, x) - U prvom koraku se alocira prostor za novi čvor, a zatim se u informacioni dio upisuje novi element x. Na kraju se novi čvor povezuje sa prethodnim čelom liste, dok se pokazivač vrh ažurira tako da pokazuje na novi čvor.

STAVI-NA-STEK(S,x)
p🡨GETNODE()
info(p) <-- x
sljedeci(p) <--vrh[S]
vrh[S]<--p


6. Opisati procedure (uz prikladne slike) umetanja elemenata u red sa cirkularnim nizom.
Primjer umetanja elemenata u red sa cirkularnim nizom.
U ovom primjeru, red u početnom stanju sadrži 4 elementa, od pozicije pocetak=2 do pozicije kraj=5
(slika a).
U red se pozivom procedure STAVI-U-RED (Q, 5) umeće novi element 5. Oznaka kraj se povećava za 1 i
poprima vrijednost kraj=6, te se na tu lokaciju upisuje novi element. U ovoj situaciji vrijedi kraj>pocetak


JE-LI-PUN (Q)
if (pocetak[Q] = (kraj[Q] + 1) mod duzina[Q]) then
	return true
else 
	return false
end_if

Operacija umetanja novog elementa x u red Q je opisana funkcijom STAVI-U-RED. 
Prvo se pozivom funkcije JE-LI-PUN(Q) provjerava da li je red Q pun.
Ako je red pun, novi element se ne može umetnuti, te se signalizira prekoračenje kapaciteta reda.
Nadalje, ako red nije pun, povećava se pokazivač kraj za 1, tako da pokazuje na prvu sljedeću slobodnu lokaciju u nizu, te se na tu lokaciju upisuje novi element x.
Na kraju, procedura STAVI-U-RED još provjerava da li se umetanje obavlja u prazan red, jer se u toj situaciji treba, pored oznake kraj, ažurirati i oznaka pocetak.
Naime, ako je red bio prazan (pocetak=-1), onda se postavlja i oznaka čela reda pocetak navrijednost 0.


STAVI-U-RED (Q,x)
If(JE-LI-PUN(Q)) then
	ERROR (“Red je pun”)
else
	kraj[Q] <-- (kraj[Q]+1 mod duzina[Q]
Q[kraj[Q]] <-- x
if ( pocetak[Q] = -1) then
pocetak [Q] <-- 0
end_if
end_if


7. Opisati dvodimenzionalne nizove
Dvodimenzionalni logički niz treba prevesti u jednodimenzionalni niz na fizičkim lokacijama, odnosno provesti linearizaciju 
Niz X[l1...u1, l2...u2] treba prevesti na način da se dobije jednostavno izračunavanje npr. adrese Ai,j za element X[i, j] 
Alokacija po redovima - Provodi se na način da se prvo smješta prvi red, zatim drugi red sve do reda m-1.
Ako se koristi raspon i=l1,...u1 i j=l2,...u2, adresna funkcija za element X[i, j] ima oblik Ai,j = Al1,l2 +(( i − l1) ∙ n + j − l2) ∙ s l1 ≤ i ≤ u1 i l2 ≤ j ≤ u2 gdje je Al1,l2 adresa prvog elementa, m broj redova u1-l1+1, n broj kolona u2-l2+1 i s memorijska veličina jednog elementa 
Alokacija po kolonama - Provodi se na način da se prvo smješta prva kolona, zatim druga kolona sve do reda n-1.
Ako se koristi raspon i=l1,...u1 i j=l2,...u2, adresna funkcija za element X[i, j] ima oblik Ai,j = A0,0 + (j ∙ m + i) ∙ s i = 0, 1, ... , m − 1 i j = 0, 1, ... , n − 1 gdje je Al1,l2 adresa prvog elementa, m broj redova u1-l1+1, n broj kolona u2-l2+1 i s memorijska veličina jednog elementao

		     
8. Opisati procedure brisanja elemenata iz niza.
Operacija brisanja elementa iz liste
Ako je indeks tekuće pozicije pozicioniran tako da je desna particija prazna, funkcija signalizira grešku.
U suprotnom, element na tekućoj poziciji se pamti u privremenom objektu x, te se svi elementi od
tekuće pozicije do kraja liste pomjeraju za jedno mjesto ulijevo.
Na kraju se atribut velicina umanjuje za 1, te funkcija vraća element koji se izbacuje. Najbolji slučaj pri
izbacivanju je izbacivanje zadnjeg elementa, u kojoj nema pomjeranja elemenata, pa se operacija izvodi u
konstantnom vremenu O(1).
Najgori slučaj se pojavljuje kada se izbacuje prvi element
		   
IZBACI (L)
if(tekuci[L] > velicina [L]) then
	ERROR (“Nista za izbaciti”)
end_if
x <-- L[tekuci]
for i <-- tekuci[L] to velicina [L] -1 do
	L[i] <-- L[i+1]
end_for
velicina[L] <-- velicina [L] -1 
return x

Npr funkcija IZBACI(L) početnu konfiguraciju liste (15,27 l 8, 43, 29), mijenja u (15,27,43,29)
