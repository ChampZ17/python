IMPLEMENTACIJA GOMILE POMOĆU NIZA
---------------------------------
Na početku razmotrimo kako se binarno stablo može prikazati pomoću niza. čvorovi stabla su numerirani, tako da je korijenu pridružena vrijednost 0, a ostale vrijednosti (1, 2, 3, itd.) su pridružene čvorovima, tako da se poštuje poredak čvorova po nivoima, kao i poredak koji se dobiva kretanjem od lijeve prema desnoj strani na svakom nivou. Ako koristimo broj čvora kao indeks niza, onda nam ovaj pristup može dati redoslijed po kojem pohranjujemo čvorove stabla u niz. Stablo se može lako rekonstruirati iz niza na sljedeći način: Lijevo dijete čvora numeriranog kao k ima indeks 2k+1. Na primjer, lijevo dijete čvora numeriranog kao 5 ima indeks 11. Desno dijete čvora numeriranog kao k ima indeks 2k+2. Na primjer, desno dijete čvora numeriranog kao 3 ima indeks 8 Prema tome, korijen je smješten na poziciju 0, dvoje djece korijena je smješteno na pozicijama 1 i 2. Nadalje, djeca čvora 1 su smještena na pozicijama 3 i 4, djeca čvora 2 su smještena na pozicijama 5 i 6, itd

--------------------
POPRAVI GOMILU
---------------------
Za proces izgradnje gomile jedna od ključnih procedura predstavlja postupak spuštanja nekog izabranog čvora u gomili, s ciljem pronalaženja njegove prihvatljive pozicije da bi se održalo potrebno svojstvo poretka. Taj postupak je opisan procedurom POPRAVI-DOLJE. Ulaz u proceduru su niz A i indeks i. Prije poziva procedure pretpostavljamo da su lijevo i desno podstablo čvora i gomile, a nakon izvođenja procedure podstablo koje ima korijen smješten na poziciji s indeksom i također postaje gomila. Postupak spuštanja čvora se izvršava u petlji while, tako da u pojedinim iteracijama varijabla veci poprima vrijednost indeksa većeg djeteta čvora i. Ako je element A[i] veći od svoje djece, što se utvrđuje njegovim poređenjem sa većim djetetom A[veci], tada se procedura prekida, jer ostatak stabla sigurno ima svojstvo poretka (linije 7-9). U suprotnom, elementi niza A sa indeksima i i veci izmjenjuju pozicije, te indeks i poprima vrijednost većeg djeteta veci (linije 10-11). 

1. while(jeLiLista(A,i)!=true)do
2. veci<--lijevo-dijete(i)
3. dd<--desno-dijete(i)
4. if(dd<velicina[A]and A[dd]>A[veci] then
5. veci<--dd
6. end_if
7. if(A[i]>A[veci]then
8. return
9. end_if
10. A[i]<-->A[veci]
11. i<--veci
12. end_while
      
-----------------------------------------------------------------------------------------------------------------------
OPISATI REKURZIVNU PROCEDURU ZA ODREĐIVANJE PERMUTACIJA SKUPA OD N ELEMENATA (MOŽE SE UZETI PRIMJER SKUPA A[0,3]
----------------------------------------------------------------------------------------------------------------------
Ako se u funkciji nalazi više od jednog poziva rekurzivne funkcije, onda takve funkcije nazivamo eksponencijalne rekurzivne funkcije. Kod ovakvih funkcija broj rekurzivnih poziva raste eksponencijalno. Eksponencijalnu rekurziju ćemo ilustrirati rješavanjem relativno čestog problema pronalaženja permutacija nekog skupa. Permutacije skupa od n elemenata su mogući uređeni razmještaji elemenata ili mogući uređeni izbori elemenata iz tog skupa. Broj permutacija skupa od n elemenata je n!. Pođimo od jednog konkretnog primjera. Pretpostavimo da je zadat skup koji je prikazan u obliku cjelobrojnog niza A[0..3]={1, 2, 3, 4}. Neka je potrebno pronaći sve permutacije elemenata tog skupa. Označimo početni problem sa P0, a skup svih permutacija koji predstavlja njegovo rješenje sa S0. Na slici 7.6 je ilustriran jedan od mogućih pristupa rješavanju problema P0. Skup S0 možemo podijeliti na četiri disjunktna podskupa Si (i=0, 1, 2, 3). Svaki od podskupova Si je kreiran tako da se na prvoj poziciji nalazi element A[i], a na ostalim pozicijama j (j≠i) se nalaze permutacije preostala 3 elementa. Na primjer, skup S1 sadrži sve permutacije koje na prvoj poziciji sadrže element A[1]=2, dok skup S3 označava sve permutacije koje na prvoj poziciji sadrže element A[3]=4. Nadalje, u skupu S1 sve permutacije na preostale tri pozicije zapravo sadrže permutacije podskupa {1, 3, 4}, dok u skupu S3 sve permutacije na preostale tri pozicije sadrže permutacije podskupa {1, 2, 3}.

----------------------------------------------------------------------------------
OPISATI REKURZIVNU FUNKCIJU IZBOR (n,k) ZA ODREĐIVANJE K ELEMENATA IZ SKUPA N
------------------------------------------------------------------------------
Rekurzivne funkcije ponekada sadrže više od jednog rekurzivnog poziva. Ako se izvršavanjem funkcije ostvaruju dva rekurzivna poziva, onda takve funkcije nazivamo binarne rekurzivne funkcije. Primjer binarne rekurzije možemo ilustrirati, na primjer, određivanjem podskupova sa k elemenata (k kombinacija) iz skupa sa n elemenata. Broj takvih kombinacija je:
(n,k)=(n!)/(k!(n-k)!

Izbor po tri elementa iz skupa A daje sljedeće moguće kombinacije: {0, 1, 2},{0, 1, 3},{0, 1, 4},{0, 2, 3},{0, 2, 4},{0, 3, 4},{1, 2, 3},{1, 2, 4},{1, 3, 4},{2, 3, 4}

IZBOR (n, k)
1 if (k = 0 or n = k) then
2 return 1
3 else
4 return IZBOR (n-1, k)+IZBOR (n-1, k-1)
5 end_if
            
-----------------------------------------------
OBJASNITI OPERACIJU UMETANJA U AVL STABLO
------------------------------------------
Umetanje novih čvorova kod AVL stabla je vrlo slično kao i umetanje novih čvorova u obično binarno stablo pretraživanja. Razlika je u tome što se kod AVL stabla nakon svakog dodavanja treba provjeriti da li je narušena balansiranost stabla. Čvorovi kod kojih može doći do narušavanja uvjeta balansiranosti su oni koji se nalaze na putu od korijena do umetnutog čvora. Ove čvorove treba ispitivati odozdo prema gore. Da bismo vidjeli i razmotrili moguće slučajeve, poslužit ćemo se jednim konkretnim primjerom kreiranja AVL stabla. Počinjemo sa umetanjem čvora 20 u korijen (slika 9.17a). Budući da ovaj čvor nema djecu, njegov balans je 0, te stablo koje trenutno ima samo jedan čvor zadovoljava uvjete AVL stabla. Sada dodajemo sljedeći čvor 30, što je prikazano na slici 9.17b. Čvor 30 ima balans 0, a čvor 20 sada ima balans -1. Sljedeći čvor kojeg dodajemo je čvor 40 (slika 9.17c). Počevši od tog čvora, izračunavamo balans čvorova na putu prema korijenu. Pošto je čvor 40 terminalni čvor, njegov balans je 0. Čvor 30 ima balans -1, što ne narušava uvjete AVL stabla. Međutim, čvor 20, koji ima balans -2, je čvor koji narušava uvjete AVL stabla, pa je potrebno preurediti stablo na način da se obnovi balansiranost stabla. Operacija kojom se obnavlja balansiranost stabla se naziva rotacija. Postoje dva tipa rotacije kod AVL stabala: jednostruka i dvostruka rotacija. Da bismo odlučili koju rotaciju treba primijeniti koriste se sljedeća pravila:
1. Krećemo od novog dodanog čvora u stablo, slijedeći put umetanja prema korijenu i provjeravamo balans čvorova na tom putu. Kada pronađemo kritični čvor kod kojeg je narušen balans, potrebno je utvrditi da li kritični čvor i njegovo dijete na putu umetanja naginju na istu stranu. 
2. Ako kritični čvor i njegovo dijete na putu umetanja naginju na istu stranu, za obnavljanje balansiranosti stabla je potrebno primijeniti jednostruku rotaciju. Lijeva rotacija se primjenjuje ako čvorovi naginju na desnu stranu, dok se desna rotacija primjenjuje ako čvorovi naginju na lijevu stranu. 3. Ako kritični čvor i njegovo dijete na putu umetanja naginju na različite strane, za obnavljanje balansiranosti je potrebno primijeniti dvostruku rotaciju.

-------------------------------------------------------------------------------
OBJASNITI PROCEDURU UMETANJA ČVOROVA U BINARNO STABLO (REKURZIVNI PSUEDOKOD)
----------------------------------------------------------------------------
Pretpostavimo da imamo sljedeću listu brojeva: 15, 18, 8, 21, 3, 19, 13, 24 i 10. Ovu listu brojeva ćemo ubaciti u binarno stablo pretraživanja, pri tome koristeći neki privremeni tekući pokazivač koji inicijalno pokazuje na korijen tog stabla, na sljedeći način: 
Ako je tekući pokazivač 0, treba kreirati novi čvor u koji se upisuje informacioni sadržaj, te treba vratiti adresu novog čvora. 
Inače, treba izvršiti usporedbu nove vrijednosti i čvora pohranjenog u tekućem čvoru. Ako je nova vrijednost manja od vrijednosti u tekućem čvoru, onda se ona treba umetnuti u lijevo podstablo trenutnog čvora rekurzivnom primjenom istog algoritma. U suprotnom, nova vrijednost se umeće u desno podstablo trenutnog čvora.
Opisani postupak umetanja novog čvora je opisan rekurzivnom procedurom UMETNI-BST-R. Ova procedura umeće novi čvor sa adresom z u stablo sa korijenom na kojeg pokazuje pokazivač korijen.

UMETNI-BST-R (korijen, z)
1 p = korijen
2 if (p == NIL) then
3 korijen = z
4 else
5 if (z.kljuc < p.kljuc) then
6 UMETNI-BST-R (p.lijevi, z)
7 else
8 UMETNI-BST-R (p.desni, z)
9 end_if
10 end_if
            
------------
KULE HANOJ
-----------
PSUEDOKOD
HANOJSKI-TORNJEVI (n, S, D, T)
1 if (n = 1) then
2 PRINT(„Preseliti disk 1 sa štapa S na štap D“)
3 return
4 end_if
5 HANOJSKI-TORNJEVI (n-1, S, T, D)
6 PRINT („Preseliti disk n sa štapa S na štap D“)
7 HANOJSKI-TORNJEVI (n-1, T, D, S)
8 return

void towerOfHanoi(int n, char from_rod,
                    char to_rod, char aux_rod) 
{ 
    if (n == 1) 
    { 
        cout << "Move disk 1 from rod " << from_rod << 
                            " to rod " << to_rod<<endl; 
        return; 
    } 
    towerOfHanoi(n - 1, from_rod, aux_rod, to_rod); 
    cout << "Move disk " << n << " from rod " << from_rod <<
                                " to rod " << to_rod << endl; 
    towerOfHanoi(n - 1, aux_rod, to_rod, from_rod); 
} 
 
// Driver code
int main() 
{ 
    int n = 4; // Number of disks 
    towerOfHanoi(n, 'A', 'C', 'B'); // A, B and C are names of rods 
    return 0; 
} 

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
ALGORITMI SORTIRANJA
--------------------------------------------------------------------------------------
Problem sortiranja neuređene kolekcije ključeva u uređenu, jedan je od najčešćih u informatici i mnogo se zna o efikasnosti različitih rješenja, kao i o ograničenjima u najboljim mogućim rješenjima. Na primjer, ako neki algoritam koristi poređenje između ključeva za odlučivanje o njihovom uređenju, onda on ne može, u prosjeku, sortirati niz od n ključeva za vrijeme proporcionalno manje od nlogn. Veličina nlogn je donja granica za sortiranja bazirana na poređenju. Postoje i O(n) algoritmi za sortiranje koji se oslanjaju na takozvane tehnike adresnih kalkulacija (address-calculation techniques). 
Ponekad tehnika sortiranja koja odlično radi u glavnoj memoriji, nije tako efikasna za sortiranje velikih fajlova koji se nalaze na spoljnim memorijskim medijumima. Takođe, QuickSort može sortirati n ključeva, u prosjeku, dva puta brže od uporedne O(nlogn) tehnike, kao što je HeapSort, iako se vrijeme sortiranja za QuickSort ponaša kao O(n2 ), a za HeapSort kao O(nlogn). 
Upoznavanje sa karakteristikama različitih metoda sortiranja može biti od izuzetne važnosti, jer na taj način možete lakše odabrati tehniku sortiranja koja najviše odgovara posebnostima problema koji rješavate. Metode sortiranja se grupišu u različite klase koje sadrže slične teme. Jedan način za njihovo organizovanje (mada ne i jedini mogući) je prikazan na slici.

--------------
BUBBLE SORT
--------------
Bubble sort je jedan od prvih unapređenih algoritama za sortiranje, ali se i dalje smatra veoma sporim jer radi u vremenu O(n2 ). Ime algoritma potiče od ideje da tokom postepenog sortiranja elementi niza kao mehurići „isplivaju“ na pravo mjesto. 
U ovom algoritmu se sukcesivno porede susjedni elementi niza, i vrše se zamjene mjesta ukoliko je to potrebno. Poboljšanje u odnosu na originalni algoritam donosi promjenjiva koja označava je li bilo zamjene (zamjena) pomoću koje se prekida sa izvršavanjem algoritma ukoliko u prethodnoj iteraciji nije bilo nijezne zamjene mjesta. Dodatno poboljšanje je uvođenje promjenjive j, pomoću koje se svaki put opseg koji se sortira smanjuje za 1.

------------------------
INSERTION SORT O(n^2)
------------------------
Insertion sort spada u „umetni i održi sortiranim“ algoritme i radi u vremenu O(n2 ). U praksi se često koristi za sortiranje malih nizova. U ovom algoritmu se niz dijeli na dva zamišljena podniza: sortirani i nesortirani. U svakom koraku, novi ključ K koji treba umetnuti, se odvaja od lijevog kraja nesortiranog podniza i ubacuje u sortirani podniz na odgovarajuću poziciju:
1.	ključ K se uklanja sa lijevog kraja nesortiranog podniza, na taj način praveći rupu 
2.	svi ključevi u sortiranom podnizu koji su veći od K se pomjeraju za jedno mjesto u desno 
3.	K se umeće u preostalu „rupu“ u sortiranom podnizu. 
Proces se ponavlja dok se svi ključevi iz U ne umetnu u S, a u tom trenutku S predstavlja cijeli niz A. U početku se smatra da sortirani podniz sadrži prvi element niza, a nesortirani sve ostale.

--------------------------
SELECTION SORT O(n^2)
--------------------------
Selection sort je jedan od algoritama koji za sortiranje koriste prioritetni red. U ovom slučaju, reprezentacija prioritetnog reda je nesortirani niz. Algoritam je veoma jednostavan, a u pojedinim situacijama može biti i veoma efikasan. 
Ideja je sljedeća: niz koji se treba sortirati se podjeli na dva zamišljena podniza: sortirani i nesortirani; inicijalno, sortirani podniz je prazan, a nesortirani sadrži čitav niz. U svakom koraku algoritam određuje najmanji (ili najveći) element u nesortiranom podnizu i dodaje ga na kraj sortiranog podniza, sve dok nesortirani podniz ne postane prazan, odnosno, dok se ne sortira čitav niz.

--------------
MERGE SORT
---------------
Apstraktni prikaz strategije algoritma MergeSort dat je u narednoj programskoj strategiji.
void MergeSort(SortingArray A, int m, int n) { 
/* treba sortirati podniz A[m:n] niza A u rastući poredak */ 
(deklarisati pomoćni brojač Srednji) 
if (postoji više od jednog elementa koje treba sortirati u A[m:n], m<n) { 
(podijeliti A[m:n] na polovine, LijeviNiz i DesniNiz, Srednji=(m+n)/2) (sortirati LijeviNiz pozivom funkcije MergeSort(A,m,Srednji)) (sortirati DesniNiz pozivom funkcije MergeSort(A,Srednji+1,n)) (spojiti LijeviNiz i DesniNiz da bi se dobio rezultat) 
}}
Osnova MergeSort algoritma je funkcija Merge kojom se dva sortirana niza spajaju u jedan sortirani niz. 
Algoritam MergeSort spada u brže algoritme jer radi u vremenu O(nlog2n), ali ima koristi pomoćni niz kojij je iste veličine kao i originalni niz. Ipak, MergeSort spada u stabilne algoritme (algoritme koji se uvijek ponašaju na isti/sličan način, što se može povezati sa razgranatošću stabla poziva rekurzivne funkcije), ali se njegova upotreba ne preporučuje za male nizove. Na slici je ilustrovana ideja.
Postoje razne implementacije koda za algoritam MergeSort u raznim programskim jezicima1 . No, osnovna ideja i rekurzivna funkcija su srž svake imaplementacije, iako je moguće implementirati ne-rekurzivni algoritam. Poboljšanja MergeSort algoritma se odnose na: 
1.	Smanjivanje broja poziva provjerom uslova da je najveći element u lijevom podnizu manji od najmanjeg u desnom (u tom slučaju se podnizovi mogu direktno spojiti) 
2.	Izbjeći korištenje dodatnog niza (ovo poboljšanje je moguće, ali je komplikaovano).
 
-------------
QUICK SORT
-------------
Quick sort spada u podjeli-i-osvoji (divide et impera, divide-and-conquer) algoritme, u prosječnom slučaju radi u vremenu O(nlogn) i zbog toga se veoma često koristi u praksi. 
Proces kojim se sortira niz je sljedeći: prvo, bira se element niza kao vodeći (pivot) element. Pivot se koristi za razdvajanje svih elemenata niza u dvije particije: 
1.	ijeva particija sadrži elemente manje ili jednake pivotu, a 
2.	desna particija sadrži elemente veće ili jednake pivotu. 
Dalje se QuickSort rekurzivno poziva za sortiranje lijeve i desne particije. Kada se proces završi, nisu potrebna nikakva druga preuređenja niza, jer je origanalni niz, koji sadrži dvije sortirane particije, lijevu i desnu, sortiran u rastućem poretku.

PARTICIJA(A, prvi, zadnji)
pivot <-- A[prvi]
p<--prvi+1
while(p<=zadnji and A[p]<pivot)do
	p<--p+1
End while
for(i <--p+1 to zadnji ) do
	if(A[i] < pivot) then
		A[i] <--> A[p]
		p<--p+1
	Endif
Endfor
A[prvi]<-->A[p-1]
Return p-1

QUICK-SORT(A, prvi, zadnji)
if(prvi < zadnji)then
	j<-PARTICIJA(A, prvi, zadnji)
	QUICKSORT(A, prvi, j-1)
	QUICKSORT(A, j+1, zadnji)
endif

---------------------------------
BINARNO STABLO PRETRAŽIVANJE
---------------------------------
Pomoću binarnog stabla za pretraživanje se često uspješno mogu predstavljati ATP liste ili tabele. Ako kombinacija operacija zahtjeva i umetanje i brisanje i pretraživanje, onda AVL stablo može pružiti bolje pogodnosti nego povezana ili sekvencijalna reprezentacija. Dodavanje ekstra polja svakom čvoru AVL stabla (u koje smjestimo broj čvorova u lijevom podstablu plus 1) se može iskoristiti kao osnova za rapidni slučajni pristup datom čvoru i za računanje ukupnog broja čvorova u stablu (što služi za računanje dužine ATP liste). 
Binarno stablo za pretraživanje ima svojstvo da za proizvoljni čvor N sa ključem K važi da su ključevi u lijevom podstablu čvora N manji od K, a u desnom podstablu čvora N veći od K. Važi i pretpostavka da se ključevi mogu porediti (da za svaka dva ključa K1 i K2 važi tačno jedna od relacija K1 < K2, K1 == K2 ili K1 > K2), pa ključ može biti i numerička i znakovna promjenljiva. 
Novi čvor N sa ključem K se umeće na odgovarajuću poziciju, tako da važi da su ključevi u lijevom podstablu čvora N manji od K, a u desnom veći. Novo stablo se formira od praznog stabla tako što se prvi čvor umetne u korjen, a dalje se prati pravilo. Za pronalaženje ključa K u binarnom stablu za pretragu, T, prvo poredimo K sa ključem korjena, Kr. Ukoliko je K==Kr, naša potraga je završena. Ukoliko je K<Kr, pretraga se nastavlja u lijevom , a ukoliko je K>Kr, pretraga se nastavlja u desnom podstablu stabla T. Ukoliko je stablo T prazno, pretraga nije uspjela.
 Na primjer, u potrazi za ključem ORD u binarnom stablu sa Slike 1, poredimo ključ ORD sa ključem ORY u korjenu. Kako je ORD<ORY, potragu nastavljamo u lijevom podstablu. Zatim se ORD poredi sa JFK i kako je ORD>JFK, dalje pretražujemo desno podstablo. Pošto je ORD>MEX opet krećemo desno. Na kraju imamo ORD=ORD i pretraga je uspješno okončana. Ako u istom stablu potražimo kod DCA poređenjima DCA<ORY, DCA>JFK, DCA>BRU i DCA<DUS, dolazimo do praznog podstabla čvora sa ključem DUS, što znači da pretraga nije uspjela, to jest da u stablu nema čvora sa ključem DCA. 
Ako sada u dato stablo želimo da umetnemo čvor sa ključem DCA, treba ga umetnuti kao lijevo podstablo čvora sa ključem DUS.

--------------
STABLO
--------------
Stablo (tree) je jedna od najznačajnijih struktura podataka u informatici. Stablo obezbjeđuju prirodnu reprezentaciju za razne vrste podataka koji se javljaju u aplikacijama, a korisno je i za rješavanje mnogih algoritamskih problema. Ponekad je stablo statična (ne mjenja oblik u toku izvršavanja programa po datom algoritmu). U drugim slučajevima stablo je dinamično (mjenjaju oblik u toku algoritma). Oblik stabla se može mijenjati umetanjem ili uklanjanjem čvora. Postoje i lokalne operacije za mjenjanje oblika stabla, bez umetanja ili uklanjanja. 
Oblik se može mjenjati i kombinovanjem dva stabla. Još jedna vrsta dinamičkog stabla je stablo koje se generira tokom rješavanja problema. Na primjer u stablu igre (game tree) su predstavljeni svi mogući potezi igrača u svakoj fazi igre. Dati čvor predstavlja specifičnu situaciju, a grane moguće poteze koje igrač može da napravi u toj situaciji. Stablo za pretragu (search tree) se koristi prilikom potrage za ranije uskladištenim informacijama; često se vezuje sa ključevima za pretragu (search keys). Svaki čvor u ovakvom stablu može predstavljati test za ključ za pretragu koji se koristi.
 Rezultat testa može odrediti koju granu stabla slijediti da bi se suzila pretraga. Stablo za pretragu se uspješno može koristiti i kod velikih fajlova i za baze podataka. Stablo se može koristiti i za kreiranje veoma efikasnih reprezentacija različitih algoritamskih rješenja. Na primjer, red za čekanje se može predstaviti specijalnim binarnim stablom. Stablo se može predstaviti i pomoću povezane i pomoću sekvencijalne reprezentacije. Efikasnost reprezentacija varira od slučaja do slučaja.

OSNOVNI KONCEPTI I TERMINOLOGIJA
Dijagram stabla je formiran od čvorova (node) povezanih linijama. Linije se nazivaju ivice ili grane (edge ili branch).

Na primjer, za stablo kažemo: 
1.	R je korjen stabla (korjeni čvor), ili najgornji čvor, 
2.	kada se krećemo naniže od R, dolazimo do R-ove djece, do čvorova S (lijevo djete) i T (desno djete), (V je srednje djete čvora T), 
3.	kada se krećemo naviše, kažemo da je R roditelj čvora S, 
4.	potomci čvora su čvorovi do kojih se dolazi putovanjem naniže, bilo kojom putanjom, 
5.	preci čvora su čvorovi do kojih se dolazi putovanjem naviše, 
6.	listovi stabla su čvorovi koji nemaju djece, 
7.	ako čvor ima djece zove se unutarnji čvor (internal node). 
Čvorove stabla možemo organizirati i u numerisane nivoe. Korjeni čvor je nulti nivo. Prvom nivou pripadaju sva djeca korjenog čvora. Drugi nivo sačinjavaju sva djeca svih čvorova prvog nivoa (ili svi unuci korjenog čvora) i tako redom. Uopšteno govoreći, do proizvoljnog čvora, N, se može stići putovanjem naniže od korjenog čvora, putanjom p. Ako je putanja p sačinjena od n ivica, onda kažemo da čvor N pripada n-tom nivou i da je dužina putanje p jednaka n. U stablu postoji tačno jedna putanja od korjena do proizvoljnog nasljednika, N (ukoliko ima više od jedne putanje, onda se ne radi o stablu). Geometrijski gledano, u informatici je praksa da se stablo crta naopačke, sa korjenom na vrhu, jer se u procesiranju algoritama obično kreće od korjenog čvora. U nekim je situacijama korisno definisati i koristiti prazno stablo – stablo u kojem nema ni čvorova ni ivica.

------------------------------------------------  
PERFORMANSE BINARNOG STABLA ZA PRETRAŽIVANJE
------------------------------------------------
Binarna stabla za pretraživanje su djelimično interesantna i zbog značajnih performansi. Ispostavlja se da se, ukoliko je stablo balansirano, pretraga obavlja u logaritamskom vremenu, O(logn); kada je stablo dugačko i nerazgranato, pretraga se obavlja u linearnom vremenu, O(n). 
Ovdje ćemo navesti formule za broj poređenja potrebnih za lociranje ključeva u najboljem, najgorem i prosječnom slučaju. 
Ako se dati ključ K nalazi na nivou l, onda je broj poređenja 2*l+1. Može vam se učiniti da je broj potrebnih poređenja l+1, ali algoritam za pretraživanje binarnog stabla uvijek prvo testira je li ključ K jednak ključu Ki, pa ako nije, onda poredi je li K manje od Ki da ustanovi na koju stranu treba ići da nastavi pretragu. Dakle treba nam 2*l poređenja od korjena do čvora sa ključem K i jedno poređenje za lociranje ključa K na nivou l. 
Za određivanje prosječnog broja poređenja potrebnih za uspješnu potragu za ključem K, je korisno definisati internu dužinu putanje (I) stabla T. Interna dužina putanje stabla T je zbir dužina svih putanja do individualnih čvorova. Na primjer, za stablo sa Slike 1, interna dužina putanje je 28:
I=( 0+1+1+2+2+3+3+3+4+4+5)
Ukoliko je jednako vjerovatna uspješna potraga sa svakim od ključeva Ki, binarnog stabla T sa n čvorova, onda je broj poređenja potrebnih za prosječnu uspješnu pretragu jednak
Cn = (2I+n)/n

 
------------------
BINARNO STABLO
-------------------
Binarno stablo je ono u kojem svaki čvor ima tačno dva djeteta. Dozvoljeno je da jedno ili oba djeteta budu prazni čvorovi. Ukoliko čvor ima dva prazna djeteta, onda je list. Binarno stablo je pogodno definisati rekurzivnom definicijom:
Binarno stablo je ili prazno stablo ili čvor čije su lijevo i desno podstablo binarna stabla.
Kod binarnog stabla svaki čvor uvijek ima i lijevo i desno djete (bez obzira jesu li to prazni čvorovi ili ne). Ponekad se u dijagramu binarnog stabla prazno binarno stablo eksplicitno prikazuje (praznim kvadratićem, kao na Slici 2) i tada kažemo da smo prikazali prošireno binarno stablo.
 
-----------------------------
KOMPLETNO BINARNO STABLO
-----------------------------
Za binarno stablo kažemo da je kompletno ako 
1.	ima listove bilo na jednom nivou, bilo na dva susjedna nivoa i 
2.	ako su listovi na najnižem nivou grupisani lijevo, koliko je god to moguće. 
Na slici su prikazana tri stabla. Prvo je kompletno. Drugo nije jer mu listovi nisu grupisani na lijevoj strani. Treće stablo nije kompletno jer mu listovi nisu na dva susjedna nivoa.
 
--------------------------------------------
KRETANJE (TRAVERSING) PO BINARNOM STABLU
---------------------------------------------
Jedan od primjera binarnog stabla je stablo kojim se predstavlja algebarski izraz sa binarnim operacijama. Na slici je prikazano stablo izraza (b^2-4*a*c)/(2*a). Ovaj izraz je u stablu predstavljen na uobičajeni način, prema prioritetima operacija ^, * i /, + i -, a u odsustvu zagrada, operacije sa istim prioritetom se izvršavaju s lijeva na desno. Ukoliko želimo predstaviti izraz na neki drugi način (prefiks ili postfiks) možemo iskoristiti postojeće stablo, samo se po njemu krećemo drugim redosljedom. Kretanje po binarnom stablu je proces u kome se svaki čvor stabla posjeti tačno jednom, po nekom utvrđenom redosljedu.
 
 
Tri popularna redosljeda kretanja po binarnom stablu su PreOrder, InOrder i PostOrder. Definicije ovih redosljeda kretanja su date u tabeli.
 
Kada pročitamo izraz u stablu sa slike 6.10 po ova tri redosljeda, dobijamo sledeće rezultate:
PreOrder: / - ^ b 2 * * 4 a c * 2 a
InOrder: b ^ 2 – 4 * a * c / 2 * a
PostOrder: b 2 ^ 4 a * c * - 2 a * /

--------------------------------------------------------
KRETANJE BINARNIM STABLOM U POVEZANOJ REPREZENTACIJI
----------------------------------------------------------
Za primjenu algoritama za kretanje po binarnom stablu (traversal) je pogodna povezana reprezentacija binarnog stabla. Prvo ćemo razmotriti povezanu reprezentaciju. Na slici je prikazano stablo izraza (x – y + z), kao i njegova povezana reprezentacija.
 
Ovdje su u LLink i RLink članovima elementa CvorStabla smješteni pokazivači na lijevo i desno podstablo čvora, respektivno. Ukoliko je podstablo prazno, vrijednost odgovarajućeg pokazivača je NULL. 
Upotrebom steka i povezane reprezentacije binarnog stabla se mogu pisati programi za ne-rekurzivne funkcije za kretanje binarnim stablom. U takvim funkcijama se u steku čuvaju pokazivači na podstabla koja čekaju na obilazak. Može se reći da se stek S u ovoj programskoj strategiji koristi za odloženi nalog za obilazak. U procesu PreOrder obilaska stabla, kada dođemo do proizvoljnog čvora N, prvo odštampamo sadržaj tog čvora. Zatim smjestimo prvo desni link čvora N u stek, pa za njim i lijevi. U steku se sada nalaze dva odložena naloga za obilazak, prvo lijevog, pa desnog podstabla čvora N. 
Pretpostavimo da sada želimo izmjeniti tip kontejnera u koji se smještaju odložene obaveze obilaska, da upotrebimo red za čekanje, Q, umjesto steka. Poslije dolaska do čvora N i štampanja njegovog sadržaja, umećemo lijevi i desni link čvora N (baš tim redosljedom) u red za čekanje, Q. Sada se u Q nalaze odložene obaveze za obilazak lijevog i desnog podstabla. Kada uklanjamo pokazivače iz Q i pratimo one nenulte, prvo odštampamo sadržaj čvora na koji ukazuje pokazivač, a zatim umećemo lijevi i desni pokazivač tog čvora na kraj reda za čekanje. Na ovaj način se štampa sadržaj izraza nivo po nivo, počevši od nultog nivoa. Na taj način će stablo sa slike 7, rezultovati niskom: / - * ^ * 2 a b 2 * c 4 a.

------------------
HEŠIRANJE
-------------------
ATP TABLA
Tabela T je apstraktno sredstvo u kome se čuvaju slogovi tabele koji su ili prazni, ili uređeni parovi sa formom (K,I), gdje je K jedinstveni ključ, a I informacija povezana sa K. Različiti slogovi tabele imaju različite ključeve. 
ATP tabela je definisana slijedećim operacijama: 
1.	Iniciranje tabele T da bude prazna tabela. Prazna tabela je ispunjena praznim slogovima (K0,I0), gdje je K0 poseban, prazan ključ, različit od svih ostalih nepraznih ključeva.
2.	Određivanje je li tabela T puna. 
3.	Umetanje novog sloga (K,I) u tabelu T, pod uslovom da T nije puna.
4.	Brisanje sloga (K,I) iz tabele T.
5.	Kada je dat ključ K, pretraživanje tabele u potrazi za K i preuzimanje informacije iz sloga (K,I) tabele T. Ažuriranje sloga (K,I) tabele T, zamjenom sa novim slogom (K,I’), kojim se sa K povezuje nova informacija I’.
6.	Numerisanje slogova (K,I) tabele T u rastućem poretku po ključevima K. 
Jedan primjer apstraktne tabele je naredna tabela, gdje u svakom slogu (K,I), troslovni aerodromski kod predstavlja jedinstveni ključ K, a informacija I objašnjava u kom gradu i državi se nalazi aerodrom sa datim kodom, K.

---------------------
HEŠIRANJE
----------------------
Heširanje (engleski Hashing) je nastalo iz potrebe da se ubrza pretraživanje tabele. Ukoliko niz ima n elemenata, i treba se pronaći određena vrijednost, onda se ili mora pretražiti čitav niz (ukoliko je nesortiran) ili (ukoliko je niz sortiran u na primjer binarno stablo za pretraživanje) može pretražiti samo određena grana. Sortiranjem u stablo se vrijeme u najgorem slučaju smanjuje na logaritamsko (O(logn)). No, ukoliko se zna indeks elementa niza u koji je smješten traženi sadržaj, vrijeme za pretraživanje postaje konstantno (O(1)). Heširanje je u tom smislu proces u kome se ključevima tabele (u opštem slučaju ključevi mogu biti alfanumerički) pridodaju numeričke vrijednosti (na određeni, sistematičan, način) i time omogućava da se ključevi nađu u konstantnom vremenu (ukoliko je metoda povoljno odabrana i ne dođe do velike klasterizacije). Primjer ključa koji se hešira i jednostavno nalazi je bibliotečki broj knjige; ukoliko se hešira i heš vrijednost smjesti u heš tabelu, pretraga za brojem se provodi samo po heš tabeli, a ona obično podrazumjeva mali broj koraka.
UVOD U HEŠIRANJE POMOĆU JEDNOSTAVNIH PRIMJERA 
Za uvođenje osnovnih pojmova hešinga ćemo razmotriti nekoliko jednostavnih primjera. U ovim primjerima ćemo za ključeve koristiti slova engleskog alfabeta indeksirana brojevima (kao A1, B2, C3, R18, Z26), gdje indeks slova označava njegovu poziciju u alfabetu. Tabela T, koju ćemo koristiti je namjerno izabrana da bude mala: T ima mjesta za smještanje samo 7 slogova koji se smještaju u redove tabele T numerirane od 0 do 6. Radi jednostavnosti ćemo pretpostaviti da slog sadrži samo ključ, a ne i informaciju. 
Pošto imamo sedam mjesta u tabeli T, da bi odredili u koji red ćemo smjestiti ključ Ki, podjelićemo vrijednost indeksa i sa 7. Ostatak djeljenja1 i/7 nam određuje u koji red da smjestimo ključ Ki. Tako se ključevi B2, J10 i S19 smještaju u redove 2, 3 i 5 respektivno. Funkcija kojom se određuje lokacija Ln na koju smještamo ključ sa indeksom n je 
h(Ln) = n % 7.
Funkciju h(Ln) zovemo heš funkcija ključa Ln. Dobra heš funkcija, h(Ln) će preslikati ključeve Ln uniformno i slučajno na cijeli raspon mogućih lokacija (0:6) u tabeli T. Sada ćemo pokušati da umetnemo ključeve N14, X24 i W23 u tabelu T. Ključ N14 se može umetnuti direktno u tabelu, na lokaciju h(N14)=0. Kada pokušamo da umetnemo ključ X24 na poziciju h(X24)=3, vidimo da je u red 3 već smješten ključ J10. Ovakva situacija se naziva kolizija, jer dva ključa dolaze u koliziju (treba da se smjeste na istu lokaciju u tabeli) pošto imaju iste heš adrese, h(J10)=h(X24)=3. Potrebno je odrediti na koji način će se razrješavati ovakve situacije. Jednostavan način za rješavanje kolizije je da se u tabeli T potraži prva slobodna niža lokacija i u nju smjesti dati ključ. Na primjer, pošto je h(X24)=3 zauzeta, provjerimo je li slobodna lokacija 2, pa pošto ni ona nije slobodna, provjerimo je li slobodna lokacija 1. Kako je lokacija 1 slobodna, ključ X24 se smješta u prvi red tabele i to iz trećeg pokušaja.
 
Na kraju ćemo umetnuti ključ W23. Prvi pokušaj umetanja W23 na njegovu heš adresu, h(W23)=2, dovodi do kolizije jer je u red 2 već smješten ključ B2. Zato provjeravamo redom lokacije 1 i 0, koje su obe zauzete. Zatim “zaokrenemo” i pokušamo sa poslijednjom lokacijom u tabeli. Kako je lokacija 6 slobodna, smještamo ključ W23 na lokaciju 6 u tabeli T. Lokacije koje ispitujemo prilikom pokušaja umetanja novog ključa u tabelu T se nazivaju probni niz. (Probni niz za ključ W23 je 2,1,0,6,5,4,3.) Probni niz je tako određen da ispituje svaku lokaciju tabele T tačno jednom. Da bi obezbjedili da uvijek pronađemo praznu lokaciju primjenom probnog niza, definiraćemo punu tabelu, T, takvu da T sadrži tačno jedan prazan red. Na ovaj način obezbjeđujemo uspješnu potragu za praznim lokacijama i ne moramo prebrojavati lokacije u probnom nizu da bi obezbjedili kraj pretrage. Ovakav probni niz se naziva linearnim. 

----------------------
OTVORENO ADRESIRANJE
--------------------------

Metod umetanja ključeva u prazne redove tabele se naziva otvoreno adresiranje. Otvreno adresiranje sa linerano probnim nizom ima ozbiljne nedostatke pogoto u slučaju gotovo pune tabele.
Postoje drugi vidovi otvorenog adresiranja koji se ponašaju mnogo bolje od otvorenog adresiranja sa linearnim probnim nizom. Jedan od njih, dvostruko heširanje, koristi nelinearni probni niz tako što se izračunavaju različite probne adrese za različite ključeve. Prikazaćemo dvostruko heširanje na primjeru iste prazne tabele kao i kod linearnog probnog niza. Prvo ćemo definisati funkciju za računanje probnog umanjenja, p(Ln). Za jednostavnu ilustraciju, neka je 
p(Ln) = max(1, n/7).
Počećemo umetanjem ključeva J10, B2, S19 i N14 u praznu tabelu T. Opet koristimo vrijednosti heš funkcije, h(Ln) za određivanje heš lokacije na koju ćemo prvo pokušati da umetnemo ključ. Kako nema kolizije među ovim adresama, ključevi se umeću direktno u redove 3, 2, 5 i 0, respektivno. Zatim pokušavamo da umetnemo ključ X24 na njegovu heš adresu 3. Kako je ova adresa zauzeta, umanjujemo je za 3 i pokušavamo da umetnemo ključ X24 na adresu 0. I ova adresa je zauzeta, pa je ponovo umanjimo za 3 (7-3=4) i pokušamo da umetnemo ključ X24 na adresu 4, koja nije zauzeta i tu se umeće X24.
Konačno, pokušavamo da umetnemo ključ W23 na njegovu heš adresu 2. Pošto je adresa 2 zauzeta, umanjimo je za 3, (2-3=-1, 7-1=6, ili brojimo 1,0,6) pa umetnemo ključ W23 na adresu 6 (pošto ona nije bila zauzeta). Tako su ključevi J10, B2, S19, N14, X24 i W23 umetnuti na adrese 3, 2, 5, 0, 4 i 6, respektivno. Kod dvostrukog heširanja kada su dva ključa sa istom heš adresom u koliziji, oni obično imaju različito umanjenje i različite probne nizove. Ključevi koji su u koliziji, praćenjem različitih probnih staza, brže ispunjavaju prazne redove tabele. Kod otvorenog adresiranja sa linearnim probnim nizom svi ključevi prate jedan probni niz (probe sequence), pa je zato otvoreno adresiranje sa dvostrukim heširanjem bolji metod za razrješavanje kolizije. U narednom primjeru ćemo predstaviti treći način razrješenja kolizije u heš tabeli T, pravljenjem lanaca (chaining). Ideja je da se svi ključevi sa istom heš adresom povežu u linearnu listu koja počinje na toj heš adresi. (Svaku od tih listi možemo da zamislimo kao lanac, pa odtuda i naziv za ovu tehniku.)

-------------------
KOLIZIJE 
----------------------

Do kolizije dolazi kada se dva različita ključa K i K’ preslikavaju u istu heš adresu tabele T, odnosno, kolizija između dva različita ključa, K i K’, nastaje kada pokušamo da umetnemo ključeve K i K’ u heš tabelu T, a oba ključa imaju istu heš adresu, h(K)=h(K’). Način rješavanja kolizije je metoda kojom se pronalazi slobodno prazno mjesto u tabeli T u koju se smješta ključ K', ako je njegova heš adresa h(K') već zauzeta drugim ključem K prethodno smještenim u tabelu T. Suprotno našoj intuiciji, činjenica je da su kolizije relativno česte, čak i u slabo popunjenim heš tabelama. Postoji paradoks koji se zove Rođendanski paradoks R. fon Misesa koji nam pomaže da shvatimo učestanost kolizija. Prema njemu, ako su u nekoj prostoriji 23 ili više osoba, šansa da dvije ili više osoba imaju rođendan istog dana je veća od 50%. (Druga varijanta kaže da ako je 88 ili više osoba u istoj prostoriji, onda je šansa da 3 ili više osoba imaju rođendan istog dana ,takođe, veća od 50%.) 
FAKTORI UNOSA I GRUPISANJE 
Za metodu metode otvorenog adresiranja se treba definisati faktor unosa heš tabele T. Pretpostavimo da je heš tabela T veličine M, što znači da ima mjesta za M slogova tabele, i da je N od ovih M slogova zauzeto (to jest, M-N slogova je prazno). Tada je definicija faktora unosa slijedeća: Faktor unosa,u oznaci, , heš tabele dimenzije M sa N zauzetih slogova, definiše se sa =N/M. Na primjer, ako je heš tabela T veličine 100 sa 75 zauzetih slogova i 25 praznih slogova, onda je njen faktor unosa =75/100=0.75. Dakle, faktor unosa je broj između 0 i 1. (U otvorenom adresiranju mi definiramo punu tabelu kao tabelu sa tačno jednim praznim slogom, stoga faktor unosa ne može biti jednak 1. Ovo je važna garancija da bi algoritmi pretraživanja i umetanja novog ključa u tabelu, efikasno završavali rad.)
Takođe, faktor unosa možemo shvatiti kao procenat zauzetih mjesta u tabeli T (ako je =0,25 to znači da ima 25% zauzetih mjesta, ako je =0,5 onda ima 50% zauzetih mjesta...). 
Pređimo, sada, na grupisanje (clustering). Klaster je sekvenca susjednih zauzetih slogova u heš tabeli. Klasteri ne sadrže prazne ključeve i sastoje se od uzastopnih nizova zauzetih slogova. Iz toga proizilazi da je metod linearne probe uzrok primarnog grupisanja. Možemo videti da kada je neki broj ključeva u koliziji na datoj adresi i kada za razrješavanje te kolizije koristimo linearnu probu, ključevi u koliziji se smještaju na praznu lokaciju odmah ispod lokacije kolizije (jer linearna proba traga za lokacijom praznog mjesta u tabeli na prvoj manjoj adresi od lokacije kolizije). Ovo može izazvati stvaranje male grupe ključeva na lokaciji kolizije. Grubo govoreći, u primarnom grupisanju dešava se slijedeće: mala grupa ključeva raste sve više po broju i veličini. Kako god pokušamo da umetnemo novi ključ u sredinu grupe, linearna proba nas primorava da gledamo na donju granicu grupe kako bi pronašli prvu slobodnu lokaciju za umetanje novog ključa. Zbog toga veće grupe “privlače više pogodaka” novih ključeva za umetanje, i izuzetno brzo rastu na donjoj granici (gde se riječ donja odnosi na smjer manje adrese u tabeli, a veće na smjer veće adrese u tabeli). Čak šta više, manje grupe zajedno formiraju veće, a tako formirane veće grupe rastu još brže. Ovaj fenomen formiranja grupa, njihov rast i spajanje u veće zove se primarno grupisanje. 
Suprotno tome, kada kolizije razrješavamo dvostrukim heširanjem, a ne linearnom probom, nema primarnog grupisanja. Pokazuje se da je dvostruko heširanje bolje za rad od linearne probe, zbog odsustva grupisanja.

--------
GRAF
--------
Graf je kolekcija vrhova (engl. vertex) u kojoj su neki od parovi vrhova međusobno povezani ivicama (engl. edge ili arc). U informatici je uobičajeno da se graf naziva mrežom (engl. network), a vrhovi - čvorivima (engl. node). Grafom se može pradstaviti bilo koji skup podataka od kojih neki međusobno komuniciraju, na primjer, računari umreženi u mrežu, ljudi povezani u socijalnoj mreži...

------------------------
REPREZENTACIJE GRAFA 
------------------------
Neka je G=(V,E) graf. Ako ima n vrhova u V, numeriraćemo ih brojevima od 1 do n, v1,v2,...,vn. Sada možemo oformiti tabelu Ti,j sa n redova i n kolona, gdje je i indeks reda, a j indeks kolone (i,j=1,...,n). Ispunićemo tabelu T nulama i jedinicama, tako da jedinica na mjestu ij označava da postoji ivica e=(vi,vj) (koja spaja vrhove vi i vj). Nula označava nepostojanje ivice. Takva tabela, T, se naziva matrica susjedstva (adjacency matrix) grafa G. (Primjer grafa i odgovarajuće tabele na slici.
 
Dati red Ri, tabele T, sadrži informaciju o vrhovima vj, j=1,...,n, koji su susjedni datom vrhu vi (susjedni su ako u prijeseku j-tog stupca sa redom i postoji 1). Informacija koju nosi red Ri se u C-u može predstaviti pomoću bit vektora. Bit vektor koji predstavlja red Ri bi se sastojao od niza n bitova, Ri=b1,b2,...,bn, tako da je bit bi=Ti,j Graf se može predstaviti i povezanom listom. Na primjer, možemo predstaviti svaki red Ri, matrice susjednih vrhova T, listom indeksa j, vrhova vj, koji su susjedni vrhu vi. Takva lista susjednih vrhova je samo još jedna od reprezentacija grafa i može imati sekvencijalnu ili povezanu nižu reprezentaciju, kao na slici.

U sekvencijalnoj reprezentaciji je dužina svake liste susjednih vrhova jednaka stepenu adekvatnog vrha kod neusmjerenog grafa, odnosno izlaznom stepenu, kod usmjerenog grafa.
 Još jedan bitan pojam je stepen vrha. Ukoliko je graf usmjeren, razlikuju se dva stepena za svaki vrh: 
1.	izlazni stepen (out-degree) koji se računa kao zbir elemenata u redu, a označava broj ivica koje „izlaze“ iz vrha i
2.	ulazni stepen (in-degree) koji se računa kao zbir kolone, a označava broj ivica koje „ulaze“ u vrh.
Tako je, na primjer, izlazni stepen vrha 3 sa Slike 1 jednak 2 (zbir elemenata u trećem redu) a ulazni je 1 (zbir elemenata u trećoj koloni). 
Ukoliko graf nije usmjeren, zbirovi po i-tom redu i i-toj koloni su jednaki i predstavljaju stepen i-tog vrha. Centralnost vrha/čvora izražena preko stepena se definiše ili kao stepen vrha ili kao stepen vrha podjeljen maksimalnim brojem ivica iz jednog vrha.
Gustina grafa/mreže se računa kao broj ivica podjeljen maksimalnim brojem ivica. Za njeno računanje se može iskoristiti Handshaking lemma (broj ivica je jednak polovini zbira stepeni svih vrhova. 
Ostali pojmovi o grafovima su definisani u materijalima iz diskretne matematike. Iako se graf može predstaviti i u povezanoj reprezentaciji, uobičajeno je, da se radi brzine, koristi sekvencijalna reprezentacija matrice susjedstva, odnosno dvodimenzioni niz.

--------------------
PRIMJENE GRAFA
---------------------
Postoje dvije veoma raširene i veoma popularne primjene teorije grafova u informatici: 
1.	primjena u kompjuterskim mrežama 
Dat je primjer kompjuterske mreže sa topologijom zvijezde (svaki računar je povezan samo na switch); sastaviti funkciju koja određuje switch, (ulaz u funkciju je dvodimenzioni niz, a funkcija ispisuje poruku na ekranu i indeks vrha koji ima najveći stepen). 
2.	primjena u socijalnim mrežama.
Recimo da se trebaju prikupiti informacije o prijateljstvima na FB za studente 1. Godine PTF-a. U tom slučaju je najjednostavnije reći da studentima odgovaraju čvorovi grafa, a uspostavljenim prijateljstvima ivice grafa. Ovaj graf nije usmjeren jer prijateljstvo na FB ne može biti jednosmjerno, već je uvijek uzajamno. 
U ovakvom grafu stepen vrha predstavlja broj prijatelja. On se računa sumiranjem po redu (ili koloni) za odgovarajući indeks. 

                                                                                                                                           
                                                                                                                                           
-------------------------------------------------------------------------------------------------------------------------
Primjer usmjerenog grafa: komunikacija mail-om
Recimo da se trebaju prikupiti informacije o komunikaciji studenata 1. godine i edukatora na PTF-u. U ovom slučaju je bitno ko je s kim komunicirao, pa se za reprezentaciju bira usmjereni graf. U tom grafu su čvorovi i studenti i edukatori, a lukovi (usmjerene ivice) prate ko je s kim komunicirao.
U slučaju ovakve mreže može nas zanimati: 
1.	postoji li student koji nije dobio odgovor od edukatora 
2.	postoji li edukator koji nije odgovorio svim studentima koji su mu pisali 
3.	ko je komunicirao sa najviše osoba (ko ima najveći izlazni stepen vrha) 
4.	ko je primio poštu od najvećeg broja osoba (ko ima najveći ulazni stepen vrha) 
5.	postoji li neko ko je slao pisma na tri različite adrese (izlazni stepen je 3), itd.
 
GRAF MIN – NAJKRAĆA PUTANJA
Usmjereni težinski graf1 je usmjereni graf kod koga su usmjerenim ivicama pridodati brojevi koji se nazivaju težine. Težine pridodate ivicama mogu predstavljati veličine kao što su razdaljina, cijena ili vrijeme. 
Pretpostavimo da vrhovi grafa G=(V,E) predstavljaju gradove, a težine dodjeljene ivicama razdaljine među gradovima. Ako su nam data dva grada, X i Y, možemo odrediti najkraću putanju između njih. 
Neka za reprezentaciju usmjerenog težinskog grafa koristimo matricu susjedstva, T[i,j], u kojoj je T[i,j]=wi,j ukoliko postoji ivica e=(vi,vj) sa težinom wi,j, a T[i,j] je 0 za i=j, a (znak beskonačno) ukoliko ne postoji ivica između vrhova vi i vj. Neka su još sve težine wi,j pozitivne veličine.

GRAF PRIMOV I KRUSKALOV ALOGRITAM
Problem nalaženja minimalnog razapinjućeg stabla javlja se u slučajevima kada treba pronaći mrežu sa minimalnim troškovima kojom se povezuje dati skup vrhova (npr. mreža kablovske televizije, mreža drumskih i željezničkih pravaca između gradova i sl.). Iako ovi algoritmi mogu zvučati jednostavno, njihova implementacija može biti komplikovanija. U opštem slučaju, najveći problem je da se odredi prave li dvije ivice ciklus. Taj se problem može riješiti na način da se prati koji su vrhovi krajevi ivica. Kadaa se odabere ivica, oba vrha koji su joj krajevi se dodaju u spisak odabranih vrhova, ukoliko je to moguće. Ukoliko su oba vrha već u skupu odabranih, onda se ta ivica ne može odabrati.
ALGORITMI ZA NALAŽENJE MINIMALNOG RAZAPINJUĆEG STABLA 
Kruskal-ov algoritam: u svakom koraku se bira ivica najmanje težine tako da se ne formira ciklus. 
Implementacija 
Potrebne strukture su: spisak ivica sa težinama i vrhovima koji su im krajevi, skup odabranih ili odbijenih ivica, skup odabranih vrhova organizovanih u stabla (inicijalno, svaki vrh je zasebno stablo); ivice mogu biti organizovane u prioritetni red, najveći prioritet ima najmanja težina. Postupak: Inicijalno, svaki vrh je posebno stablo; iz skupa ivica bira se ivica najmanje težine; provjeri se da li ivica spaja dva različita stabla ako da, ivice se prihvata, a dva stabla se uniraju (operacija unije za grafove), ne, ivica se odbija. i njeni vrhovi se dodaju u skup odabranih vrhova; 
Postupak se završava kada je broj odabranih ivica za jedan manji od broja vrhova.
Prim-ov algoritam: 
Formiranje podgrafa počinje od proizvoljnog vrha. U svakom koraku bira se ivica najmanje težine, iz skupa ivica koje spajaju neki od već odabranih vrhova sa nekim od onih koji još nisu odabrani.
