# BSEP-projekat


<b>Integrity check tools</b>


U okviru Integrity check tools potrebno je implementirati proveru integriteta nad listi sa APK datotekama, kako bi se ispitalo da li se APK datoteke odnose na istu zvanicnu aplikaciju. 
Sistem omogucuje prikaz liste APK datoteka, odnosno jar-a, proverava integritet jar-a i poredi javne kljuceve jar-a. Nakon izvrsene operacije, sistem ispisuje odgovarajuci odgovor, da li je uspesno izvrsena operacija ili je doslo do greske, pri cemu objasnjava i koja je greska u pitanju. APK datotekama se pristupa na osnovu njihove putanje do datog fajla.
Iz aspekta informacione bezbednosti koristice se infrastruktura javnih kljuceva, cime vezujemo i poredimo javne kljuceve izmedju vise APK datoteka. Pomocu navedenog sistema kreiramo, upravljamo, koristimo i skladistimo digitalne sertifikate. Digitalni sertifikat ce prikazati: ko je izdao sertifikat, kome i kada je izdat i do kada je validan. Javni kljuc je povezan sa sertifikatom i za koga je on izdat. Omoguceno je i formiranje digitalnog potpisa od strane izdavaoca sertifikata. Sistem ispituje ispravnost sertifikata i potpisa i ako je potrebno, prijavljuje odgovarajucu gresku. Ovim sistemom takodje je omogucena zastita integriteta, autenticnost i dostupnost javnih kljuceva.


<i><u>Funkcionalnosti:</u></i>

-l / -list	         -lista svih apk(jar) fajlova
-v / -verify         -provera ispravnosti apk(jar) fajlova
-c / -comparePublickey  -poredjenje Javnih kljuceva apk(jar) fajlova


<i><u>Nacin koriscenja:</u></i>

Potrebno je pozicionirati se na datoteku gde se nalazi integritychecktool.jar i primeniti navedene funkcionalnosti nad izapranim apk fajlovima, kojima se pristupa na osnovu njihove putanje do fajla. 


<i><u>Primer:</i></u>

java -jar ./integritychecktool.jar -l C:/Users/krist/Desktop/test/test.apk C:/Users/krist/Desktop/test/test1.apk -v -c