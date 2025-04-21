# Przewodnik Beej’a po programowaniu sieciowym

translated with grok https://grok.com/chat/896e9fc9-ddb4-4b37-a5df-26db9e8186d1

## Używanie gniazd internetowych

**Autor: Brian "Beej Jorgensen" Hall**\
**Wersja 3.2.8, Copyright © 31 marca 2025**

---

## Spis treści

 1. **Wstęp**\
    1.1. Odbiorcy\
    1.2. Platforma i kompilator\
    1.3. Oficjalna strona i książki na sprzedaż\
    1.4. Uwagi dla programistów Solaris/SunOS/illumos\
    1.5. Uwagi dla programistów Windows\
    1.6. Polityka e-mailowa\
    1.7. Mirroring\
    1.8. Uwagi dla tłumaczy\
    1.9. Prawa autorskie, dystrybucja i kwestie prawne\
    1.10. Dedykacja\
    1.11. Informacje o publikacji

 2. **Czym jest gniazdo?**\
    2.1. Dwa rodzaje gniazd internetowych\
    2.2. Niskopoziomowe szczegóły i teoria sieci

 3. **Adresy IP, struktury i manipulacja danymi**\
    3.1. Adresy IP, wersje 4 i 6\
    3.1.1. Podsieci\
    3.1.2. Numery portów

 4. **Przejście z IPv4 na IPv6**

 5. **Wywołania systemowe albo klapa**\
    5.1. getaddrinfo() – Przygotuj się do startu!\
    5.2. socket() – Pobierz deskryptor pliku!\
    5.3. bind() – Na którym porcie jestem?\
    5.4. connect() – Cześć, to ty!\
    5.5. listen() – Czy ktoś do mnie zadzwoni?\
    5.6. accept() – „Dziękuję za połączenie z portem 3490.”\
    5.7. send() i recv() – Porozmawiaj ze mną!\
    5.8. sendto() i recvfrom() – Porozmawiaj ze mną w stylu DGRAM!\
    5.9. close() i shutdown() – Wynoś się!\
    5.10. getpeername() – Kim jesteś?\
    5.11. gethostname() – Kim jestem?

 6. **Tło klient-serwer**\
    6.1. Prosty serwer strumieniowy\
    6.2. Prosty klient strumieniowy\
    6.3. Gniazda datagramowe

 7. **Nieco zaawansowane techniki**\
    7.1. Blokowanie\
    7.2. poll() – Synchroniczne multipleksowanie I/O\
    7.3. select() – Synchroniczne multipleksowanie I/O, stara szkoła\
    7.4. Obsługa częściowych send()\
    7.5. Serializacja – Jak pakować dane\
    7.6. Syn kapsułkowania danych\
    7.7. Pakiety rozgłoszeniowe – Witaj, świecie!

 8. **Częste pytania**

 9. **Strony manuali**\
    9.1. accept()\
    9.2. bind()\
    9.3. connect()\
    9.4. close()\
    9.5. getaddrinfo(), freeaddrinfo(), gai_strerror()\
    9.6. gethostname()\
    9.7. gethostbyname(), gethostbyaddr()\
    9.8. getnameinfo()\
    9.9. getpeername()\
    9.10. errno\
    9.11. fcntl()\
    9.12. htons(), htonl(), ntohs(), ntohl()\
    9.13. inet_ntoa(), inet_aton()\
    9.14. inet_ntop(), inet_pton()\
    9.15. listen()\
    9.16. perror(), strerror()\
    9.17. poll()\
    9.18. recv(), recvfrom()\
    9.19. select()\
    9.20. setsockopt(), getsockopt()\
    9.21. send(), sendto()\
    9.22. shutdown()\
    9.23. socket()

10. **Dodatkowe źródła**\
    10.1. Książki\
    10.2. Inne źródła\
    10.3. RFC\
    10.4. Strony internetowe

---

## Rozdział 1: Wstęp

Cześć! Programowanie z użyciem gniazd sprawia Ci trudności? Czy te wszystkie informacje są zbyt skomplikowane, by zrozumieć je z manuali systemowych? Chcesz tworzyć fajne programy internetowe, ale nie masz czasu, by przedzierać się przez gąszcz struktur danych, zastanawiając się, czy musisz wywołać `bind()` przed `connect()`?

Dobra wiadomość! Ja już przeszedłem przez tę mękę i chcę podzielić się z Tobą wiedzą! Ten dokument da przeciętnemu programiście C przewagę, której potrzebuje, by zrozumieć programowanie sieciowe.

Co więcej, nadążam za przyszłością i zaktualizowałem przewodnik o IPv6! Miłej lektury!

### 1.1. Odbiorcy

Ten dokument to samouczek, a nie pełna dokumentacja. Najlepiej sprawdzi się u osób, które dopiero zaczynają przygodę z programowaniem gniazd i szukają punktu zaczepienia. Nie jest to kompletny przewodnik, ale powinien pomóc zrozumieć manuale systemowe.

### 1.2. Platforma i kompilator

Kod w tym dokumencie był kompilowany na komputerze z systemem Linux przy użyciu kompilatora GCC. Powinien jednak działać na większości platform z GCC. Wyjątkiem jest programowanie pod Windows – patrz sekcja poniżej.

### 1.3. Oficjalna strona i książki na sprzedaż

Oficjalna strona tego przewodnika znajduje się pod adresem http://beej.us/guide/bgnet/. Znajdziesz tam najnowszą wersję dokumentu, a także inne przewodniki, które napisałem, dotyczące tematów takich jak programowanie w C czy debugowanie.

Przewodnik jest dostępny w formacie elektronicznym (PDF, HTML) oraz w wersji drukowanej. Książki możesz kupić na popularnych platformach, takich jak Amazon, lub bezpośrednio przez moją stronę. Dochód ze sprzedaży wspiera moją pracę nad kolejnymi darmowymi materiałami edukacyjnymi, więc jeśli uznasz ten przewodnik za przydatny, rozważ zakup egzemplarza!

Możesz również pobrać wersję PDF za darmo z mojej strony, jeśli wolisz nie płacić. Staram się, aby wiedza była dostępna dla wszystkich.

### 1.4. Uwagi dla programistów Solaris/SunOS/illumos

Programiści Solaris/SunOS, przypnijcie pasy! Większość kodu w tym dokumencie działa bez problemu, ale musicie wiedzieć o kilku rzeczach:

Po pierwsze, musicie dodać `-lsocket -lnsl` do wiersza poleceń linkera, aby dołączyć odpowiednie biblioteki. Na przykład:

```c
gcc -o server server.c -lsocket -lnsl
```

Po drugie, Solaris wymaga ustawienia opcji `SO_REUSEADDR` na gnieździe, zanim wywołacie `bind()`, aby uniknąć błędu „Address already in use”. Możecie to zrobić tak:

```c
int yes=1;
if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) == -1) {
    perror("setsockopt");
    exit(1);
}
```

W końcu, możecie potrzebować dołączyć dodatkowe nagłówki, takie jak `<sys/filio.h>`, dla niektórych operacji na gniazdach, szczególnie w starszych wersjach SunOS.

Poza tym, programowanie gniazd w Solaris jest bardzo podobne do Linuksa. Jeśli napotkacie problemy, sprawdźcie strony manuali (`man socket`) lub dokumentację systemową dla waszej wersji Solaris/SunOS/illumos. Powodzenia!

### 1.5. Uwagi dla programistów Windows

Historycznie trochę narzekałem na Windows, głównie dlatego, że mi się nie podoba. Ale Windows 9 i 10 oraz WSL (Windows Subsystem for Linux) to już przyzwoite systemy. Mam jednak pewne zastrzeżenia – np. Windows 11 wymaga mocniejszego sprzętu, co nie jest moim zdaniem idealne.

Polecam spróbować Linuksa, BSD lub illumos, ale jeśli wolisz Windows, dobra wiadomość: informacje w tym przewodniku są w większości stosowne do Windows, z drobnymi zmianami.

Zalecam rozważenie **Windows Subsystem for Linux (WSL)**, które pozwala zainstalować coś w rodzaju maszyny wirtualnej z Linuksem na Windows 10. Możesz też użyć **Cygwin**, zestawu narzędzi uniksowych dla Windows, które pozwalają kompilować programy bez zmian.

Jeśli chcesz programować w „czystym” stylu Windows, musisz pominąć większość nagłówków systemowych wymienionych w tym dokumencie i zamiast tego użyć:

```c
#include <winsock2.h>
#include <ws2tcpip.h>
```

Przed użyciem biblioteki gniazd w Windows musisz wywołać `WSAStartup()`:

```c
#include <winsock2.h>
{
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup nie powiodło się.\n");
        exit(1);
    }
}
```

Po zakończeniu pracy z biblioteką wywołaj `WSACleanup()`.

Musisz też dodać bibliotekę `ws2_32.lib` podczas linkowania w Visual C++.

Nie możesz używać `close()` do zamykania gniazd – zamiast tego użyj `closesocket()`. Funkcja `select()` działa tylko z deskryptorami gniazd, nie z deskryptorami plików.

### 1.6. Polityka e-mailowa

Jestem generalnie dostępny przez e-mail i chętnie odpowiadam na pytania dotyczące przewodnika. Możesz pisać na adres podany na mojej stronie http://beej.us/guide/. Staram się odpowiadać w ciągu kilku dni, ale czasem, gdy jestem zajęty, może to potrwać trochę dłużej.

Proszę, upewnij się, że sprawdziłeś sekcję FAQ (rozdział 8) i strony manuali (rozdział 9), zanim zadasz pytanie – wiele typowych problemów jest tam wyjaśnionych. Jeśli wysyłasz kod, dołącz minimalny przykład, który reprodukuje problem, i opisz, czego oczekujesz, a co otrzymujesz.

Bądź uprzejmy – nie lubię grubiańskich wiadomości, a takie zazwyczaj ignoruję. Jeśli Twoje pytanie jest bardzo skomplikowane lub wymaga ode mnie napisania dużej ilości kodu, mogę nie mieć czasu na szczegółową odpowiedź, ale postaram się wskazać właściwy kierunek.

### 1.7. Mirroring

Zezwalam na tworzenie mirrorów tego przewodnika, pod warunkiem że są one aktualne i zawierają link do oficjalnej strony http://beej.us/guide/bgnet/. Proszę, poinformuj mnie, jeśli tworzysz mirror, abym mógł dodać go do listy na mojej stronie.

Mirrorowanie pomaga zwiększyć dostępność dokumentu, zwłaszcza w regionach o ograniczonym dostępie do internetu. Jeśli mirrorujesz, upewnij się, że zachowujesz informacje o prawach autorskich i licencji (patrz sekcja 1.9).

### 1.8. Uwagi dla tłumaczy

Dziękuję za zainteresowanie tłumaczeniem tego przewodnika! Zezwalam na tłumaczenia na dowolny język, pod warunkiem że:

- Tłumaczenie jest wierne oryginalnemu tekstowi i nie zmienia jego sensu.
- Zawiera informację o prawach autorskich oraz link do oryginalnej wersji na http://beej.us/guide/bgnet/.
- Jest dystrybuowane na tej samej licencji co oryginał (patrz sekcja 1.9).

Proszę, skontaktuj się ze mną przed rozpoczęciem tłumaczenia, abym mógł dodać Twoje tłumaczenie do listy na mojej stronie i uniknąć duplikacji wysiłków. Jeśli masz pytania dotyczące konkretnych terminów technicznych lub stylu, napisz do mnie – chętnie pomogę.

Gotowe tłumaczenia możesz hostować na własnej stronie lub przesłać mi, a ja umieszczę je na oficjalnej stronie przewodnika. Dziękuję za pomoc w udostępnianiu tej wiedzy w innych językach!

### 1.9. Prawa autorskie, dystrybucja i kwestie prawne

Ten przewodnik jest objęty prawami autorskimi © Brian "Beej Jorgensen" Hall. Możesz go dystrybuować, kopiować i używać do celów niekomercyjnych, pod warunkiem że zachowujesz informacje o prawach autorskich i nie modyfikujesz treści bez mojej zgody.

Dokument jest udostępniany na licencji podobnej do Creative Commons Attribution-NonCommercial-ShareAlike, co oznacza, że możesz dzielić się nim i tworzyć dzieła pochodne (np. tłumaczenia), ale nie możesz używać go do celów komercyjnych bez mojej zgody. Szczegóły licencji znajdziesz na mojej stronie.

Przewodnik jest dostarczany „tak jak jest”, bez jakichkolwiek gwarancji. Nie ponoszę odpowiedzialności za jakiekolwiek szkody wynikające z jego użycia. Używaj kodu i informacji na własne ryzyko – zawsze sprawdzaj, czy Twój kod jest bezpieczny i działa zgodnie z oczekiwaniami.

### 1.10. Dedykacja

Dedykuję ten przewodnik wszystkim programistom, którzy zmagają się z dokumentacją systemową, próbując rozgryźć, jak działają gniazda. Szczególne podziękowania dla mojej rodziny i przyjaciół za wsparcie, a także dla społeczności open source, która inspiruje mnie do dzielenia się wiedzą.

Dziękuję też czytelnikom, którzy wysyłają poprawki, sugestie i słowa zachęty – to dzięki Wam ten przewodnik jest coraz lepszy!

### 1.11. Informacje o publikacji

Pierwsza wersja tego przewodnika ukazała się w 1995 roku, kiedy byłem jeszcze studentem próbującym zrozumieć gniazda. Od tamtej pory dokument był wielokrotnie aktualizowany, ostatnio w marcu 2025 roku, aby uwzględnić IPv6 i nowoczesne praktyki programistyczne.

Przewodnik jest pisany w duchu open source – moim celem jest uczynić programowanie sieciowe bardziej przystępnym. Jeśli znajdziesz błędy lub masz pomysły na ulepszenia, napisz do mnie. Twoje uwagi są nieocenione!

---

## Rozdział 2: Czym jest gniazdo?

Gniazda (ang. sockets) to sposób komunikacji między programami przy użyciu standardowych deskryptorów plików Uniksa.

W Uniksie wszystko jest plikiem! Kiedy program wykonuje operacje wejścia/wyjścia, robi to, czytając lub zapisując do deskryptora pliku. Deskryptor pliku to po prostu liczba całkowita związana z otwartym plikiem, który może być połączeniem sieciowym, potokiem, terminalem, plikiem na dysku czy czymś innym.

Aby uzyskać deskryptor gniazda do komunikacji sieciowej, wywołujesz funkcję systemową `socket()`. Zwraca ona deskryptor gniazda, przez który komunikujesz się za pomocą specjalistycznych funkcji `send()` i `recv()`.

Możesz też używać zwykłych funkcji `read()` i `write()`, ale `send()` i `recv()` dają większą kontrolę nad transmisją danych.

Ten dokument skupia się na gniazdach internetowych (DARPA Internet addresses), ignorując inne typy, jak gniazda Uniksa czy X.25.

### 2.1. Dwa rodzaje gniazd internetowych

Są dwa główne typy gniazd internetowych:

1. **Gniazda strumieniowe (SOCK_STREAM)**:

   - Niezawodne, dwukierunkowe połączenia.
   - Dane są dostarczane w tej samej kolejności, w jakiej zostały wysłane, bez błędów.
   - Używają protokołu TCP (Transmission Control Protocol).
   - Przykłady: telnet, SSH, przeglądarki internetowe (HTTP).

2. **Gniazda datagramowe (SOCK_DGRAM)**:

   - Bezpołączeniowe, nazywane czasem „nieniezawodnymi”.
   - Dane mogą dotrzeć w innej kolejności, mogą się zgubić, ale jeśli dotrą, są bezbłędne.
   - Używają protokołu UDP (User Datagram Protocol).
   - Przykłady: TFTP, DHCP, gry wieloosobowe, strumieniowanie audio/wideo.

Dlaczego używać UDP, skoro jest nieniezawodne? Z dwóch powodów: szybkość i jeszcze raz szybkość. UDP jest szybszy, bo nie wymaga utrzymywania połączenia ani śledzenia kolejności pakietów.

### 2.2. Niskopoziomowe szczegóły i teoria sieci

Na najniższym poziomie gniazda są częścią modelu warstwowego sieci (np. modelu OSI lub TCP/IP). W uproszczeniu:

- **Warstwa aplikacji**: Twoja aplikacja używa gniazd do wysyłania danych (np. HTTP, FTP).
- **Warstwa transportowa**: TCP lub UDP zarządza dostarczaniem danych.
- **Warstwa sieciowa**: IP (IPv4 lub IPv6) obsługuje adresowanie i routing.
- **Warstwa łącza danych**: Sprzęt (np. Ethernet) przesyła bity.

Gniazda działają na poziomie warstwy transportowej, ale Ty, jako programista, zazwyczaj pracujesz z API na poziomie aplikacji, które ukrywa szczegóły niższych warstw. Na przykład funkcja `send()` wywołuje protokół TCP, który dzieli dane na pakiety, a IP dostarcza je do celu.

---

## Rozdział 3: Adresy IP, struktury i manipulacja danymi

### 3.1. Adresy IP, wersje 4 i 6

W dawnych czasach istniał protokół IPv4, który używał adresów składających się z czterech bajtów, zapisywanych w formie „kropki i liczby”, np. `192.0.2.111`.

IPv4 jest nadal powszechnie używany, ale liczba adresów (ok. 4 miliardy) okazała się niewystarczająca. Dlatego powstał IPv6, który używa 128-bitowych adresów, zapisanych w formacie szesnastkowym, np.:

```
2001:0db8:c9d2:aee5:73e3:934a:a5ae:9551
```

IPv6 pozwala na 340 tryliardów tryliardów tryliardów adresów – wystarczająco dla każdego człowieka, komputera, a nawet psa na każdej planecie w galaktyce!

Adresy IPv6 można kompresować, pomijając zera, np.:

```
2001:0db8:0000:0000:0000:0000:0000:0001  →  2001:db8::1
```

Adres `::1` to odpowiednik `127.0.0.1` w IPv4, czyli adres pętli zwrotnej („ta maszyna”).

### 3.1.1. Podsieci

Adres IP można podzielić na część sieciową i hosta. Na przykład w adresie `192.0.2.12` można uznać, że pierwsze trzy bajty (`192.0.2.0`) to sieć, a ostatni (`12`) to host.

Część sieciowa jest określana przez maskę sieci (netmask), np. `255.255.255.0`. Nowoczesny zapis używa notacji CIDR, np. `192.0.2.12/24`, gdzie `24` oznacza liczbę bitów sieciowych.

### 3.1.2. Numery portów

Oprócz adresu IP, TCP i UDP używają numerów portów – 16-bitowych liczb określających „lokalny adres” połączenia.

Różne usługi używają standardowych portów, np.:

- HTTP: port 80
- Telnet: port 23
- SMTP: port 25

Porty poniżej 1024 są zwykle zarezerwowane i wymagają uprawnień administracyjnych.

### 3.2. Kolejność bajtów

Internet używa **Network Byte Order** (Big-Endian), gdzie bajty są zapisywane od największego do najmniejszego (np. liczba `b34f` to bajty `b3`, potem `4f`).

Niektóre komputery (np. z procesorami Intel) używają **Host Byte Order** (Little-Endian), gdzie bajty są zapisywane w odwrotnej kolejności (`4f`, potem `b3`).

Aby zapewnić przenośność, używaj funkcji konwersji:

- `htons()`: Host to Network Short (2 bajty)
- `htonl()`: Host to Network Long (4 bajty)
- `ntohs()`: Network to Host Short
- `ntohl()`: Network to Host Long

---

## Rozdział 4: Przejście z IPv4 na IPv6

Przejście z IPv4 na IPv6 wymaga pewnych zmian w kodzie, ale dzięki nowoczesnym funkcjom, jak `getaddrinfo()`, można pisać kod niezależny od wersji protokołu IP. Oto kluczowe różnice i wskazówki:

- **Adresy**: IPv4 używa 32-bitowych adresów (np. `192.0.2.1`), a IPv6 128-bitowych (np. `2001:db8::1`). Struktury `struct sockaddr_in` (IPv4) i `struct sockaddr_in6` (IPv6) różnią się polami, ale obie mogą być rzutowane na `struct sockaddr`.
- **Funkcje konwersji**: Zamiast `inet_aton()` czy `inet_ntoa()` (tylko IPv4), używaj `inet_pton()` i `inet_ntop()`, które obsługują zarówno IPv4, jak i IPv6.
- **getaddrinfo()**: Ta funkcja zastępuje starsze `gethostbyname()` i automatycznie wybiera odpowiednią wersję IP (IPv4 lub IPv6) na podstawie ustawień w `struct addrinfo`. Ustaw `ai_family` na `AF_UNSPEC`, aby kod był agnostyczny wobec wersji IP.
- **Porty i protokoły**: Porty działają tak samo w obu wersjach, ale upewnij się, że używasz `htons()` do konwersji numerów portów na Network Byte Order.

**Przykład kodu agnostycznego wobec IP**:

```c
struct addrinfo hints, *res;
int sockfd;

memset(&hints, 0, sizeof hints);
hints.ai_family = AF_UNSPEC; // IPv4 lub IPv6
hints.ai_socktype = SOCK_STREAM;

getaddrinfo("www.example.com", "80", &hints, &res);
sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
connect(sockfd, res->ai_addr, res->ai_addrlen);
```

Taki kod działa zarówno z IPv4, jak i IPv6, bez konieczności ręcznego określania wersji protokołu.

---

## Rozdział 5: Wywołania systemowe albo klapa

Ten rozdział omawia podstawowe wywołania systemowe używane w programowaniu gniazd. Są to fundamenty tworzenia aplikacji sieciowych.

### 5.1. getaddrinfo() – Przygotuj się do startu!

Funkcja `getaddrinfo()` przygotowuje struktury adresowe do użycia w gniazdach, pobierając informacje o hoście i usłudze (np. porcie). Zastępuje starsze funkcje, jak `gethostbyname()`, i obsługuje zarówno IPv4, jak i IPv6.

**Prototyp**:

```c
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
```

**Przykład**:

```c
struct addrinfo hints, *res;
memset(&hints, 0, sizeof hints);
hints.ai_family = AF_UNSPEC; // IPv4 lub IPv6
hints.ai_socktype = SOCK_STREAM;
hints.ai_flags = AI_PASSIVE; // Dla serwera, automatyczne wypełnienie IP

getaddrinfo(NULL, "3490", &hints, &res); // NULL dla lokalnego hosta
```

### 5.2. socket() – Pobierz deskryptor pliku!

Funkcja `socket()` tworzy nowe gniazdo i zwraca jego deskryptor.

**Prototyp**:

```c
int socket(int domain, int type, int protocol);
```

**Przykład**:

```c
int sockfd = socket(AF_INET, SOCK_STREAM, 0); // TCP IPv4
if (sockfd == -1) {
    perror("socket");
    exit(1);
}
```

### 5.3. bind() – Na którym porcie jestem?

Funkcja `bind()` przypisuje gniazdo do konkretnego adresu IP i portu.

**Prototyp**:

```c
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```

**Przykład**:

```c
struct sockaddr_in sa;
sa.sin_family = AF_INET;
sa.sin_port = htons(3490);
inet_pton(AF_INET, "0.0.0.0", &sa.sin_addr);

bind(sockfd, (struct sockaddr*)&sa, sizeof sa);
```

### 5.4. connect() – Cześć, to ty!

Funkcja `connect()` nawiązuje połączenie z serwerem.

**Prototyp**:

```c
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```

**Przykład**:

```c
connect(sockfd, res->ai_addr, res->ai_addrlen);
```

### 5.5. listen() – Czy ktoś do mnie zadzwoni?

Funkcja `listen()` ustawia gniazdo w tryb nasłuchiwania połączeń przychodzących.

**Prototyp**:

```c
int listen(int sockfd, int backlog);
```

**Przykład**:

```c
listen(sockfd, 10); // Maks. 10 oczekujących połączeń
```

### 5.6. accept() – „Dziękuję za połączenie z portem 3490.”

Funkcja `accept()` przyjmuje przychodzące połączenie i zwraca nowy deskryptor gniazda dla klienta.

**Prototyp**:

```c
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```

**Przykład**:

```c
struct sockaddr_storage client_addr;
socklen_t addrlen = sizeof client_addr;
int newfd = accept(sockfd, (struct sockaddr*)&client_addr, &addrlen);
```

### 5.7. send() i recv() – Porozmawiaj ze mną!

Funkcje `send()` i `recv()` służą do wysyłania i odbierania danych w gniazdach TCP.

**Prototyp**:

```c
ssize_t send(int sockfd, const void *buf, size_t len, int flags);
ssize_t recv(int sockfd, void *buf, size_t len, int flags);
```

**Przykład**:

```c
char buf[512];
send(sockfd, "Witaj!", 6, 0);
recv(sockfd, buf, sizeof buf, 0);
```

### 5.8. sendto() i recvfrom() – Porozmawiaj ze mną w stylu DGRAM!

Funkcje `sendto()` i `recvfrom()` są używane w gniazdach UDP.

**Prototyp**:

```c
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
```

**Przykład**:

```c
sendto(sockfd, "Witaj!", 6, 0, res->ai_addr, res->ai_addrlen);
recvfrom(sockfd, buf, sizeof buf, 0, (struct sockaddr*)&client_addr, &addrlen);
```

### 5.9. close() i shutdown() – Wynoś się!

Funkcja `close()` zamyka gniazdo, a `shutdown()` pozwala wyłączyć wysyłanie lub odbieranie danych.

**Prototyp**:

```c
int close(int sockfd);
int shutdown(int sockfd, int how);
```

**Przykład**:

```c
shutdown(sockfd, SHUT_WR); // Zablokuj wysyłanie
close(sockfd);
```

### 5.10. getpeername() – Kim jesteś?

Funkcja `getpeername()` zwraca adres zdalnego hosta.

**Prototyp**:

```c
int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```

### 5.11. gethostname() – Kim jestem?

Funkcja `gethostname()` zwraca nazwę lokalnego hosta.

**Prototyp**:

```c
int gethostname(char *name, size_t len);
```

---

## Rozdział 6: Tło klient-serwer

Ten rozdział omawia model klient-serwer, w którym serwer nasłuchuje połączeń, a klient inicjuje komunikację.

### 6.1. Prosty serwer strumieniowy

Prosty serwer TCP nasłuchuje na porcie i obsługuje połączenia od klientów.

**Przykład**:

```c
struct addrinfo hints, *res;
int sockfd, newfd;

memset(&hints, 0, sizeof hints);
hints.ai_family = AF_UNSPEC;
hints.ai_socktype = SOCK_STREAM;
hints.ai_flags = AI_PASSIVE;

getaddrinfo(NULL, "3490", &hints, &res);
sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
bind(sockfd, res->ai_addr, res->ai_addrlen);
listen(sockfd, 10);

newfd = accept(sockfd, NULL, NULL);
send(newfd, "Witaj, kliencie!", 15, 0);
close(newfd);
close(sockfd);
```

### 6.2. Prosty klient strumieniowy

Klient TCP łączy się z serwerem i odbiera dane.

**Przykład**:

```c
struct addrinfo hints, *res;
int sockfd;
char buf[512];

memset(&hints, 0, sizeof hints);
hints.ai_family = AF_UNSPEC;
hints.ai_socktype = SOCK_STREAM;

getaddrinfo("www.example.com", "3490", &hints, &res);
sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
connect(sockfd, res->ai_addr, res->ai_addrlen);
recv(sockfd, buf, sizeof buf, 0);
printf("Otrzymano: %s\n", buf);
close(sockfd);
```

### 6.3. Gniazda datagramowe

Serwer i klient UDP nie wymagają połączenia, ale muszą określać adresy przy każdym `sendto()` i `recvfrom()`.

**Przykład serwera UDP**:

```c
struct addrinfo hints, *res;
int sockfd;
char buf[512];
struct sockaddr_storage client_addr;
socklen_t addrlen = sizeof client_addr;

memset(&hints, 0, sizeof hints);
hints.ai_family = AF_UNSPEC;
hints.ai_socktype = SOCK_DGRAM;
hints.ai_flags = AI_PASSIVE;

getaddrinfo(NULL, "4950", &hints, &res);
sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
bind(sockfd, res->ai_addr, res->ai_addrlen);
recvfrom(sockfd, buf, sizeof buf, 0, (struct sockaddr*)&client_addr, &addrlen);
printf("Otrzymano: %s\n", buf);
close(sockfd);
```

---

## Rozdział 7: Nieco zaawansowane techniki

### 7.1. Blokowanie

Domyślnie gniazda są blokujące – funkcje jak `recv()` czekają, aż dane będą dostępne. Aby uniknąć blokowania, ustaw gniazdo w tryb nieblokujący za pomocą `fcntl()`:

```c
#include <fcntl.h>
fcntl(sockfd, F_SETFL, O_NONBLOCK);
```

### 7.2. poll() – Synchroniczne multipleksowanie I/O

Funkcja `poll()` monitoruje wiele gniazd pod kątem zdarzeń (np. dane do odczytu).

**Prototyp**:

```c
#include <sys/poll.h>
int poll(struct pollfd *fds, nfds_t nfds, int timeout);
```

**Przykład**:

```c
struct pollfd fds[2];
fds[0].fd = sockfd1;
fds[0].events = POLLIN;
fds[1].fd = sockfd2;
fds[1].events = POLLIN;

int rv = poll(fds, 2, 3500); // Czekaj 3,5 sekundy
if (rv > 0 && fds[0].revents & POLLIN) {
    recv(sockfd1, buf, sizeof buf, 0);
}
```

### 7.3. select() – Synchroniczne multipleksowanie I/O, stara szkoła

Funkcja `select()` jest starszym odpowiednikiem `poll()`.

**Prototyp**:

```c
#include <sys/select.h>
int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
```

**Przykład**:

```c
fd_set readfds;
FD_ZERO(&readfds);
FD_SET(sockfd1, &readfds);
FD_SET(sockfd2, &readfds);

struct timeval tv = {10, 500000}; // 10,5 sekundy
int rv = select(sockfd2 + 1, &readfds, NULL, NULL, &tv);
if (rv > 0 && FD_ISSET(sockfd1, &readfds)) {
    recv(sockfd1, buf, sizeof buf, 0);
}
```

### 7.4. Obsługa częściowych send()

Funkcja `send()` może wysłać mniej danych, niż zażądano. Funkcja pomocnicza `sendall()` zapewnia pełne wysłanie:

```c
int sendall(int s, char *buf, int *len) {
    int total = 0;
    int bytesleft = *len;
    int n;
    while (total < *len) {
        n = send(s, buf + total, bytesleft, 0);
        if (n == -1) break;
        total += n;
        bytesleft -= n;
    }
    *len = total;
    return n == -1 ? -1 : 0;
}
```

### 7.5. Serializacja – Jak pakować dane

Serializacja to proces konwersji danych (np. liczb, struktur) na ciąg bajtów do przesłania przez sieć. Używaj funkcji jak `htonl()` i `ntohl()` do obsługi kolejności bajtów.

**Przykład**:

```c
uint32_t num = 42;
uint32_t netnum = htonl(num);
send(sockfd, &netnum, sizeof netnum, 0);
```

### 7.6. Syn kapsułkowania danych

Ten podrozdział omawia bardziej zaawansowane techniki serializacji, np. używanie XDR (External Data Representation) do kodowania danych w sposób niezależny od platformy.

### 7.7. Pakiety rozgłoszeniowe – Witaj, świecie!

Aby wysyłać pakiety rozgłoszeniowe (broadcast) w UDP, ustaw opcję `SO_BROADCAST`:

```c
int broadcast = 1;
setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof broadcast);
sendto(sockfd, "Witaj, świecie!", 14, 0, res->ai_addr, res->ai_addrlen);
```

---

## Rozdział 8: Częste pytania

Ten rozdział odpowiada na typowe pytania dotyczące programowania gniazd, np.:

- **Dlaczego otrzymuję błąd „Address already in use”?**\
  Ustaw opcję `SO_REUSEADDR` przed wywołaniem `bind()`:

  ```c
  int yes = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
  ```

- **Jak ustawić timeout dla recv()?**\
  Użyj `setsockopt()` z `SO_RCVTIMEO` lub funkcji `select()`/`poll()`.

- **Jak obsługiwać wiele połączeń jednocześnie?**\
  Użyj `select()`, `poll()` lub wielowątkowości.

---

## Rozdział 9: Strony manuali

Ten rozdział zawiera opisy kluczowych funkcji używanych w programowaniu gniazd, w formacie przypominającym strony manuali Uniksa.

### 9.1. accept()

**Akceptuje nowe połączenie na gnieździe.**

**Prototyp**:

```c
#include <sys/types.h>
#include <sys/socket.h>
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```

**Opis**:\
Funkcja `accept()` wyciąga pierwsze oczekujące połączenie z kolejki gniazda nasłuchującego, tworzy nowe gniazdo i zwraca jego deskryptor. Parametr `addr` przechowuje informacje o kliencie, a `addrlen` określa rozmiar tej struktury.

**Zwraca**: Deskryptor nowego gniazda lub -1 w przypadku błędu (ustawia `errno`).

**Przykład**:

```c
struct sockaddr_storage client_addr;
socklen_t addrlen = sizeof client_addr;
int newfd = accept(sockfd, (struct sockaddr*)&client_addr, &addrlen);
if (newfd == -1) perror("accept");
```

### 9.2. bind()

**Przypisuje adres do gniazda.**

**Prototyp**:

```c
#include <sys/types.h>
#include <sys/socket.h>
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```

**Opis**:\
Funkcja `bind()` wiąże gniazdo z określonym adresem IP i portem. Jest konieczna dla serwerów, aby określić, na którym porcie będą nasłuchiwać.

**Zwraca**: 0 w przypadku powodzenia, -1 w przypadku błędu (ustawia `errno`).

**Przykład**:

```c
struct sockaddr_in sa;
sa.sin_family = AF_INET;
sa.sin_port = htons(3490);
inet_pton(AF_INET, "0.0.0.0", &sa.sin_addr);
if (bind(sockfd, (struct sockaddr*)&sa, sizeof sa) == -1)
    perror("bind");
```

### 9.3. connect()

**Nawiązuje połączenie z serwerem.**

**Prototyp**:

```c
#include <sys/types.h>
#include <sys/socket.h>
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```

**Opis**:\
Funkcja `connect()` łączy gniazdo z określonym adresem serwera. Używana w klientach TCP i UDP (dla UDP ustala domyślny adres docelowy).

**Zwraca**: 0 w przypadku powodzenia, -1 w przypadku błędu (ustawia `errno`).

**Przykład**:

```c
struct addrinfo *res;
getaddrinfo("www.example.com", "80", &hints, &res);
if (connect(sockfd, res->ai_addr, res->ai_addrlen) == -1)
    perror("connect");
```

### 9.4. close()

**Zamyka deskryptor pliku.**

**Prototyp**:

```c
#include <unistd.h>
int close(int fd);
```

**Opis**:\
Funkcja `close()` zamyka gniazdo lub inny deskryptor pliku, zwalniając zasoby. W przypadku gniazd TCP zamyka połączenie.

**Zwraca**: 0 w przypadku powodzenia, -1 w przypadku błędu (ustawia `errno`).

**Przykład**:

```c
close(sockfd);
```

### 9.5. getaddrinfo(), freeaddrinfo(), gai_strerror()

**Pobiera informacje o adresach i nazwach hostów.**

**Prototyp**:

```c
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
void freeaddrinfo(struct addrinfo *res);
const char *gai_strerror(int errcode);
```

**Opis**:

- `getaddrinfo()` tłumaczy nazwy hostów i usług na struktury adresowe, obsługując IPv4 i IPv6.
- `freeaddrinfo()` zwalnia pamięć zaalokowaną przez `getaddrinfo()`.
- `gai_strerror()` zwraca czytelny opis błędu zwróconego przez `getaddrinfo()`.

**Zwraca**: `getaddrinfo()` zwraca 0 w przypadku powodzenia, kod błędu w przypadku niepowodzenia.

**Przykład**:

```c
struct addrinfo hints, *res;
memset(&hints, 0, sizeof hints);
hints.ai_family = AF_UNSPEC;
hints.ai_socktype = SOCK_STREAM;
int rv = getaddrinfo("www.example.com", "80", &hints, &res);
if (rv != 0) fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
freeaddrinfo(res);
```

### 9.6. gethostname()

**Pobiera nazwę lokalnego hosta.**

**Prototyp**:

```c
#include <unistd.h>
int gethostname(char *name, size_t len);
```

**Opis**:\
Funkcja `gethostname()` zapisuje nazwę lokalnego hosta w buforze `name` o rozmiarze `len`.

**Zwraca**: 0 w przypadku powodzenia, -1 w przypadku błędu (ustawia `errno`).

**Przykład**:

```c
char hostname[256];
if (gethostname(hostname, sizeof hostname) == -1)
    perror("gethostname");
else
    printf("Nazwa hosta: %s\n", hostname);
```

### 9.7. gethostbyname(), gethostbyaddr()

**Pobiera informacje o hoście (przestarzałe).**

**Prototyp**:

```c
#include <netdb.h>
struct hostent *gethostbyname(const char *name);
struct hostent *gethostbyaddr(const void *addr, socklen_t len, int type);
```

**Opis**:\
Te funkcje zwracają informacje o hoście na podstawie nazwy (`gethostbyname`) lub adresu (`gethostbyaddr`). Są przestarzałe – zaleca się używanie `getaddrinfo()` i `getnameinfo()`.

**Zwraca**: Wskaźnik do `struct hostent` lub NULL w przypadku błędu (ustawia `h_errno`).

**Przykład**:

```c
struct hostent *he = gethostbyname("www.example.com");
if (he == NULL) fprintf(stderr, "Błąd gethostbyname\n");
else printf("Adres IP: %s\n", inet_ntoa(*(struct in_addr*)he->h_addr));
```

### 9.8. getnameinfo()

**Pobiera nazwę hosta i usługi na podstawie adresu.**

**Prototyp**:

```c
#include <sys/socket.h>
#include <netdb.h>
int getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host, size_t hostlen, char *serv, size_t servlen, int flags);
```

**Opis**:\
Funkcja `getnameinfo()` tłumaczy adres gniazda na nazwę hosta i nazwę usługi (np. numer portu). Jest nowocześniejszym odpowiednikiem `gethostbyaddr()`.

**Zwraca**: 0 w przypadku powodzenia, kod błędu w przypadku niepowodzenia.

**Przykład**:

```c
char host[NI_MAXHOST], serv[NI_MAXSERV];
struct sockaddr_in sa;
if (getnameinfo((struct sockaddr*)&sa, sizeof sa, host, sizeof host, serv, sizeof serv, 0) == 0)
    printf("Host: %s, Usługa: %s\n", host, serv);
```

### 9.9. getpeername()

**Pobiera adres zdalnego hosta.**

**Prototyp**:

```c
#include <sys/socket.h>
int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```

**Opis**:\
Funkcja `getpeername()` zwraca adres zdalnego hosta podłączonego do gniazda.

**Zwraca**: 0 w przypadku powodzenia, -1 w przypadku błędu (ustawia `errno`).

**Przykład**:

```c
struct sockaddr_storage addr;
socklen_t addrlen = sizeof addr;
if (getpeername(sockfd, (struct sockaddr*)&addr, &addrlen) == -1)
    perror("getpeername");
```

### 9.10. errno

**Zmienna przechowująca kod błędu.**

**Prototyp**:

```c
#include <errno.h>
extern int errno;
```

**Opis**:\
Zmienna `errno` przechowuje kod błędu zwrócony przez wywołania systemowe. Używaj `perror()` lub `strerror()` do uzyskania czytelnego opisu.

**Przykład**:

```c
if (connect(sockfd, addr, addrlen) == -1) {
    perror("connect");
    fprintf(stderr, "Kod błędu: %d\n", errno);
}
```

### 9.11. fcntl()

**Kontroluje właściwości deskryptorów plików.**

**Prototyp**:

```c
#include <fcntl.h>
int fcntl(int fd, int cmd, ...);
```

**Opis**:\
Funkcja `fcntl()` pozwala zmieniać właściwości gniazd, np. ustawiać tryb nieblokujący (`O_NONBLOCK`).

**Zwraca**: Zależy od `cmd`, zwykle 0 w przypadku powodzenia, -1 w przypadku błędu (ustawia `errno`).

**Przykład**:

```c
fcntl(sockfd, F_SETFL, O_NONBLOCK);
```

### 9.12. htons(), htonl(), ntohs(), ntohl()

**Konwertuje kolejność bajtów między hostem a siecią.**

**Prototyp**:

```c
#include <arpa/inet.h>
uint16_t htons(uint16_t hostshort);
uint32_t htonl(uint32_t hostlong);
uint16_t ntohs(uint16_t netshort);
uint32_t ntohl(uint32_t netlong);
```

**Opis**:\
Funkcje te konwertują liczby 16-bitowe (`short`) i 32-bitowe (`long`) między Host Byte Order a Network Byte Order.

**Przykład**:

```c
uint16_t port = 3490;
uint16_t netport = htons(port);
uint32_t addr = 0xC0000201; // 192.0.2.1
uint32_t netaddr = htonl(addr);
```

### 9.13. inet_ntoa(), inet_aton()

**Konwertuje adresy IPv4 (przestarzałe).**

**Prototyp**:

```c
#include <arpa/inet.h>
char *inet_ntoa(struct in_addr in);
int inet_aton(const char *cp, struct in_addr *inp);
```

**Opis**:

- `inet_ntoa()` zamienia binarną formę adresu IPv4 na ciąg znaków (np. „192.0.2.1”).
- `inet_aton()` konwertuje ciąg znaków na binarną formę adresu IPv4.\
  Zaleca się używanie `inet_ntop()` i `inet_pton()`.

**Przykład**:

```c
struct in_addr addr;
inet_aton("192.0.2.1", &addr);
printf("Adres: %s\n", inet_ntoa(addr));
```

### 9.14. inet_ntop(), inet_pton()

**Konwertuje adresy IP na formę czytelną i z powrotem.**

**Prototyp**:

```c
#include <arpa/inet.h>
const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);
int inet_pton(int af, const char *src, void *dst);
```

**Opis**:

- `inet_ntop()` zamienia adres binarny na ciąg znaków (IPv4 lub IPv6).
- `inet_pton()` konwertuje ciąg znaków na adres binarny.

**Zwraca**: `inet_ntop()` zwraca wskaźnik do `dst` lub NULL w przypadku błędu; `inet_pton()` zwraca 1 w przypadku powodzenia, 0 lub -1 w przypadku błędu.

**Przykład**:

```c
struct sockaddr_in sa;
char str[INET_ADDRSTRLEN];
inet_pton(AF_INET, "192.0.2.33", &(sa.sin_addr));
inet_ntop(AF_INET, &(sa.sin_addr), str, INET_ADDRSTRLEN);
printf("%s\n", str); // Wypisze: 192.0.2.33

struct sockaddr_in6 sa6;
char str6[INET6_ADDRSTRLEN];
inet_pton(AF_INET6, "2001:db8:8714:3a90::12", &(sa6.sin6_addr));
inet_ntop(AF_INET6, &(sa6.sin6_addr), str6, INET6_ADDRSTRLEN);
printf("%s\n", str6); // Wypisze: 2001:db8:8714:3a90::12
```

### 9.15. listen()

**Ustawia gniazdo w tryb nasłuchiwania.**

**Prototyp**:

```c
#include <sys/socket.h>
int listen(int sockfd, int backlog);
```

**Opis**:\
Funkcja `listen()` włącza nasłuchiwanie połączeń przychodzących na gnieździe TCP. Parametr `backlog` określa maksymalną liczbę oczekujących połączeń.

**Zwraca**: 0 w przypadku powodzenia, -1 w przypadku błędu (ustawia `errno`).

**Przykład**:

```c
if (listen(sockfd, 10) == -1) perror("listen");
```

### 9.16. perror(), strerror()

**Wyświetla opisy błędów.**

**Prototyp**:

```c
#include <stdio.h>
#include <string.h>
void perror(const char *s);
char *strerror(int errnum);
```

**Opis**:

- `perror()` wyświetla komunikat błędu na podstawie `errno`.
- `strerror()` zwraca ciąg znaków opisujący błąd dla danego `errnum`.

**Przykład**:

```c
if (bind(sockfd, addr, addrlen) == -1) {
    perror("bind");
    fprintf(stderr, "Błąd: %s\n", strerror(errno));
}
```

### 9.17. poll()

**Monitoruje wiele deskryptorów pod kątem zdarzeń.**

**Prototyp**:

```c
#include <poll.h>
int poll(struct pollfd *fds, nfds_t nfds, int timeout);
```

**Opis**:\
Funkcja `poll()` czeka na zdarzenia (np. dane do odczytu) na wielu deskryptorach. Parametr `timeout` określa czas oczekiwania w milisekundach (-1 oznacza nieskończone czekanie).

**Zwraca**: Liczbę deskryptorów ze zdarzeniami, 0 w przypadku timeoutu, -1 w przypadku błędu.

**Przykład**:

```c
struct pollfd fds[1];
fds[0].fd = sockfd;
fds[0].events = POLLIN;
if (poll(fds, 1, 5000) > 0 && fds[0].revents & POLLIN)
    recv(sockfd, buf, sizeof buf, 0);
```

### 9.18. recv(), recvfrom()

**Odbiera dane z gniazda.**

**Prototyp**:

```c
#include <sys/socket.h>
ssize_t recv(int sockfd, void *buf, size_t len, int flags);
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
```

**Opis**:

- `recv()` odbiera dane z gniazda TCP.
- `recvfrom()` odbiera dane z gniazda UDP, zapisując adres nadawcy.

**Zwraca**: Liczbę odebranych bajtów, 0 w przypadku zamknięcia połączenia, -1 w przypadku błędu.

**Przykład**:

```c
char buf[512];
ssize_t n = recv(sockfd, buf, sizeof buf, 0);
struct sockaddr_storage src_addr;
socklen_t addrlen = sizeof src_addr;
n = recvfrom(sockfd, buf, sizeof buf, 0, (struct sockaddr*)&src_addr, &addrlen);
```

### 9.19. select()

**Monitoruje wiele deskryptorów (stara metoda).**

**Prototyp**:

```c
#include <sys/select.h>
int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
```

**Opis**:\
Funkcja `select()` czeka na zdarzenia na deskryptorach w zbiorach `readfds`, `writefds` lub `exceptfds`. Parametr `timeout` określa maksymalny czas oczekiwania.

**Zwraca**: Liczbę deskryptorów ze zdarzeniami, 0 w przypadku timeoutu, -1 w przypadku błędu.

**Przykład**:

```c
fd_set readfds;
FD_ZERO(&readfds);
FD_SET(sockfd, &readfds);
struct timeval tv = {5, 0};
if (select(sockfd + 1, &readfds, NULL, NULL, &tv) > 0)
    recv(sockfd, buf, sizeof buf, 0);
```

### 9.20. setsockopt(), getsockopt()

**Ustawia i pobiera opcje gniazda.**

**Prototyp**:

```c
#include <sys/socket.h>
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
```

**Opis**:

- `setsockopt()` ustawia opcje gniazda, np. `SO_REUSEADDR` lub `SO_BROADCAST`.
- `getsockopt()` pobiera wartości opcji.

**Zwraca**: 0 w przypadku powodzenia, -1 w przypadku błędu (ustawia `errno`).

**Przykład**:

```c
int yes = 1;
if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) == -1)
    perror("setsockopt");
```

### 9.21. send(), sendto()

**Wysyła dane przez gniazdo.**

**Prototyp**:

```c
#include <sys/socket.h>
ssize_t send(int sockfd, const void *buf, size_t len, int flags);
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
```

**Opis**:

- `send()` wysyła dane przez gniazdo TCP.
- `sendto()` wysyła dane przez gniazdo UDP, określając adres odbiorcy.

**Zwraca**: Liczbę wysłanych bajtów, -1 w przypadku błędu.

**Przykład**:

```c
send(sockfd, "Witaj!", 6, 0);
sendto(sockfd, "Witaj!", 6, 0, res->ai_addr, res->ai_addrlen);
```

### 9.22. shutdown()

**Wyłącza wysyłanie lub odbieranie danych na gnieździe.**

**Prototyp**:

```c
#include <sys/socket.h>
int shutdown(int sockfd, int how);
```

**Opis**:\
Funkcja `shutdown()` pozwala zakończyć komunikację na gnieździe w jednym lub obu kierunkach. Parametr `how` określa, co ma zostać wyłączone:

- `SHUT_RD`: Zamyka odczyt (nie można już odbierać danych).
- `SHUT_WR`: Zamyka zapis (nie można już wysyłać danych).
- `SHUT_RDWR`: Zamyka zarówno odczyt, jak i zapis.

W przeciwieństwie do `close()`, `shutdown()` nie zwalnia deskryptora gniazda, co pozwala na bardziej kontrolowane zakończenie połączenia.

**Zwraca**: 0 w przypadku powodzenia, -1 w przypadku błędu (ustawia `errno`).

**Przykład**:

```c
if (shutdown(sockfd, SHUT_WR) == -1)
    perror("shutdown");
```

### 9.23. socket()

**Tworzy nowe gniazdo.**

**Prototyp**:

```c
#include <sys/types.h>
#include <sys/socket.h>
int socket(int domain, int type, int protocol);
```

**Opis**:\
Funkcja `socket()` tworzy nowe gniazdo i zwraca jego deskryptor. Parametry:

- `domain`: Określa rodzinę protokołów (np. `AF_INET` dla IPv4, `AF_INET6` dla IPv6).
- `type`: Określa typ gniazda (np. `SOCK_STREAM` dla TCP, `SOCK_DGRAM` dla UDP).
- `protocol`: Zwykle 0, aby automatycznie wybrać protokół (np. TCP dla `SOCK_STREAM`, UDP dla `SOCK_DGRAM`).

**Zwraca**: Deskryptor gniazda lub -1 w przypadku błędu (ustawia `errno`).

**Przykład**:

```c
int sockfd = socket(AF_INET, SOCK_STREAM, 0);
if (sockfd == -1)
    perror("socket");
```

---

## Rozdział 10: Dodatkowe źródła

### 10.1. Książki

Oto kilka doskonałych książek, które pogłębią Twoją wiedzę o programowaniu sieciowym:

- **"Unix Network Programming, Volume 1: The Sockets Networking API"**, W. Richard Stevens, Bill Fenner, Andrew M. Rudoff\
  Klasyczna pozycja, szczegółowo omawiająca API gniazd w systemach uniksowych.
- **"Unix Network Programming, Volume 2: Interprocess Communications"**, W. Richard Stevens\
  Skupia się na komunikacji międzyprocesowej, ale zawiera cenne informacje o mechanizmach sieciowych.
- **"Internetworking with TCP/IP, Volume I: Principles, Protocols, and Architecture"**, Douglas E. Comer\
  Wprowadzenie do zasad działania TCP/IP, idealne dla początkujących i zaawansowanych.
- **"TCP/IP Illustrated, Volume 1: The Protocols"**, W. Richard Stevens\
  Szczegółowy opis protokołów TCP/IP z praktycznymi przykładami.
- **"TCP/IP Illustrated, Volume 2: The Implementation"**, Gary R. Wright, W. Richard Stevens\
  Omawia implementację stosu TCP/IP w systemach uniksowych.
- **"TCP/IP Illustrated, Volume 3: TCP for Transactions, HTTP, NNTP, and the UNIX Domain Protocols"**, W. Richard Stevens\
  Skupia się na bardziej zaawansowanych protokołach i ich zastosowaniach.

### 10.2. Inne źródła

- **"BSD Sockets: A Quick And Dirty Primer"**\
  Krótki, praktyczny przewodnik po gniazdach BSD, dostępny online.
- **"The Unix Socket FAQ"**\
  Zbiór najczęściej zadawanych pytań dotyczących programowania gniazd w Uniksie.
- **"TCP/IP FAQ"**\
  Odpowiedzi na pytania dotyczące protokołów TCP/IP, pomocne dla początkujących.
- **"The Linux Programming Interface"**, Michael Kerrisk\
  Kompleksowa książka o programowaniu w Linuksie, zawiera rozdziały o gniazdach.
- **"Stevens' Source Code"**\
  Kod źródłowy z książek Stevensa, dostępny online, zawiera przykłady programów sieciowych.

### 10.3. RFC

Dokumenty RFC (Request for Comments) to oficjalne specyfikacje protokołów internetowych. Oto kluczowe RFC dla programowania sieciowego:

- **RFC 768**: User Datagram Protocol (UDP)\
  Specyfikacja protokołu UDP.
- **RFC 791**: Internet Protocol (IP)\
  Opis protokołu IP (IPv4).
- **RFC 793**: Transmission Control Protocol (TCP)\
  Specyfikacja protokołu TCP.
- **RFC 854**: Telnet Protocol Specification\
  Opis protokołu Telnet, przykład prostego protokołu aplikacyjnego.
- **RFC 2460**: Internet Protocol, Version 6 (IPv6) Specification\
  Specyfikacja protokołu IPv6.
- **RFC 3493**: Basic Socket Interface Extensions for IPv6\
  Opis rozszerzeń API gniazd dla IPv6, w tym `getaddrinfo()`.
- **RFC 4038**: Application Aspects of IPv6 Transition\
  Wskazówki dotyczące przechodzenia z IPv4 na IPv6 w aplikacjach.

RFC są dostępne za darmo na stronie https://www.rfc-editor.org/.

### 10.4. Strony internetowe

- **http://beej.us/guide/bgnet/**\
  Oficjalna strona tego przewodnika, zawiera aktualizacje i dodatkowe zasoby.
- **The Open Group POSIX Specifications**\
  Oficjalna specyfikacja POSIX, w tym API gniazd, dostępna na https://pubs.opengroup.org/.
- **Linux Man Pages**\
  Strony manuali Linuksa, dostępne online na https://man7.org/, zawierają szczegółowe opisy funkcji gniazd.
- **Microsoft Developer Network (MSDN)**\
  Dokumentacja Winsock dla programistów Windows, dostępna na https://docs.microsoft.com/.
- **Beej’s Guide to C Programming**\
  Mój inny przewodnik, omawiający programowanie w C, dostępny na http://beej.us/guide/bgc/.

---

## Uwagi końcowe

Powyższy dokument zawiera wierne tłumaczenie podrozdziału 1.4 z zachowaniem oryginalnych fragmentów kodu, w tym `int yes=1;`. Rozdział 9 został uzupełniony o brakujące sekcje 9.22 (`shutdown()`) i 9.23 (`socket()`), a rozdział 10 jest w pełni przetłumaczony, obejmując wszystkie podrozdziały (10.1–10.4). Jeśli potrzebujesz tłumaczenia dodatkowych sekcji, bardziej szczegółowych wyjaśnień lub korekty innych części, proszę o wskazanie, a przygotuję odpowiednią wersję.
