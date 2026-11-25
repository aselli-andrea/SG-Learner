# SG-Learner

**Security group a minimo privilegio appresi dal traffico reale in OpenStack**

SG-Learner è un plugin DevStack che osserva il traffico reale delle VM di
OpenStack e propone, per ciascuna, il security group minimo che lo consente.
Dopo l'approvazione dell'amministratore applica il nuovo gruppo al posto di
quello originale e, da quel momento, segnala il traffico bloccato come
anomalia.

Nei cloud reali i security group nascono spesso troppo permissivi ("apri
tutto, poi si vedrà") e nessuno li restringe più, perché non è chiaro quali
porte servano davvero. SG-Learner ricava questa informazione dai log di rete,
ossia da ciò che le VM fanno davvero, e lascia all'amministratore solo la
decisione finale.

Un esempio, quello della demo. Tre VM formano un'applicazione, in cui un client
(vm-app) chiama un web server (vm-web), che a sua volta usa un database
(vm-db). All'inizio hanno tutte un security group che apre ogni porta, quindi
anche il client può collegarsi direttamente al database, anche se non ne ha
mai bisogno. Se il client venisse attaccato, l'attaccante arriverebbe ai dati,
ed è il cosiddetto movimento laterale. Dopo l'osservazione, SG-Learner dà a ogni
VM un gruppo con le sole connessioni che ha usato davvero. L'applicazione
continua a funzionare, ma il client non raggiunge più il database, e tutte
le altre porte, che prima erano aperte senza che nessuno le usasse vengono bloccate.

### Cosa aggiunge a OpenStack

OpenStack fornisce il meccanismo ma non la decisione. Ci sono i security
group, ma le regole le scrive l'amministratore a mano, senza sapere quali
porte usa davvero una VM. C'è il Packet Logging, ma produce righe grezze,
una per pacchetto, che non diventano mai regole. SG-Learner collega le due
cose:

- **trasforma il traffico in regole**, cioè dalle righe del log ricava una
  proposta di gruppo a minimo privilegio, che OpenStack non fa;
- **scrive regole adatte al cloud**, non si limita a copiare gli indirizzi
  visti nel log. Quando una VM parla con un'altra VM, la regola indica il
  gruppo di quella VM (`remote_group`) e non il suo IP, così continua a
  funzionare anche se l'IP cambia. Quando una VM riceve connessioni da molti
  indirizzi esterni diversi, capisce che è un servizio pubblico e apre a
  tutti (`0.0.0.0/0`); se gli indirizzi sono pochi, apre solo a quelli
  (`/32`). Aggiunge infine le regole per il DHCP e il metadata, che la VM
  usa all'avvio e che durante l'osservazione di solito non si vedono;
- **applica in modo sicuro e reversibile**. Non modifica i security group
  che la VM aveva (per esempio `demo-open`), che spesso sono condivisi con
  altre VM: crea invece un gruppo nuovo, solo per quella VM, e lo mette al
  posto dei vecchi. I gruppi originali restano intatti e salvati, quindi se
  qualcosa non va basta `sg-learner rollback` per rimetterli e tornare alla
  situazione di prima;
- **mantiene le regole nel tempo**. Dopo l'applicazione, qualcuno potrebbe
  cambiare le cose a mano da Horizon, e in OpenStack quella modifica
  resterebbe lì senza che nessuno la noti. SG-Learner invece ogni 30 secondi
  confronta ogni VM applicata con la proposta approvata e annulla le
  differenze: se nel gruppo `learned-<vm>` compare una regola in più (per
  esempio la porta 3306 aperta a mano), la cancella; se sulla porta della VM
  compare un security group in più (per esempio `demo-open` rimesso a mano),
  lo toglie dalla porta, senza cancellarlo da Neutron. Non importa chi abbia
  fatto la modifica: vale solo la proposta approvata. Chi vuole davvero una
  regola nuova deve passare da SG-Learner, accettando un'anomalia o
  ripetendo l'osservazione, così ogni cambiamento resta approvato;
- **sorveglia il traffico bloccato**, classificandolo in `scan`, `candidate`
  e `alert`, mentre in OpenStack un pacchetto bloccato sparisce senza
  lasciare traccia;
- **si integra con OpenStack**, come plugin DevStack, con un'API registrata
  in Keystone e riservata agli amministratori, e senza installare niente
  nelle VM.

In pratica, senza SG-Learner l'amministratore deve scrivere le regole a
mano e stabilire da solo, spesso senza dati certi, quali porte servono. Con SG-Learner le regole gliele
propone il plugin, ricavandole dal traffico che le VM hanno fatto davvero, e
a lui resta solo da controllarle e nel caso approvarle.

---

## Indice

1. [Come funziona](#1-come-funziona)
2. [Ambiente utilizzato](#2-ambiente-utilizzato)
3. [Installazione](#3-installazione)
4. [Uso](#4-uso)
5. [Configurazione](#5-configurazione)
6. [Demo con tre VM](#6-demo-con-tre-vm)
7. [Scelte di sicurezza](#7-scelte-di-sicurezza)
8. [Struttura della repo e test](#8-struttura-della-repo-e-test)

---

## 1. Come funziona

### Architettura

SG-Learner è un servizio Python distribuito come **plugin DevStack**: si
attiva con una riga `enable_plugin` nel `local.conf`, e il plugin fa da solo
l'installazione e l'avvio. Usa solo le **API pubbliche di OpenStack**
(tramite openstacksdk), senza modificarne il codice.

**I processi sono due**, che condividono lo stesso database SQLite:

- il **servizio** `devstack@sg-learner` (`service.py`) lavora di
  continuo: legge il log di OVN, genera le proposte alla scadenza, applica e
  sorveglia, usando i moduli `follower.py`, `collector.py`, `store.py`,
  `lifecycle.py`, `enforcer.py` e `detector.py`;
- l'**API** `devstack@sg-learner-api` (`api.py`) è l'unico punto
  d'accesso dell'amministratore: riceve i comandi e scrive le decisioni nel
  database.

La **CLI** `sg-learner` (`cli.py`) è un client dell'API e non apre
mai il database.
Tutte le chiamate a OpenStack passano da un solo modulo (`cloud.py`), e tutto
l'accesso al database da un altro (`store.py`).

**Come comunicano le parti.** L'amministratore lancia un comando
`sg-learner`. La CLI chiede un token a Keystone e manda la richiesta all'API,
che verifica il token, controlla il ruolo admin e scrive la decisione nel
database SQLite. Il servizio, che gira di continuo, legge dal database le
decisioni e dal log di `ovn-controller` il traffico delle VM. Poi parla con
OpenStack tramite openstacksdk: con Nova per l'elenco delle VM, con Neutron
per security group, porte e network log. Neutron, attraverso ML2/OVN, applica
le regole alle VM e scrive le righe di log che il servizio legge.

**Interconnessione con OpenStack**

- **Keystone** autentica l'utente di servizio `sg-learner`, verifica i token
  dell'API e la registra nel catalogo, dove la CLI la trova.
- **Nova** fornisce l'elenco delle VM di tutti i progetti.
- **Neutron** espone le API dei security group, delle porte e dei network log
  (Packet Logging).
- **ML2/OVN** traduce i security group in ACL e scrive il log che SG-Learner
  legge.

### Il funzionamento, passo per passo

Il percorso dei dati, dall'alto in basso:

1. **OpenStack produce i dati.** Con il Packet Logging di Neutron attivo,
   `ovn-controller` scrive una riga `acl_log` per ogni pacchetto che passa dai
   security group sotto osservazione. Una riga `acl_log` è una voce del file
   di log che descrive un pacchetto controllato dal firewall: chi l'ha
   mandato, a chi, su quale porta e se è passato o è stato bloccato. I dati
   quindi non sono i pacchetti, ma le righe di log che li descrivono. Il processo, in ordine:
   1. **Neutron decide le regole.** I security group sono il firewall delle
      VM e li gestisce Neutron, il servizio di rete di OpenStack. Neutron
      però non tocca direttamente i pacchetti, e per applicare le regole usa un "motore" di
      rete, scelto tramite **ML2**, il sistema a plugin di Neutron. In
      DevStack il motore predefinito è **OVN** (per questo si parla di
      backend ML2/OVN); SG-Learner funziona solo con OVN, perché legge il
      suo file di log.
   2. **OVN trasforma le regole in ACL.** Ogni regola di un security group,
      per esempio "apri la porta 80", diventa una **ACL**, cioè una regola del
      firewall di OVN.
   3. **`ovn-controller` applica le ACL.** È il programma di OVN che gira sul
      nodo, e ogni pacchetto delle VM passa da lui, che lo confronta con le
      ACL e lo fa passare o lo blocca.
   4. **Il Packet Logging fa scrivere un registro.** È una funzione di
      Neutron che, accesa su un security group, fa scrivere a `ovn-controller`,
      nel suo file `/var/log/ovn/ovn-controller.log`, una riga per ogni
      pacchetto controllato dalle ACL di quel gruppo. La riga si chiama
      `acl_log` ("registro di una ACL", non crea nessuna regola) e dice chi
      parla con chi (IP, porte, protocollo) e se il pacchetto è passato
      (`allow`) o è stato bloccato (`drop`). Per esempio *172.24.4.1 verso
      vm-web, porta 80, allow*.
   5. **SG-Learner legge il registro.** Normalmente `ovn-controller` controlla
      i pacchetti senza scrivere niente, ed è SG-Learner che, con `learn`,
      accende il Packet Logging sui security group della VM, e da quel
      momento legge quel file.

   È un approccio **agentless** (senza agenti), perché SG-Learner vede il traffico
   delle VM senza installare niente dentro le VM. Quindi funziona con
   qualunque VM e sistema operativo, anche quelle dei clienti a cui
   l'amministratore del cloud non ha accesso; non serve entrare nelle VM né
   modificarle; e una VM compromessa non può falsificare i dati, perché il
   registro lo scrive OpenStack, fuori dalla VM.
2. **Raccolta**: il LogFollower legge le righe nuove, il Flow Collector le
   trasforma in connessioni e il Flow Store le salva in SQLite.
   - Il **LogFollower** ogni 2 secondi legge solo le righe aggiunte al file.
     Ricorda fin dove è arrivato e salva il punto nel database, così se il
     servizio si riavvia riprende da lì, senza rileggere le righe già lette e
     senza saltare quelle nuove. Regge anche la **rotazione** del log. Per non
     farlo crescere all'infinito, il sistema periodicamente rinomina il file
     (per esempio in `ovn-controller.log.1`) e ne apre uno nuovo vuoto con il
     nome originale. Il LogFollower se ne accorge, finisce di leggere le
     ultime righe del file vecchio e poi passa al nuovo, così nessuna
     connessione va persa. I file vecchi li gestisce il sistema, che di solito
     ne tiene alcuni e cancella i più vecchi.
   - Il **Flow Collector** passa dai pacchetti alle connessioni, perché una SSH
     sono decine di pacchetti, ma è una sola connessione verso la porta 22.
     Per questo tiene solo il primo pacchetto (il SYN per il TCP, la echo
     request per il ping, il datagramma per l'UDP) e scarta le risposte, che
     non servono perché i security group sono *stateful*. Inoltre non conta
     due volte lo stesso tentativo, quindi se un pacchetto con la stessa firma
     (stessi IP e stesse porte) arriva di nuovo entro 60 secondi, per esempio
     un SYN rimandato perché non è arrivata risposta, lo considera una ripetizione. Le
     connessioni nuove invece si contano tutte, perché il client usa ogni
     volta una porta di origine diversa.
   - Il **Flow Store** non salva ogni connessione, ma un riepilogo. Per
     costruire una regola servono solo questi campi: VM, direzione,
     protocollo, porta, altro capo e verdetto. Le connessioni con gli stessi
     campi finiscono nella stessa riga, che aumenta un contatore, per cui 5 chiamate
     da vm-app a vm-web sulla 80 sono una riga con contatore 5, non cinque
     righe. Così il database resta piccolo, e il contatore serve dopo al
     Policy Engine, per esempio per segnare una regola come "poco osservata".
3. **Decisione**: alla fine dell'osservazione il Policy Engine calcola la
   proposta; l'amministratore la approva con la CLI `sg-learner`, che è un
   client dell'API REST di SG-Learner.
   - Il **Policy Engine** parte alla scadenza della finestra, o subito con
     `proposal generate`, e trasforma le osservazioni della VM in regole di
     security group. Una regola di Neutron dice quattro cose: la
     **direzione** (in ingresso o in uscita), il **protocollo** (TCP, UDP,
     ICMP), la **porta** e **l'altro capo**, cioè con chi la VM può
     comunicare, ovvero chi può collegarsi a lei (in ingresso) o verso chi può
     collegarsi lei (in uscita). L'altro capo si può indicare con un
     intervallo di indirizzi IP o con un altro security group.
   - Prima raggruppa le connessioni per servizio (stessa direzione,
     protocollo e porta), per esempio tutte le connessioni in ingresso sulla
     TCP 80 di vm-web. Poi, per ogni servizio, sceglie come scrivere l'altro
     capo, in tre casi:
     - **un'altra VM del cloud** → si usa il suo **gruppo** (`remote_group`),
       non il suo IP, per esempio *vm-db accetta la 5432 dal gruppo di vm-web*. La regola
       segue la VM anche se cambia indirizzo, e non apre niente a chi prende
       un IP vicino;
     - **almeno 5 IP esterni diversi** → è un servizio pubblico, e si apre a
       tutti con `0.0.0.0/0`, per esempio *vm-web accetta la 80 da chiunque*;
     - **pochi IP esterni** → un `/32` per ognuno, cioè solo quell'indirizzo,
       per esempio *vm-web accetta la SSH solo da 172.24.4.1*, l'host dell'amministratore.

     Gli indirizzi esterni diventano quindi un `/32` ciascuno oppure, con
     almeno 5, `0.0.0.0/0`, senza raggruppamenti intermedi (per esempio più
     IP vicini riuniti in un `/24`).
   - Il traffico bloccato non diventa mai una regola. DHCP e metadata non si
     ricavano dal traffico ma si aggiungono sempre, come **regole di base**,
     perché servono alla VM per avviarsi anche se durante l'osservazione non
     si vedono. Una regola vista meno di 3 volte viene segnata come **poco
     osservata**, perché l'amministratore la controlli.
   - L'**amministratore** legge la proposta e la approva o la rifiuta. La CLI
     manda la richiesta all'API, che registra solo la decisione nel
     database, e su Neutron non cambia ancora niente.
   - La decisione è **per VM**. Ogni VM ha una sua proposta, che diventerà
     un solo gruppo `learned-<vm>` con più regole, e si approva o si rifiuta
     tutta insieme: si può approvare vm-web e rifiutare vm-db, ma non
     scegliere le singole regole di vm-web. La proposta descrive il
     comportamento della VM nel suo insieme; se una regola non convince, si
     rifiuta la proposta e si osserva di nuovo.
4. **Applicazione (solo dopo l'approvazione)**: quando l'amministratore ha
   approvato, l'Enforcer crea il gruppo `learned-<vm>` su Neutron, lo
   assegna alla porta della VM e attiva il logging dei soli pacchetti
   bloccati. Finché la proposta non è approvata, su Neutron non cambia
   niente; se viene rifiutata, non cambia mai.
   - **Quando parte.** `approve` registra solo la decisione, poi ogni 30 secondi
     il servizio cerca le VM approvate, e l'Enforcer le applica. Al massimo
     dopo 30 secondi, quindi, la proposta è attiva.
   - **Il nuovo gruppo.** L'Enforcer crea su Neutron il security group
     `learned-<vm>` (per esempio `learned-vm-web`). Neutron mette in ogni
     gruppo nuovo due regole che permettono tutto in uscita, e l'Enforcer le
     cancella subito, poi crea le sole regole approvate più quelle di base
     (DHCP e metadata). Nella descrizione del gruppo scrive il segno
     `[sg-learner:<ID della VM>]`, che lo lega alla VM.
   - **Le regole verso altre VM.** Se una regola dice "accetta dal gruppo di
     vm-app", quel gruppo deve esistere e vm-app deve farne parte. L'Enforcer
     lo crea (vuoto, se la proposta di vm-app non è ancora applicata) e lo
     aggiunge alla porta di vm-app, così la regola funziona subito.
   - **La sostituzione sulla porta.** Ogni VM è collegata alla rete da una
     **porta** di Neutron, ed è alla porta che si assegnano i security group.
     L'Enforcer toglie dalla porta i gruppi originali (per esempio
     `demo-open`) e mette `learned-vm-web`. I gruppi originali non vengono né
     modificati né cancellati, perché possono servire ad altre VM. Restano
     salvati nel database, e il rollback li rimette.
   - **Il log dei pacchetti bloccati.** Sul nuovo gruppo accende un Packet
     Logging solo per i pacchetti bloccati (`DROP`). Il traffico permesso
     ormai è noto; interessa solo quello che il gruppo ferma, ed è quello che
     analizza l'Anomaly Detector. La VM passa in `enforcing`.
   - **La riconciliazione.** Ogni 30 secondi l'Enforcer ricontrolla le VM
     applicate e corregge le differenze, cioè cancella una regola aggiunta a mano
     al gruppo, toglie dalla porta un gruppo rimesso a mano (per esempio
     `demo-open`), ricrea il log `DROP` se è stato cancellato. Se tutto è in
     ordine non fa niente, quindi ripeterlo non fa danni (è *idempotente*).
     La proposta approvata è l'unica fonte di verità. Le correzioni
     riguardano solo le VM in `enforcing`: nessun gruppo viene cancellato da
     Neutron (al massimo viene tolto da una porta) e le VM che SG-Learner non
     segue non vengono toccate. Toglie anche dal database le VM che non
     esistono più in Nova.

5. **Sorveglianza**: l'Anomaly Detector classifica il traffico bloccato e lo
   presenta all'amministratore, che decide se trasformarlo in una regola.
   Prima dell'applicazione SG-Learner osserva tutto il traffico per
   **imparare**; dopo osserva solo quello bloccato per **sorvegliare**.
   - **Il traffico normale passa e basta.** Le connessioni previste dal
     gruppo appreso (per esempio vm-app verso vm-web sulla 80) passano senza
     essere registrate, perché ormai sono note.
   - **Il traffico bloccato viene registrato.** Sul gruppo appreso è acceso
     il log `DROP`, quindi ogni pacchetto che il gruppo ferma finisce nel file di
     OVN, e SG-Learner lo salva come per l'osservazione.
   - **Ogni 30 secondi l'Anomaly Detector** legge i pacchetti bloccati dal
     momento dell'applicazione e li divide in tre tipi:
     - `scan`: uno stesso IP prova almeno 5 porte diverse. È il segno di
       qualcuno che cerca porte aperte, per esempio una VM compromessa;
     - `candidate`: lo stesso flusso viene bloccato almeno 5 volte. Potrebbe
       essere un servizio legittimo non visto durante l'osservazione;
     - `alert`: un tentativo isolato.
   - **L'amministratore decide.** Vede le anomalie con `sg-learner alerts
     list` e per ognuna sceglie:
     - `accept`: l'anomalia diventa una regola. La VM torna per un attimo in
       `approved`, l'Enforcer applica la regola nuova e la VM torna in
       `enforcing`;
     - `dismiss`: l'anomalia viene ignorata e resta nello storico.

     Una `scan` si può solo ignorare, perché SG-Learner non apre mai una porta da
     solo, altrimenti un attaccante potrebbe raggirarlo insistendo con i
     tentativi.
   - **Intanto la riconciliazione continua**, e ogni 30 secondi l'Enforcer
     rimette gruppo e porta come nella proposta approvata.
   - **Le regole che non servono più non vengono rimosse in automatico.**
     Dopo l'applicazione si registra solo il traffico bloccato, per non
     appesantire `ovn-controller`, quindi SG-Learner non sa se una regola
     permessa viene ancora usata. Per toglierle si ripete l'osservazione
     (rollback e `learn`): la nuova proposta contiene solo ciò che è stato
     usato e, una volta approvata, sostituisce la vecchia.
   - **Come si esce.** La VM resta in `enforcing` finché l'amministratore non
     fa `sg-learner rollback`, che rimette i gruppi originali, spegne il log
     `DROP` e porta la VM in `proposed`. Da lì si può riapprovare, oppure
     rifare `learn` per una nuova osservazione.

### Gli stati di una VM

Ogni VM seguita da SG-Learner è sempre in uno **stato**, che dice a che
punto è. Il percorso normale è questo:

```
learning  ──►  proposed  ──►  approved  ──►  enforcing
 osserva       proposta       approvata      gruppo appreso
               pronta         dall'admin     applicato
```

- **`learning`**: SG-Learner sta osservando la VM e registra tutto il suo
  traffico. Finisce da solo alla scadenza della finestra (per esempio 30
  minuti), oppure subito con `sg-learner proposal generate`.
- **`proposed`**: la proposta di gruppo minimo è pronta e aspetta la
  decisione dell'amministratore. Con `proposal approve` si va avanti; con
  `proposal reject` la proposta viene scartata (stato `rejected`).
- **`approved`**: l'amministratore ha approvato, ma su Neutron non è ancora
  cambiato niente. Entro 30 secondi il servizio applica la proposta.
- **`enforcing`**: la VM usa il gruppo `learned-<vm>` al posto di quelli
  originali. Da qui SG-Learner registra solo il traffico bloccato, per
  segnalare le anomalie.

Poi ci sono i passaggi per tornare indietro:

- **`rollback`** (da `enforcing`): rimette i gruppi originali e riporta la VM
  in `proposed`. La proposta non si perde e si può riapprovare.
- **`rejected`**: la proposta è stata rifiutata. La VM non è mai stata
  toccata e tiene i suoi gruppi originali; per una nuova proposta si rifà
  `learn`.
- **Un'anomalia accettata** (da `enforcing`): la nuova regola entra nella
  proposta e la VM torna in `approved`, così il servizio la applica.
- **Una nuova osservazione** con `learn` si può avviare da ogni stato tranne
  `approved` ed `enforcing`, perché con il gruppo appreso sulla porta, il traffico
  nuovo verrebbe bloccato e non entrerebbe mai nella proposta. Prima si fa
  `rollback`.

### I componenti

Ognuno è descritto sopra:

- **LogFollower**, **Flow Collector** e **Flow Store** raccolgono il
  traffico (passo 2);
- **Policy Engine** calcola la proposta (passo 3);
- **Enforcer** applica e mantiene le proposte, ed esegue il rollback (passo 4);
- **Anomaly Detector** classifica il traffico bloccato (passo 5);
- la **CLI `sg-learner`** invia i comandi dell'amministratore all'**API REST**
  (Flask, porta 9797), che li esegue (vedi Architettura).

### Perché SQLite

Il database è un file SQLite in `/opt/stack/data/sg-learner`. Lo usano due
processi, il servizio e l'API, che possono aprirlo nello stesso momento.
SQLite lo permette, con una regola precisa, cioè **tante letture insieme, una sola
scrittura alla volta**.

- **Letture e scritture insieme.** `store.py` attiva la modalità WAL, in cui chi
  legge non blocca chi scrive e viceversa, quindi l'API legge lo stato delle
  VM mentre il servizio salva le connessioni.
- **Due scritture insieme.** SQLite le mette in fila, e la seconda aspetta che
  la prima finisca (fino a 5 secondi) e poi scrive.
- **Due modifiche alla stessa VM.** Il lock non basta, perché il servizio potrebbe
  salvare una copia della VM letta prima di una modifica fatta dall'API. Per
  questo ogni VM ha un `updated_at`, e un salvataggio basato su una copia
  vecchia viene rifiutato (`ConflictError`), e chi lo riceve rilegge e
  riprova.

SQLite è stato scelto perché non richiede un server da installare e
configurare, fa già parte di Python, salva tutto in un solo file che
sopravvive ai riavvii, e regge senza problemi il carico del progetto, cioè due
processi sulla stessa macchina e poche scritture al secondo. Il limite è che
è un file locale, quindi con più nodi di calcolo servirebbe un database in rete,
come il MySQL che OpenStack usa già.

---

## 2. Ambiente utilizzato

Il progetto è stato sviluppato e provato su questa configurazione:

| | |
|---|---|
| Macchina fisica | Mac con processore Apple Silicon (ARM) |
| Virtualizzazione | VMware Fusion |
| Macchina DevStack | VM Ubuntu 24.04 (aarch64) con 12 GB di RAM, 6 vCPU, 20 GB di disco e 2 GB di swap |
| OpenStack | DevStack su nodo singolo, backend di rete ML2/OVN (il default di DevStack) |
| Hypervisor delle istanze | QEMU in emulazione: su Apple Silicon non c'è virtualizzazione annidata |
| Istanze di prova | CirrOS, flavor `m1.tiny`, rete `private`, floating IP sulla rete `public` |
| Linguaggio | Python 3.12 nel venv di DevStack, con openstacksdk |
| Database | SQLite (un file in `/opt/stack/data/sg-learner`) |

Per l'emulazione QEMU su ARM servono le righe indicate nella sezione ARM di
[`devstack/local.conf.sample`](devstack/local.conf.sample). SG-Learner legge
i log delle ACL di OVN, quindi richiede ML2/OVN e non funziona con ML2/OVS o
Linux bridge.

---

## 3. Installazione

Come utente `stack` (preparato come indica la
[guida di DevStack](https://docs.openstack.org/devstack/latest/)):

1. **Clonare DevStack:**

   ```bash
   git clone https://opendev.org/openstack/devstack
   cd devstack
   ```

2. **Scrivere `local.conf`** con il plugin SG-Learner:

   ```bash
   cat > local.conf <<'EOF'
   [[local|localrc]]
   ADMIN_PASSWORD=secret
   DATABASE_PASSWORD=$ADMIN_PASSWORD
   RABBIT_PASSWORD=$ADMIN_PASSWORD
   SERVICE_PASSWORD=$ADMIN_PASSWORD
   enable_plugin sg-learner https://github.com/aselli-andrea/SG-Learner main
   EOF
   ```

   Su un Mac Apple Silicon (ARM, senza virtualizzazione annidata) vanno
   aggiunte le righe ARM di
   [`devstack/local.conf.sample`](devstack/local.conf.sample).

3. **Installare:**

   ```bash
   ./stack.sh
   ```

Il plugin ([`devstack/plugin.sh`](devstack/plugin.sh)) fa da solo tutto
quello che serve:

| Fase di DevStack | Cosa fa il plugin |
|---|---|
| `stack install` | installa il pacchetto Python `sg-learner` |
| `stack post-config` | attiva il Packet Logging di Neutron (service plugin `log`, `rate_limit` e `burst_limit`); crea l'utente di servizio `sg-learner` in Keystone e registra l'API nel catalogo; concede all'utente `stack` la lettura del log di OVN con una ACL; scrive `/etc/sg-learner/sg-learner.conf`, compresa la sezione `[keystone_authtoken]` per l'API |
| `stack extra` | avvia il servizio `devstack@sg-learner` e l'API `devstack@sg-learner-api` (systemd) |
| `unstack` / `clean` | ferma servizio e API / cancella configurazione e dati |

Per verificare: `sudo journalctl -u devstack@sg-learner -n 20 --no-pager`
deve mostrare l'autenticazione su Keystone, `Logging API attiva` e
`Log OVN leggibile`; `sudo journalctl -u devstack@sg-learner-api -n 5
--no-pager` deve mostrare `API di SG-Learner ... in ascolto su 0.0.0.0:9797`.

L'installazione è stata verificata da zero, con `./unstack.sh` e poi
`./stack.sh` con il plugin scaricato da GitHub e la sola riga
`enable_plugin` nel `local.conf`, senza altri passaggi a mano. Anche l'API
REST è configurata, registrata nel catalogo di Keystone e avviata dal
plugin.

Dopo un riavvio della macchina DevStack conviene lanciare, come utente
`stack`, [`tools/post-boot.sh`](tools/post-boot.sh), che aspetta la
sincronizzazione dell'orologio, ricollega `br-ex` e riavvia i servizi
nell'ordine giusto (1-3 minuti, da non interrompere).

---

## 4. Uso

Il comando `sg-learner` usa le credenziali dell'amministratore di openrc ed
è installato nel venv di DevStack, quindi si aggiunge il venv al `PATH`:

```bash
source /opt/stack/devstack/openrc admin admin
export PATH=/opt/stack/data/venv/bin:$PATH
```

Ogni comando è una richiesta all'API. Se l'API non risponde, la CLI stampa
"API di SG-Learner non raggiungibile"; se l'utente non ha il ruolo `admin`,
stampa "serve il ruolo admin".

| Comando | Effetto |
|---|---|
| `sg-learner learn <vm> --duration 30m` | avvia l'osservazione della VM per la durata indicata (`90s`, `30m`, `2h`, `1d`; senza `--duration` un'ora) e attiva il logging sui suoi security group; se la proposta è applicata, prima `rollback` |
| `sg-learner status` | stato di tutte le VM seguite |
| `sg-learner proposal generate <vm>` | chiude subito l'osservazione e calcola la proposta |
| `sg-learner proposal show <vm>` | mostra la proposta |
| `sg-learner proposal approve <vm>` | approva: l'Enforcer la applica entro 30 secondi |
| `sg-learner proposal reject <vm>` | rifiuta: la VM resta con i gruppi originali, la proposta resta come storico |
| `sg-learner alerts list [<vm>] [--all]` | anomalie aperte (con `--all` anche quelle chiuse) |
| `sg-learner alerts accept <id>` | trasforma un'anomalia in regola (non vale per le scansioni) |
| `sg-learner alerts dismiss <id>` | chiude un'anomalia, che resta nello storico |
| `sg-learner rollback <vm>` | rimette i security group originali |

Esempio reale, la proposta per il web server della demo:

```
$ sg-learner proposal show vm-web
Proposta per vm-web (10.0.0.36) (23 connessioni osservate)
  = regole di base, sempre presenti: egress udp/67 verso 0.0.0.0/0, egress tcp/80 verso 169.254.169.254/32
  + ingress tcp/22 da 172.24.4.1/32                    3 conn.
  + ingress tcp/80 da 0.0.0.0/0                        5 conn.
  + ingress tcp/80 da gruppo vm:vm-app                 5 conn.
  + egress tcp/5432 verso gruppo vm:vm-db              5 conn.
  + egress udp/53 verso gruppo vm:vm-db                5 conn.
```

E le anomalie dopo l'applicazione, con vm-app che scansiona il database:

```
$ sg-learner alerts list
  ID VM             TIPO       TENTATIVI ULTIMO       DESCRIZIONE
   2 vm-db          alert              1 24/11 22:55  ingress tcp/5432 da 172.24.4.1
   3 vm-web         alert              1 24/11 22:55  ingress icmp da 172.24.4.1
   5 vm-app         scan               7 24/11 22:55  egress verso 10.0.0.20: 7 porte diverse provate
```

### API REST

La CLI usa questa API, che si può chiamare anche direttamente via HTTP
sulla porta 9797, con risposte in JSON. L'API è registrata nel catalogo di Keystone (`openstack catalog
list`, servizio `sg-learner`). Ogni richiesta deve portare un token Keystone
nell'header `X-Auth-Token`. Senza token la risposta è 401; con un token
senza ruolo `admin` è 403.

```bash
source /opt/stack/devstack/openrc admin admin
TOKEN=$(openstack token issue -f value -c id)
API=http://192.168.203.128:9797/v1

curl -s -H "X-Auth-Token: $TOKEN" $API/vms
curl -s -H "X-Auth-Token: $TOKEN" -X POST $API/vms/vm-web/proposal/approve
```

| Metodo e percorso | Effetto |
|---|---|
| `GET /v1/vms` | stato di tutte le VM seguite |
| `GET /v1/vms/<vm>` | una VM, con la proposta |
| `POST /v1/vms/<vm>/learn` | avvia l'osservazione (corpo facoltativo `{"duration": "30m"}`) |
| `POST /v1/vms/<vm>/proposal/generate` | chiude subito l'osservazione e calcola la proposta |
| `POST /v1/vms/<vm>/proposal/approve` | approva: l'Enforcer la applica entro 30 secondi |
| `POST /v1/vms/<vm>/proposal/reject` | rifiuta la proposta |
| `POST /v1/vms/<vm>/rollback` | rimette i security group originali |
| `GET /v1/alerts[?vm=<vm>&all=true]` | anomalie aperte (con `all=true` anche quelle chiuse) |
| `POST /v1/alerts/<id>/accept` | trasforma un'anomalia in regola |
| `POST /v1/alerts/<id>/dismiss` | chiude un'anomalia |

Gli errori hanno un codice HTTP e un messaggio: 404 se la VM o l'anomalia
non esiste, 409 se l'operazione non è valida nello stato attuale (ad esempio
approvare durante l'osservazione), 400 se la durata non è valida. Un errore
interno resta un 500 e non viene scambiato per una VM inesistente.

---

## 5. Configurazione

Il plugin scrive `/etc/sg-learner/sg-learner.conf`:

```ini
[DEFAULT]
# secondi tra un giro e l'altro del servizio
interval = 30
ovn_log_file = /var/log/ovn/ovn-controller.log
# cartella del database SQLite
data_dir = /opt/stack/data/sg-learner

[openstack]
# credenziali dell'utente di servizio sg-learner in Keystone
auth_url = ...
username = sg-learner
...

[api]
# indirizzo e porta dell'API REST
host = 0.0.0.0
port = 9797

[keystone_authtoken]
# opzioni di keystonemiddleware, scritte da DevStack
# (configure_keystone_authtoken_middleware): verifica dei token dell'API
www_authenticate_uri = ...
auth_type = password
...
```

Le soglie hanno valori predefiniti e si possono cambiare aggiungendo queste
sezioni al file. Poi si riavviano sia il servizio sia l'API, perché le
soglie servono a entrambi (l'API genera le proposte richieste dalla CLI):
`sudo systemctl restart devstack@sg-learner devstack@sg-learner-api`.

```ini
[engine]
# con almeno questi IP esterni distinti la regola usa 0.0.0.0/0
public_threshold = 5
# connessioni minime perché un flusso diventi una regola
min_connections = 1
# sotto questa soglia la regola è marcata "poco osservata"
low_confidence_below = 3

[detector]
# con almeno questi tentativi bloccati un flusso è "candidate"
candidate_threshold = 5
# un IP che prova almeno queste porte diverse è una "scan"
scan_ports = 5
```

Dal `local.conf` si possono invece cambiare percorsi, intervallo e limiti
del Packet Logging (variabili `SG_LEARNER_*` in
[`devstack/settings`](devstack/settings)).

I limiti del Packet Logging sono `rate_limit = 500` e `burst_limit = 250`,
più alti dei minimi della documentazione di Neutron (100 e 25). OVN registra
ogni pacchetto di una connessione, non solo il primo, quindi con i minimi alcune
connessioni ravvicinate superano il picco e il limitatore può scartare il SYN,
e una connessione TCP senza SYN non viene contata. Il valore attivo si vede
con `sudo ovn-nbctl meter-list` (meter `acl_log_meter`).

---

## 6. Demo con tre VM

La demo riproduce un'applicazione a tre livelli partita con un gruppo
permissivo, `demo-open`, che apre in ingresso il ping e tutte le porte TCP e UDP.

| VM | Ruolo | Servizio simulato |
|---|---|---|
| `vm-web` | web server | porta 80 |
| `vm-db` | database | porta 5432 |
| `vm-app` | client dell'applicazione | nessuno |

I servizi sono simulati con `nc` di BusyBox (CirrOS), per esempio
`nc -lk -p 80 -e /bin/hostname` risponde a ogni connessione con il nome della
VM.

La demo si fa con un solo comando, sulla macchina DevStack come utente
`stack`, dopo:

```bash
source /opt/stack/devstack/openrc admin admin
export PATH=/opt/stack/data/venv/bin:$PATH   # il comando sta nel venv di DevStack
```

Lo script è [`tools/demo.sh`](tools/demo.sh):

```bash
tools/demo.sh setup      # crea demo-open, le tre VM e i floating IP, avvia i servizi
tools/demo.sh run        # la demo completa, passo per passo
tools/demo.sh test       # solo la verifica: cosa passa e cosa no
tools/demo.sh services   # dopo un riavvio: riavvia i servizi finti
tools/demo.sh clean      # cancella VM e gruppi della demo e svuota il database di SG-Learner
```

`run` esegue tutto il ciclo in sette passi: punto di partenza, osservazione,
traffico reale dell'applicazione, proposte, approvazione con verifica,
Anomaly Detector (vm-app scansiona il database) e rollback. Stampa ogni
comando prima di eseguirlo, si ferma tra un passo e l'altro (con
`tools/demo.sh --no-pause run` non si ferma) e chiede conferma per le
decisioni dell'amministratore (approvazione, rollback). Se trova VM già
applicate da una prova precedente, al primo passo fa da solo il rollback. Per
ripartire da zero: `clean`, `setup`, `test` (con `demo-open` le sei prove
passano tutte).

**Risultato** (verificato dal vivo, anche su un'installazione da zero)

| Flusso | Con `demo-open` | Con i gruppi appresi | Regola che lo decide |
|---|---|---|---|
| vm-app → vm-web:80 | passa | **passa** | ingress tcp/80 dal gruppo `learned-vm-app` |
| vm-web → vm-db:5432 | passa | **passa** | ingress tcp/5432 dal gruppo `learned-vm-web` |
| esterno → vm-web:80 | passa | **passa** | `0.0.0.0/0`: 5 IP esterni distinti osservati |
| vm-app → vm-db:5432 | passa | **bloccato** | nessuna: vm-app non ha mai parlato con il database |
| esterno → vm-db:5432 | passa | **bloccato** | nessuna |
| ping a vm-web | passa | **bloccato** | nessuna |

Dopo l'applicazione, la scansione di vm-app verso il database compare in
`sg-learner alerts list` come anomalia di tipo `scan`.

---

## 7. Scelte di sicurezza

- **Approvazione obbligatoria.** SG-Learner propone, ma non applica nulla
  senza `proposal approve`. Già all'avvio dell'osservazione (`learn`) si
  segna nel database quali security group ha la VM (per esempio
  `demo-open`), così dopo l'applicazione il rollback sa esattamente quali
  gruppi rimettere sulla porta.
- **SG-Learner non allarga mai le regole da solo.** Un flusso bloccato che
  si ripete diventa al massimo una `candidate`, che l'amministratore può
  accettare. Se le regole si aprissero da sole dopo qualche tentativo, un
  attaccante potrebbe raggirare il firewall semplicemente insistendo finché
  la porta non si apre.
- **Una scansione non diventa mai una regola.** Se uno stesso IP prova
  almeno 5 porte diverse, l'anomalia è una `scan` e si può solo ignorare.
- **Regole di base.** Una VM, per funzionare, ha bisogno di due servizi che
  usa soprattutto all'avvio, cioè il **DHCP**, che le assegna l'indirizzo IP, e
  il **metadata**, da cui scarica la sua configurazione. Durante
  l'osservazione la VM è già accesa, quindi questo traffico di solito non si
  vede e non entrerebbe nella proposta. Ma senza quelle regole, al primo
  riavvio la VM non riotterrebbe l'IP e resterebbe isolata. Per questo
  l'Enforcer aggiunge sempre le due regole `egress udp/67` (DHCP) ed
  `egress tcp/80` verso `169.254.169.254/32` (metadata).
- **Regole tra VM per gruppo, non per IP.** Il traffico tra VM diventa
  `remote_group`, così la regola segue la VM anche se cambia indirizzo e non
  apre nulla a chi prende un IP vicino.
- **Gruppi nuovi vuoti.** Quando si crea un security group, Neutron ci mette
  da solo due regole che permettono **tutto il traffico in uscita** (una per
  IPv4, una per IPv6). Se restassero, la VM potrebbe collegarsi verso
  qualunque destinazione, e metà del lavoro sarebbe annullato. SG-Learner le
  cancella subito dopo aver creato il gruppo, così un gruppo `learned-`
  contiene solo le regole approvate e quelle di base.
- **Rollback sicuro.** Il rollback di una VM toglie il suo gruppo appreso
  dalla porta, tranne quando altre VM lo citano nelle loro
  regole. Per esempio vm-web accetta la porta 80 "dal gruppo `learned-vm-app`".
  Se il rollback di vm-app togliesse `learned-vm-app` dalla sua porta, vm-web
  non riconoscerebbe più vm-app e la bloccherebbe, e l'applicazione si
  romperebbe. Quindi sulla porta di vm-app restano sia i gruppi originali
  sia `learned-vm-app`. Non toglie niente a vm-app, perché le regole dei
  gruppi si sommano, e vm-web continua ad accettarne il traffico.
- **Gruppi riconosciuti dalla VM, non dal nome.** Ogni gruppo `learned-`
  ha nella descrizione il segno `[sg-learner:<ID della VM>]`. Un gruppo
  creato a mano con un nome simile, o rimasto da una VM cancellata con lo
  stesso nome, non viene mai scambiato per un gruppo appreso.
- **Nuova osservazione solo dopo il rollback.** Per imparare, SG-Learner
  deve vedere il traffico della VM così com'è. Se la proposta è applicata,
  sulla porta c'è il gruppo appreso, che blocca tutto ciò che non conosce,
  quindi un servizio nuovo verrebbe solo bloccato, e la nuova proposta non lo
  conterrebbe mai. Per questo `learn` su una VM applicata viene rifiutato,
  e prima si fa `rollback`, che rimette i gruppi originali, e poi si osserva
  di nuovo.
- **Modifiche concorrenti.** Servizio e API sono processi separati che usano
  lo stesso database, quindi una VM letta viene salvata solo se nessuno l'ha
  cambiata nel frattempo, così un `accept` non viene sovrascritto dalla
  riconciliazione.
- **API protetta da Keystone.** Davanti all'API c'è `keystonemiddleware`,
  lo stesso componente dei servizi OpenStack, che verifica il token con
  Keystone e toglie dalle richieste gli header di identità inviati dal
  client, così nessuno può fingersi amministratore. L'API accetta solo il
  ruolo `admin`.
- **Privilegi.** L'utente di servizio ha il ruolo `admin` (serve per vedere
  le VM di tutti i progetti); la configurazione con la password è leggibile
  solo da `stack` (permessi 640); il log di OVN è accessibile in sola
  lettura tramite ACL.

### Limiti noti

Sono limiti conosciuti, lasciati apposta fuori da questa versione.

- **SG-Learner impara da quello che vede.** Durante l'osservazione considera
  legittimo tutto il traffico, quindi se in quella finestra il client si collegasse
  al database, la connessione finirebbe nella proposta. Non può distinguere
  da solo il traffico buono da quello cattivo, come ogni sistema che impara
  dal comportamento. Il progetto lo gestisce in tre modi:
  - **decide l'amministratore**: nella proposta comparirebbe una riga come
    `ingress tcp/5432 da gruppo vm:vm-app`, e chi conosce l'applicazione la
    riconosce come sbagliata e rifiuta la proposta, o rifà l'osservazione;
  - **l'osservazione va fatta in un periodo di funzionamento normale**, per
    esempio dopo il deploy, non mentre è in corso un attacco;
  - **dopo l'applicazione non impara più**: il traffico nuovo viene solo
    bloccato e segnalato, mai aggiunto da solo. Un attaccante arrivato dopo
    non può raggirare il firewall insistendo, e al massimo crea una
    `candidate`, che l'amministratore deve accettare a mano, e una scansione
    non si può accettare mai.
- **Un solo nodo e una porta per VM.** Il servizio legge il log di OVN della
  macchina su cui gira, quindi vede solo le VM di quel nodo, e con più nodi di
  calcolo servirebbe un lettore su ognuno. Se una VM ha più schede di rete,
  SG-Learner segue solo la prima.
- **Rollback nello stesso momento della riconciliazione.** Due processi
  possono lavorare sulla stessa VM insieme, cioè il servizio, che ogni 30 secondi
  rimette a posto i gruppi delle VM applicate, e l'API, che esegue il
  rollback quando l'amministratore lo chiede. Di solito non si incontrano,
  ma se capita nello stesso istante può succedere questo:
  1. il servizio legge dal database vm-web, che risulta applicata;
  2. un attimo dopo l'amministratore fa `rollback vm-web`, e l'API rimette
     `demo-open` sulla porta e nel database segna vm-web come non più
     applicata;
  3. il servizio, che sta ancora lavorando con quello che aveva letto al
     passo 1, crede che vm-web sia applicata e rimette `learned-vm-web` sulla
     porta.

  Il risultato è che il database dice che vm-web non è applicata, ma sulla porta c'è
  il gruppo appreso, e nessuno lo ricontrollerà più. È raro, perché le due
  cose devono capitare nello stesso momento, e si vede con `openstack server
  show vm-web`. Per sistemare si riapprova la proposta e si rifà il
  rollback. La soluzione definitiva è far eseguire il rollback al servizio,
  come già succede per l'applicazione, così l'API registrerebbe solo la
  richiesta, e un solo processo modificherebbe le porte.
- **Connessioni perse se il database è occupato.** A ogni giro il servizio
  legge le righe nuove del log, segna fin dove è arrivato e poi salva le
  connessioni. Se proprio in quel momento il database è occupato da un'altra
  scrittura per più di 5 secondi, il salvataggio fallisce, ma il segno è già
  stato spostato avanti, quindi quelle righe non verranno rilette, e le connessioni
  di quel giro (due secondi di traffico) si perdono. La soluzione è salvare
  il segno e le connessioni insieme, nella stessa operazione.
- **I log dell'osservazione restano accesi.** Per osservare una VM, `learn`
  accende il Packet Logging (evento `ALL`) sui suoi security group. Ma il
  log si accende sul **gruppo**, non sulla singola VM, quindi se vm-web, vm-db e
  vm-app hanno tutte `demo-open`, c'è un solo log su `demo-open`, che
  registra il traffico di tutte e tre. Quando finisce l'osservazione di
  vm-web, SG-Learner non può spegnerlo, perché vm-db e vm-app potrebbero
  essere ancora in osservazione e spegnendolo smetterebbe di vederle. Per
  spegnerlo al momento giusto dovrebbe tenere il conto di quali VM lo usano
  ancora, e spegnerlo quando non ne resta nessuna. Oggi quindi il log resta
  acceso. Non è un problema di sicurezza, perché l'unico effetto è qualche riga in
  più nel log di OVN.
- **IPv6 supportato solo in parte.** SG-Learner legge anche il traffico IPv6
  e crea regole IPv6 corrette (`::/0`, `/128`). Le regole di base però sono
  solo IPv4, quindi una VM che prende l'indirizzo IPv6 con DHCPv6 potrebbe
  perderlo al riavvio. L'IPv6 è coperto dai test, ma la demo usa solo
  traffico IPv4.

---

## 8. Struttura della repo e test

| File | Cosa fa |
|---|---|
| `devstack/plugin.sh` | il plugin DevStack: a ogni fase di `stack.sh` installa il pacchetto, attiva il Packet Logging di Neutron, crea l'utente di servizio, concede la lettura del log di OVN, scrive la configurazione e avvia il servizio |
| `devstack/settings` | variabili del plugin (percorsi, intervallo, limiti del Packet Logging), sovrascrivibili da `local.conf` |
| `devstack/local.conf.sample` | `local.conf` di esempio, con le righe per host ARM |
| `sg_learner/service.py` | il servizio `devstack@sg-learner`: si collega a OpenStack (riprovando se non è ancora pronto), legge il log ogni 2 secondi e ogni 30 fa avanzare ciclo di vita, Enforcer e Anomaly Detector |
| `sg_learner/follower.py` | legge le righe nuove del log di `ovn-controller`: righe incomplete, rotazione, troncamento; salva la posizione per riprendere dopo un riavvio |
| `sg_learner/collector.py` | interpreta le righe `acl_log` e tiene solo l'inizio delle connessioni, scartando ritrasmissioni e risposte UDP |
| `sg_learner/store.py` | database SQLite: connessioni osservate, VM seguite con il loro stato, anomalie, posizione nel log; un salvataggio non sovrascrive le modifiche fatte nel frattempo da un altro processo |
| `sg_learner/engine.py` | Policy Engine: dalle osservazioni alla proposta (`remote_group` tra VM, `0.0.0.0/0` o `/32` per gli esterni, regole di base, DHCP e metadata esclusi) |
| `sg_learner/lifecycle.py` | stati delle VM: avvio dell'osservazione, proposta alla scadenza o su richiesta, approvazione o rifiuto |
| `sg_learner/enforcer.py` | crea e mantiene i gruppi `learned-<vm>` su Neutron, li assegna alle porte, annulla le modifiche manuali, ricrea il log DROP, toglie le VM cancellate, esegue il rollback |
| `sg_learner/detector.py` | Anomaly Detector: classifica il traffico bloccato in `alert`, `candidate` e `scan`; gestisce `accept` e `dismiss` |
| `sg_learner/cloud.py` | unico punto di accesso a Nova e Neutron (openstacksdk), comprese le chiamate REST al Packet Logging |
| `sg_learner/cli.py` | il comando `sg-learner` dell'amministratore: un client dell'API, con il token Keystone di openrc |
| `sg_learner/api.py` | l'API REST (Flask), unico punto d'accesso dell'amministratore, protetta da `keystonemiddleware`; servizio `devstack@sg-learner-api` |
| `sg_learner/__init__.py` | versione del pacchetto |
| `tools/demo.sh` | demo con tre VM: `setup`, `services`, `run`, `test`, `clean` (che svuota anche il database) |
| `tools/post-boot.sh` | dopo un riavvio della macchina DevStack: attende l'orologio, ricollega `br-ex`, riavvia i servizi in ordine, fa riaprire il log a OVN |
| `tests/test_*.py` | 103 test automatici (tabella sotto) |
| `tests/fixtures/ovn_acl_log_sample.txt` | righe reali del log di OVN usate dai test |
| `setup.py`, `setup.cfg` | pacchetto Python: metadati, dipendenze e i tre comandi `sg-learner`, `sg-learner-service` e `sg-learner-api` |
| `requirements.txt`, `test-requirements.txt` | dipendenze: openstacksdk, Flask e keystonemiddleware per il programma, pytest per i test |

I test non richiedono OpenStack, perché usano righe reali del log di OVN e un
Neutron simulato.

```bash
/opt/stack/data/venv/bin/python -m pytest -q tests/
```

| File | Test | Cosa verifica |
|---|---|---|
| `test_collector.py` | 14 | lettura delle righe reali di OVN, inizio delle connessioni, ritrasmissioni, risposte UDP |
| `test_store.py` | 10 | conteggi, filtri, persistenza, salvataggi concorrenti, cancellazione dei soli DROP e delle VM |
| `test_follower.py` | 11 | righe nuove e incomplete, rotazione, troncamento, ripresa dopo un riavvio |
| `test_engine.py` | 14 | soglia pubblica, `remote_group`, regole di base, IPv6, parametri per Neutron |
| `test_lifecycle.py` | 15 | transizioni di stato, rifiuto della proposta, comandi della CLI, credenziali mancanti, ripresa all'avvio, solo traffico della finestra, errori isolati per VM |
| `test_enforcer.py` | 19 | regole approvate, idempotenza, riconciliazione, `remote_group`, rollback, `learn` dopo rollback, VM cancellate, errori isolati, gruppi riconosciuti dal segno, log DROP ricreato |
| `test_detector.py` | 13 | alert, candidate e scan, accept e dismiss, comandi `alerts`, soglie `[engine]` in accept |
| `test_api.py` | 7 | 401 senza token e 403 senza ruolo admin, ciclo completo via HTTP, codici di errore, errori interni come 500, anomalie, applicazione da parte dell'Enforcer |
