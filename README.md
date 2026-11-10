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
decisione finale. In una demo con tre VM partite con un gruppo aperto, il
gruppo appreso lascia passare tutto il traffico dell'applicazione e blocca il
resto, compreso il movimento laterale da una VM compromessa verso il database.

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

Il percorso dei dati, dall'alto in basso:

1. **OpenStack** produce i dati: con il Packet Logging di Neutron attivo,
   `ovn-controller` scrive una riga `acl_log` per ogni pacchetto che passa dai
   security group sotto osservazione.
2. **Raccolta**: il LogFollower legge le righe nuove, il Flow Collector le
   trasforma in connessioni e il Flow Store le salva in SQLite.
3. **Decisione**: alla fine dell'osservazione il Policy Engine calcola la
   proposta; l'amministratore la approva con la CLI `sg-learner`.
4. **Applicazione**: l'Enforcer crea il gruppo `learned-<vm>` su Neutron, lo
   assegna alla porta della VM e attiva il logging dei soli pacchetti
   bloccati.
5. **Sorveglianza**: l'Anomaly Detector classifica il traffico bloccato e lo
   presenta all'amministratore, che decide se trasformarlo in una regola.

Tutte le chiamate a Nova e Neutron passano da un solo modulo (`cloud.py`), e
tutto l'accesso al database da un altro (`store.py`).

Ogni VM seguita da SG-Learner attraversa quattro stati:

| Stato | Cosa succede | Come si passa allo stato successivo |
|---|---|---|
| `learning` | Il Packet Logging di Neutron registra **tutto** il traffico dei security group della VM; SG-Learner salva le connessioni | alla scadenza della finestra di osservazione, oppure con `proposal generate` |
| `proposed` | Il Policy Engine ha calcolato il gruppo minimo; la proposta attende l'amministratore | `proposal approve` |
| `approved` | La proposta è approvata | l'Enforcer la applica entro 30 secondi |
| `enforcing` | La VM usa il gruppo `learned-<vm>`; il logging registra solo il traffico **bloccato**, analizzato dall'Anomaly Detector | `rollback` riporta in `proposed`; un'anomalia accettata riporta in `approved` |

I componenti:

- **LogFollower** legge in continuo il log di `ovn-controller`, come `tail -f`.
  Riprende dal punto giusto dopo un riavvio e regge la rotazione del log.
- **Flow Collector** trasforma le righe `acl_log` (una per pacchetto) in
  connessioni: riconosce l'inizio di una connessione (SYN, echo request,
  datagramma UDP) e scarta le ritrasmissioni e le risposte UDP.
- **Flow Store** salva le connessioni in SQLite, aggregate per VM, direzione,
  protocollo, porta di servizio, altro capo e verdetto, insieme allo stato
  delle VM e alle anomalie.
- **Policy Engine** calcola la proposta: solo il traffico consentito diventa
  una regola; il traffico verso altre VM diventa una regola `remote_group`;
  se gli IP esterni distinti sono almeno 5 la regola usa `0.0.0.0/0`,
  altrimenti un `/32` per IP.
- **Enforcer** crea il gruppo `learned-<vm>`, ne allinea le regole alla
  proposta, lo assegna alla porta al posto dei gruppi originali e attiva il
  logging DROP. Ogni 30 secondi ricontrolla e corregge eventuali modifiche
  manuali.
- **Anomaly Detector** classifica il traffico bloccato delle VM applicate in
  `alert`, `candidate` o `scan` (vedi [Scelte di sicurezza](#7-scelte-di-sicurezza)).
- **CLI `sg-learner`** è l'interfaccia dell'amministratore; il servizio
  `devstack@sg-learner` fa tutto il resto.

### Cosa succede passo passo

L'esempio segue una sola VM, `vm-web`, dall'avvio dell'osservazione al
rollback. La CLI scrive le decisioni dell'amministratore nel database; il
servizio `devstack@sg-learner`, che gira di continuo, fa il resto.

1. **`sg-learner learn vm-web --duration 10m`**
   - La CLI trova la VM su Nova e la sua porta su Neutron, con i security
     group assegnati (es. `demo-open`).
   - Su ogni gruppo crea un network log di Neutron con evento `ALL`; se ne
     esiste già uno lo riusa.
   - Cancella dal database le osservazioni vecchie della VM, la salva in
     stato `learning` con la scadenza e ricorda i gruppi originali per il
     rollback.
2. **Durante l'osservazione**
   - Per ogni pacchetto che attraversa il gruppo, OVN scrive una riga
     `acl_log` in `/var/log/ovn/ovn-controller.log`.
   - Ogni 2 secondi il servizio legge le righe nuove (LogFollower).
   - Il Flow Collector tiene solo l'inizio delle connessioni (SYN, echo
     request, primo datagramma UDP) e scarta le ripetizioni.
   - Il Flow Store aggiunge 1 al contatore della combinazione VM, direzione,
     protocollo, porta, altro capo e verdetto.
3. **Fine dell'osservazione**
   - Alla scadenza, oppure subito con `proposal generate`, il Policy Engine
     legge le osservazioni della VM.
   - Scarta DHCP e metadata, raggruppa per servizio e sceglie l'altro capo:
     il gruppo di un'altra VM, `0.0.0.0/0` con almeno 5 IP esterni,
     altrimenti un `/32` per IP.
   - La VM passa in `proposed`.
4. **`sg-learner proposal approve vm-web`**
   - La CLI segna la proposta come `approved` e basta: non tocca Neutron.
5. **Entro 30 secondi, l'Enforcer**
   - Crea il gruppo `learned-vm-web` e cancella le regole "tutto permesso in
     uscita" che Neutron vi aggiunge.
   - Crea le regole approvate più quelle di base (DHCP, metadata). Se una
     regola cita un'altra VM, quella VM viene aggiunta al proprio gruppo
     `learned-<vm>` (vuoto finché la sua proposta non è applicata), così la
     regola vale subito.
   - Sostituisce sulla porta i gruppi originali con `learned-vm-web` e
     attiva un network log `DROP` sul nuovo gruppo.
   - La VM passa in `enforcing`. Da qui, ogni 30 secondi, ricontrolla porta
     e regole e annulla eventuali modifiche manuali.
6. **Dopo l'applicazione, ogni 30 secondi**
   - L'Anomaly Detector legge i pacchetti bloccati della VM: un IP con
     almeno 5 porte diverse è una `scan`, un flusso bloccato almeno 5 volte
     è una `candidate`, il resto è `alert`.
   - Con `alerts accept` la regola viene aggiunta alla proposta e la VM
     torna in `approved`, quindi l'Enforcer la applica al giro dopo.
7. **`sg-learner rollback vm-web`**
   - Rimette i gruppi originali, spegne il log `DROP` e riporta la VM in
     `proposed`: la proposta si può riapprovare.

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
i log delle ACL di OVN, quindi richiede ML2/OVN: non funziona con ML2/OVS o
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
| `stack post-config` | attiva il Packet Logging di Neutron (service plugin `log`, `rate_limit` e `burst_limit`); crea l'utente di servizio `sg-learner` in Keystone; concede all'utente `stack` la lettura del log di OVN con una ACL; scrive `/etc/sg-learner/sg-learner.conf` |
| `stack extra` | avvia il servizio `devstack@sg-learner` (systemd) |
| `unstack` / `clean` | ferma il servizio / cancella configurazione e dati |

Per verificare: `sudo journalctl -u devstack@sg-learner -n 20 --no-pager`
deve mostrare l'autenticazione su Keystone, `Logging API attiva` e
`Log OVN leggibile`.

L'installazione è stata verificata da zero il 06/11/2026: `./unstack.sh`,
poi `./stack.sh` con il plugin scaricato da GitHub e la sola riga
`enable_plugin` nel `local.conf`, senza altri passaggi a mano.

Dopo un riavvio della macchina DevStack conviene lanciare, come utente
`stack`, [`tools/post-boot.sh`](tools/post-boot.sh): aspetta la
sincronizzazione dell'orologio, ricollega `br-ex` e riavvia i servizi
nell'ordine giusto (1-3 minuti, da non interrompere).

---

## 4. Uso

Il comando `sg-learner` usa le credenziali dell'amministratore. È
installato nel venv di DevStack, quindi conviene un alias:

```bash
source /opt/stack/devstack/openrc admin admin
alias sg-learner=/opt/stack/data/venv/bin/sg-learner
```

| Comando | Effetto |
|---|---|
| `sg-learner learn <vm> --duration 30m` | avvia l'osservazione della VM (attiva il logging sui suoi security group) |
| `sg-learner status` | stato di tutte le VM seguite |
| `sg-learner proposal generate <vm>` | chiude subito l'osservazione e calcola la proposta |
| `sg-learner proposal show <vm>` | mostra la proposta |
| `sg-learner proposal approve <vm>` | approva: l'Enforcer la applica entro 30 secondi |
| `sg-learner alerts list [<vm>] [--all]` | anomalie aperte (con `--all` anche quelle chiuse) |
| `sg-learner alerts accept <id>` | trasforma un'anomalia in regola (non vale per le scansioni) |
| `sg-learner alerts dismiss <id>` | chiude un'anomalia, che resta nello storico |
| `sg-learner rollback <vm>` | rimette i security group originali |

Esempio reale, la proposta per il web server della demo:

```
$ sg-learner proposal show vm-web
Proposta per vm-web (10.0.0.60) (23 connessioni osservate)
  = regole di base, sempre presenti: egress udp/67 verso 0.0.0.0/0, egress tcp/80 verso 169.254.169.254/32
  + ingress tcp/22 da 172.24.4.1/32                    3 conn.
  + ingress tcp/80 da 0.0.0.0/0                        5 conn.
  + ingress tcp/80 da gruppo vm:vm-app                 5 conn.
  + egress tcp/5432 verso gruppo vm:vm-db              5 conn.
  + egress udp/53 verso gruppo vm:vm-db                5 conn.
```

E le anomalie dopo l'applicazione:

```
$ sg-learner alerts list
  ID VM             TIPO       TENTATIVI ULTIMO       DESCRIZIONE
   8 vm-app         alert              1 28/10 19:00  egress tcp/5432 verso 10.0.0.45
  10 vm-db          candidate          6 28/10 19:02  ingress tcp/22 da 172.24.4.1
```

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
```

Le soglie hanno valori predefiniti e si possono cambiare aggiungendo queste
sezioni al file (poi `sudo systemctl restart devstack@sg-learner`):

```ini
[engine]
# IP esterni distinti oltre i quali la regola usa 0.0.0.0/0
public_threshold = 5
# connessioni minime perché un flusso diventi una regola
min_connections = 1
# sotto questa soglia la regola è marcata "poco osservata"
low_confidence_below = 3

[detector]
# tentativi bloccati oltre i quali un flusso è "candidate"
candidate_threshold = 5
# porte diverse provate da uno stesso IP oltre le quali è una "scan"
scan_ports = 5
```

Dal `local.conf` si possono invece cambiare percorsi, intervallo e limiti
del Packet Logging (variabili `SG_LEARNER_*` in
[`devstack/settings`](devstack/settings)).

---

## 6. Demo con tre VM

La demo riproduce un'applicazione a tre livelli partita con un gruppo
permissivo, `demo-open`, che apre in ingresso il ping e tutte le porte TCP e UDP.

| VM | Ruolo | Servizio simulato |
|---|---|---|
| `vm-web` | web server | porta 80 |
| `vm-db` | database | porta 5432 |
| `vm-app` | client dell'applicazione | nessuno |

I servizi sono simulati con `nc` di BusyBox (CirrOS):
`nc -lk -p 80 -e /bin/hostname` risponde a ogni connessione con il nome della
VM.

La demo si può fare in due modi: **con lo script**, che esegue tutto e
mostra ogni comando, oppure **a mano, comando per comando**. Il risultato è
lo stesso. In entrambi i casi si lavora sulla macchina DevStack come utente
`stack`, dopo:

```bash
source /opt/stack/devstack/openrc admin admin
alias sg-learner=/opt/stack/data/venv/bin/sg-learner   # il comando sta nel venv di DevStack
```

### 6.1 Con lo script

[`tools/demo.sh`](tools/demo.sh):

```bash
tools/demo.sh setup      # crea demo-open, le tre VM e i floating IP, avvia i servizi
tools/demo.sh run        # il ciclo completo, passo per passo
tools/demo.sh test       # solo la verifica: cosa passa e cosa no
tools/demo.sh services   # dopo un riavvio: riavvia i servizi finti
tools/demo.sh clean      # cancella tutto cio' che la demo ha creato
```

`run` stampa ogni comando prima di eseguirlo, si ferma tra un passo e
l'altro (con `tools/demo.sh --no-pause run` non si ferma) e chiede conferma
per le decisioni dell'amministratore (approvazione, rollback).

### 6.2 A mano, comando per comando

Sono gli stessi passi dello script. Gli IP sono quelli della demo del 06/11:
dopo il passo 1 vanno sostituiti con quelli di `openstack server list`. Per
entrare nelle VM CirrOS la password è `gocubsgo`: `ssh` la chiede a ogni
comando, a meno di usare `sshpass -p gocubsgo ssh ...` come fa lo script.

**1. Gruppo permissivo e tre VM con floating IP**

```bash
openstack security group create demo-open
openstack security group rule create demo-open --protocol icmp
openstack security group rule create demo-open --protocol tcp --dst-port 1:65535
openstack security group rule create demo-open --protocol udp --dst-port 1:65535

IMG=$(openstack image list -f value -c Name | grep -i cirros | head -1)
for vm in vm-web vm-db vm-app; do
    openstack server create --image "$IMG" --flavor m1.tiny --network private \
        --security-group demo-open --wait $vm
    FIP=$(openstack floating ip create public -f value -c floating_ip_address)
    openstack server add floating ip $vm $FIP
done
openstack server list -c Name -c Networks
```

**2. Indirizzi e servizi.** In emulazione CirrOS impiega circa 150 secondi
ad avviarsi. Poi:

```bash
WEB=10.0.0.60  DB=10.0.0.9  APP=10.0.0.50                 # IP privati
FWEB=172.24.4.216  FDB=172.24.4.152  FAPP=172.24.4.188    # floating IP

ssh cirros@$FWEB "(sudo nohup nc -lk -p 80 -e /bin/hostname < /dev/null > /dev/null 2>&1 &)"
ssh cirros@$FDB  "(sudo nohup nc -lk -p 5432 -e /bin/hostname < /dev/null > /dev/null 2>&1 &)"
```

Ogni servizio risponde con il nome della VM: `nc -w 3 $FWEB 80` deve
stampare `vm-web`.

**3. Avvio dell'osservazione**

```bash
for vm in vm-web vm-db vm-app; do sg-learner learn $vm --duration 10m; done
sg-learner status
```

**4. Traffico dell'applicazione**

```bash
# vm-app chiama il web server, vm-web chiama il database
ssh cirros@$FAPP "for i in 1 2 3 4 5; do nc -w 3 $WEB 80; done"
ssh cirros@$FWEB "for i in 1 2 3 4 5; do nc -w 3 $DB 5432; done"
# UDP: vm-web verso vm-db:53, vm-app fa query DNS verso 8.8.8.8
ssh cirros@$FWEB "for i in 1 2 3 4 5; do echo ciao | nc -u -w 1 $DB 53; done"
ssh cirros@$FAPP "for i in 1 2 3 4 5; do nslookup openstack.org 8.8.8.8; done"
# 5 client esterni diversi verso vm-web: indirizzi temporanei sull'host
for ip in 172.24.4.101 172.24.4.102 172.24.4.103 172.24.4.104 172.24.4.105; do
    sudo ip addr add $ip/24 dev br-ex
    nc -s $ip -w 3 $FWEB 80
    sudo ip addr del $ip/24 dev br-ex
done
```

**5. Proposte e approvazione**

```bash
for vm in vm-web vm-db vm-app; do sg-learner proposal generate $vm; done
sg-learner proposal show vm-web
for vm in vm-web vm-db vm-app; do sg-learner proposal approve $vm; done
sleep 40
sg-learner status                    # le tre VM in "enforcing"
openstack server show vm-db -c security_groups
openstack security group rule list learned-vm-db
```

**6. Verifica: cosa passa e cosa no**

```bash
ssh cirros@$FAPP "nc -w 3 $WEB 80"     # passa: stampa vm-web
ssh cirros@$FWEB "nc -w 3 $DB 5432"    # passa: stampa vm-db
nc -w 3 $FWEB 80                       # passa: servizio pubblico
ssh cirros@$FAPP "nc -w 3 $DB 5432"    # bloccato: nessuna risposta
nc -w 3 $FDB 5432                      # bloccato
ping -c 2 $FWEB                        # bloccato: 100% packet loss
```

**7. Anomaly Detector: vm-app scansiona il database**

```bash
ssh cirros@$FAPP "for p in 21 22 23 80 443 3306; do nc -w 2 $DB \$p < /dev/null; done"
sleep 35
sg-learner alerts list                 # compare una riga di tipo "scan"
```

**8. Rollback (facoltativo)**

```bash
sg-learner rollback vm-app                     # rimette demo-open
openstack server show vm-app -c security_groups
sg-learner proposal approve vm-app             # riapplica il gruppo appreso
```

Per cancellare tutto: `tools/demo.sh clean`.

**Risultato** (verificato dal vivo il 28/10, il 05/11 e il 06/11/2026, quest'ultimo su un'installazione da zero)

| Flusso | Con `demo-open` | Con i gruppi appresi | Regola che lo decide |
|---|---|---|---|
| vm-app → vm-web:80 | passa | **passa** | ingress tcp/80 dal gruppo `learned-vm-app` |
| vm-web → vm-db:5432 | passa | **passa** | ingress tcp/5432 dal gruppo `learned-vm-web` |
| vm-web → vm-db:53 (UDP) | passa | **passa** | ingress udp/53 dal gruppo `learned-vm-web` |
| vm-app → 8.8.8.8:53 (UDP, DNS) | passa | **passa** | egress udp/53 verso `8.8.8.8/32` |
| esterno → vm-web:80 | passa | **passa** | `0.0.0.0/0`: 5 IP esterni distinti osservati |
| vm-app → vm-db:5432 | passa | **bloccato** | nessuna: vm-app non ha mai parlato con il database |
| esterno → vm-db:5432 | passa | **bloccato** | nessuna |
| SSH dell'host su vm-db | passa | **dipende** | permesso solo se osservato durante il learning (lo script ci entra, la demo del 28/10 no) |
| ping a vm-web | passa | **bloccato** | nessuna |
| vm-test (VM estranea, prova a parte) → vm-db:5432 e :53 | passa | **bloccato** | vm-test non fa parte del gruppo `learned-vm-web` |
| vm-test (prova a parte) → vm-web:80 | passa | **passa** | `0.0.0.0/0`: servizio pubblico |

Dopo l'applicazione:

- i tentativi bloccati compaiono in `sg-learner alerts list`;
- 6 tentativi SSH dell'host su vm-db diventano una `candidate`. Accettata
  con `alerts accept`, l'Enforcer aggiunge la regola e l'SSH torna a
  funzionare, mentre vm-app → vm-db resta bloccato;
- `sg-learner rollback vm-app` rimette `demo-open`, e `proposal approve vm-app`
  riapplica il gruppo appreso.

---

## 7. Scelte di sicurezza

- **Approvazione obbligatoria.** SG-Learner propone, ma non applica nulla
  senza `proposal approve`. Il gruppo originale viene salvato per il
  rollback.
- **SG-Learner non allarga mai le regole da solo.** Un flusso bloccato che
  si ripete diventa al massimo una `candidate`, che l'amministratore può
  accettare. Altrimenti un attaccante potrebbe "addestrare" il firewall ad
  aprirsi insistendo con i tentativi.
- **Una scansione non diventa mai una regola.** Se uno stesso IP prova
  almeno 5 porte diverse, l'anomalia è una `scan` e si può solo ignorare.
- **Regole di base.** Con ML2/OVN, Neutron non permette implicitamente il
  DHCP: senza una regola esplicita una VM applicata non riottiene
  l'indirizzo al riavvio, perché osservando a VM accesa il DHCP non si vede.
  L'Enforcer aggiunge quindi sempre `egress udp/67` e l'accesso al servizio
  metadata (`egress tcp/80` verso `169.254.169.254/32`).
- **Regole tra VM per gruppo, non per IP.** Il traffico tra VM diventa
  `remote_group`: la regola segue la VM anche se cambia indirizzo e non
  apre nulla a chi prende un IP vicino.
- **Gruppi nuovi vuoti.** Neutron crea ogni gruppo con le regole "tutto
  permesso in uscita"; SG-Learner le cancella subito, così un gruppo
  `learned-` contiene solo regole approvate.
- **Rollback sicuro.** Se altre VM citano il gruppo learned di una VM nelle
  loro regole `remote_group`, quel gruppo resta sulla porta anche dopo il
  rollback. Le regole si sommano, quindi non restringe nulla, e le altre
  VM continuano ad accettarne il traffico.
- **Modifiche concorrenti.** Servizio e CLI sono due processi: una VM letta
  dal database viene salvata solo se nessuno l'ha cambiata nel frattempo,
  così un `accept` non viene sovrascritto dalla riconciliazione.
- **Privilegi.** L'utente di servizio ha il ruolo `admin` (serve per vedere
  le VM di tutti i progetti); la configurazione con la password è leggibile
  solo da `stack` (permessi 640); il log di OVN è accessibile in sola
  lettura tramite ACL.

---

## 8. Struttura della repo e test

| File | Cosa fa |
|---|---|
| `devstack/plugin.sh` | il plugin DevStack: a ogni fase di `stack.sh` installa il pacchetto, attiva il Packet Logging di Neutron, crea l'utente di servizio, concede la lettura del log di OVN, scrive la configurazione e avvia il servizio |
| `devstack/settings` | variabili del plugin (percorsi, intervallo, limiti del Packet Logging), sovrascrivibili da `local.conf` |
| `devstack/local.conf.sample` | `local.conf` di esempio, con le righe per host ARM |
| `sg_learner/service.py` | il servizio `devstack@sg-learner`: si collega a OpenStack (riprovando se non è ancora pronto), legge il log ogni 2 secondi e ogni 30 fa avanzare ciclo di vita, Enforcer e Anomaly Detector |
| `sg_learner/follower.py` | legge il log di `ovn-controller` come `tail -f`: righe incomplete, rotazione, troncamento; salva la posizione per riprendere dopo un riavvio |
| `sg_learner/collector.py` | interpreta le righe `acl_log` e tiene solo l'inizio delle connessioni, scartando ritrasmissioni e risposte UDP |
| `sg_learner/store.py` | database SQLite: connessioni osservate, VM seguite con il loro stato, anomalie, posizione nel log; un salvataggio non sovrascrive le modifiche fatte nel frattempo da un altro processo |
| `sg_learner/engine.py` | Policy Engine: dalle osservazioni alla proposta (`remote_group` tra VM, `0.0.0.0/0` o `/32` per gli esterni, regole di base, DHCP e metadata esclusi) |
| `sg_learner/lifecycle.py` | stati delle VM: avvio dell'osservazione, proposta alla scadenza o su richiesta, approvazione |
| `sg_learner/enforcer.py` | crea e mantiene i gruppi `learned-<vm>` su Neutron, li assegna alle porte, annulla le modifiche manuali, esegue il rollback |
| `sg_learner/detector.py` | Anomaly Detector: classifica il traffico bloccato in `alert`, `candidate` e `scan`; gestisce `accept` e `dismiss` |
| `sg_learner/cloud.py` | unico punto di accesso a Nova e Neutron (openstacksdk), comprese le chiamate REST al Packet Logging |
| `sg_learner/cli.py` | il comando `sg-learner` dell'amministratore |
| `sg_learner/__init__.py` | versione del pacchetto |
| `tools/demo.sh` | demo con tre VM: `setup`, `services`, `run`, `test`, `clean` |
| `tools/post-boot.sh` | dopo un riavvio della macchina DevStack: attende l'orologio, ricollega `br-ex`, riavvia i servizi in ordine, fa riaprire il log a OVN |
| `tests/test_*.py` | 85 test automatici (tabella sotto) |
| `tests/fixtures/ovn_acl_log_sample.txt` | righe reali del log di OVN usate dai test |
| `setup.py`, `setup.cfg` | pacchetto Python: metadati, dipendenze e i due comandi `sg-learner` e `sg-learner-service` |
| `requirements.txt`, `test-requirements.txt` | dipendenze: openstacksdk per il programma, pytest per i test |

I test non richiedono OpenStack: usano righe reali del log di OVN e un
Neutron simulato.

```bash
/opt/stack/data/venv/bin/python -m pytest -q tests/
```

| File | Test | Cosa verifica |
|---|---|---|
| `test_collector.py` | 14 | lettura delle righe reali di OVN, inizio delle connessioni, ritrasmissioni, risposte UDP |
| `test_store.py` | 9 | conteggi, filtri, persistenza, salvataggi concorrenti |
| `test_follower.py` | 11 | righe nuove e incomplete, rotazione, troncamento, ripresa dopo un riavvio |
| `test_engine.py` | 14 | soglia pubblica, `remote_group`, regole di base, IPv6, parametri per Neutron |
| `test_lifecycle.py` | 11 | transizioni di stato, comandi della CLI, credenziali mancanti, ripresa all'avvio |
| `test_enforcer.py` | 14 | regole approvate, idempotenza, riconciliazione, `remote_group`, rollback |
| `test_detector.py` | 12 | alert, candidate e scan, accept e dismiss, comandi `alerts` |
