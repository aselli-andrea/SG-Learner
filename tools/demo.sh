#!/bin/bash
# tools/demo.sh - demo di SG-Learner con tre VM (vm-web, vm-db, vm-app).
#
# Da eseguire sulla macchina DevStack come utente stack, dopo
#   source /opt/stack/devstack/openrc admin admin
#
# Comandi:
#   tools/demo.sh setup      crea gruppo demo-open, tre VM CirrOS e floating IP
#   tools/demo.sh services   avvia i servizi finti (porta 80 su vm-web,
#                            5432 su vm-db): da rilanciare dopo un riavvio
#   tools/demo.sh run        il ciclo completo: osservazione, traffico,
#                            proposta, approvazione, verifica, anomalie
#   tools/demo.sh test       solo la verifica: cosa passa e cosa no
#   tools/demo.sh clean      cancella VM, floating IP e gruppi della demo
#
# Opzione: --no-pause (prima del comando) non aspetta Invio tra un passo
# e l'altro. Le decisioni dell'amministratore (approvazione, rollback)
# vengono sempre chieste.

set -u

VMS="vm-web vm-db vm-app"
SG_OPEN=demo-open
FLAVOR=${DEMO_FLAVOR:-m1.tiny}
NETWORK=${DEMO_NETWORK:-private}
PUBLIC=${DEMO_PUBLIC:-public}
CIRROS_PASSWORD=${DEMO_CIRROS_PASSWORD:-gocubsgo}
EXTERNAL_IPS="172.24.4.101 172.24.4.102 172.24.4.103 172.24.4.104 172.24.4.105"
SG_LEARNER=${SG_LEARNER:-/opt/stack/data/venv/bin/sg-learner}
PYTHON=${PYTHON:-/opt/stack/data/venv/bin/python}
DB=${SG_LEARNER_DB:-/opt/stack/data/sg-learner/sg-learner.db}
PAUSE=1

declare -A IP FIP

# --- Aspetto -------------------------------------------------------------------

if [[ -t 1 ]]; then
    B=$'\e[1m'; DIM=$'\e[2m'; GREEN=$'\e[32m'; RED=$'\e[31m'; CYAN=$'\e[36m'; R=$'\e[0m'
else
    B=; DIM=; GREEN=; RED=; CYAN=; R=
fi

title() { echo; echo "${B}${CYAN}=== $* ===${R}"; }
say()   { echo "${DIM}$*${R}"; }
# Mostra il comando e poi lo esegue
show()  { echo "${B}\$ $*${R}"; eval "$*"; }
pause() { [[ $PAUSE == 1 ]] && read -r -p "${DIM}[Invio per continuare]${R}" _; }
ask()   { local a; read -r -p "${B}$* [s/N] ${R}" a; [[ $a == [sS]* ]]; }
die()   { echo "${RED}Errore: $*${R}" >&2; exit 1; }

# --- Funzioni di supporto --------------------------------------------------------

check_env() {
    [[ -n "${OS_AUTH_URL:-}" ]] || die "manca 'source /opt/stack/devstack/openrc admin admin'"
    [[ -x $SG_LEARNER ]] || die "comando sg-learner non trovato in $SG_LEARNER"
    command -v sshpass > /dev/null || {
        say "Installo sshpass (serve per entrare nelle VM CirrOS senza digitare la password)"
        sudo apt-get install -y sshpass > /dev/null || die "installazione di sshpass fallita"
    }
}

# IP privato e floating IP di ogni VM della demo
load_ips() {
    local vm port
    for vm in $VMS; do
        port=$(openstack port list --server "$vm" -f value -c ID 2>/dev/null | head -1)
        [[ -n $port ]] || die "$vm non esiste: lancia prima 'tools/demo.sh setup'"
        IP[$vm]=$(openstack port show "$port" -f json -c fixed_ips |
                  grep -oE '10\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        FIP[$vm]=$(openstack floating ip list --port "$port" -f value -c "Floating IP Address" | head -1)
        [[ -n ${FIP[$vm]} ]] || die "$vm non ha un floating IP"
    done
}

# Esegue un comando dentro una VM CirrOS, via SSH sul floating IP
vmssh() {
    local vm=$1; shift
    sshpass -p "$CIRROS_PASSWORD" ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5 \
        "cirros@${FIP[$vm]}" "$@"
}

vm_state() { "$SG_LEARNER" status | awk -v v="$1" '$1==v {print $3}'; }

wait_state() {   # wait_state <stato> <secondi>
    local want=$1 limit=$2 t=0 vm ok
    while (( t < limit )); do
        ok=1
        for vm in $VMS; do [[ $(vm_state "$vm") == "$want" ]] || ok=0; done
        (( ok )) && return 0
        sleep 5; t=$(( t + 5 ))
    done
    return 1
}

# Una prova di connessione: stampa PASSA o BLOCCATO e il confronto con l'atteso
probe() {   # probe <descrizione> <atteso: passa|bloccato> <comando...>
    local what=$1 expected=$2; shift 2
    local out got
    out=$(eval "$*" 2>/dev/null)
    if [[ -n $out ]]; then got=passa; else got=bloccato; fi
    if [[ $got == "$expected" ]]; then
        printf "  %-34s %-9s ${GREEN}come previsto${R}\n" "$what" "$got"
    else
        printf "  %-34s %-9s ${RED}ATTESO: %s${R}\n" "$what" "$got" "$expected"
    fi
}

show_observations() {   # solo le VM della demo
    "$PYTHON" - "$DB" "${IP[vm-web]}" "${IP[vm-db]}" "${IP[vm-app]}" <<'EOF'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
ips = sys.argv[2:]
print(f"  {'VM':11} {'DIR':8} {'SERVIZIO':10} {'ALTRO CAPO':16} {'VERDETTO':9} CONN.")
for ip, d, p, port, remote, v, n in db.execute(
        "SELECT vm_ip, direction, protocol, service_port, remote_ip, verdict,"
        " count FROM observations WHERE vm_ip IN (?, ?, ?)"
        " ORDER BY vm_ip, direction, service_port", ips):
    svc = p if port == -1 else f"{p}/{port}"
    print(f"  {ip:11} {d:8} {svc:10} {remote:16} {v:9} {n}")
EOF
}

external_ips_free() {
    local used ip
    used=$(openstack floating ip list -f value -c "Floating IP Address")
    for ip in $EXTERNAL_IPS; do
        grep -qx "$ip" <<< "$used" && return 1
    done
    return 0
}

# --- setup / services / clean ----------------------------------------------------

cmd_setup() {
    check_env
    title "Gruppo permissivo $SG_OPEN"
    if ! openstack security group show "$SG_OPEN" > /dev/null 2>&1; then
        show openstack security group create "$SG_OPEN" \
            --description "'Demo SG-Learner: gruppo permissivo iniziale'" -f value -c id
        show openstack security group rule create "$SG_OPEN" --protocol icmp -f value -c id
        show openstack security group rule create "$SG_OPEN" --protocol tcp --dst-port 1:65535 -f value -c id
    else
        say "$SG_OPEN esiste gia'"
    fi

    title "Tre VM CirrOS"
    local image vm fip port
    image=$(openstack image list -f value -c Name | grep -i cirros | head -1)
    [[ -n $image ]] || die "nessuna immagine CirrOS trovata"
    for vm in $VMS; do
        if openstack server show "$vm" > /dev/null 2>&1; then
            say "$vm esiste gia'"
            continue
        fi
        show openstack server create --image "$image" --flavor "$FLAVOR" \
            --network "$NETWORK" --security-group "$SG_OPEN" --wait "$vm" -f value -c status
    done

    title "Floating IP"
    for vm in $VMS; do
        port=$(openstack port list --server "$vm" -f value -c ID | head -1)
        if [[ -z $(openstack floating ip list --port "$port" -f value -c ID) ]]; then
            fip=$(openstack floating ip create "$PUBLIC" -f value -c floating_ip_address)
            show openstack server add floating ip "$vm" "$fip"
        fi
    done
    load_ips
    for vm in $VMS; do echo "  $vm  ${IP[$vm]}  ${FIP[$vm]}"; done

    say "Attendo l'avvio di CirrOS (circa 150 secondi in emulazione)..."
    sleep 150
    cmd_services
}

cmd_services() {
    check_env
    load_ips
    title "Servizi della demo"
    say "vm-web risponde sulla porta 80 e vm-db sulla 5432 con il proprio nome (nc di BusyBox)"
    # Il server parte in una subshell staccata, cosi' SSH non resta appeso
    vmssh vm-web "netstat -ltn | grep -q ':80 ' || (sudo nohup nc -lk -p 80 -e /bin/hostname < /dev/null > /dev/null 2>&1 &)" \
        || die "SSH su vm-web non riuscito: la VM e' accesa? (openstack server reboot --hard vm-web)"
    vmssh vm-db "netstat -ltn | grep -q ':5432 ' || (sudo nohup nc -lk -p 5432 -e /bin/hostname < /dev/null > /dev/null 2>&1 &)" \
        || die "SSH su vm-db non riuscito: la VM e' accesa? (openstack server reboot --hard vm-db)"
    sleep 2
    vmssh vm-web "netstat -ltn | grep -q ':80 '" && echo "  vm-web: porta 80 in ascolto"
    vmssh vm-db "netstat -ltn | grep -q ':5432 '" && echo "  vm-db: porta 5432 in ascolto"
}

cmd_clean() {
    check_env
    ask "Cancello le VM della demo, i loro floating IP e i gruppi demo-open e learned-vm-*?" || exit 0
    local vm port fip sg
    for vm in $VMS; do
        port=$(openstack port list --server "$vm" -f value -c ID 2>/dev/null | head -1)
        if [[ -n $port ]]; then
            for fip in $(openstack floating ip list --port "$port" -f value -c ID); do
                show openstack floating ip delete "$fip"
            done
        fi
        openstack server show "$vm" > /dev/null 2>&1 && show openstack server delete --wait "$vm"
    done
    for sg in learned-vm-web learned-vm-db learned-vm-app "$SG_OPEN"; do
        openstack security group show "$sg" > /dev/null 2>&1 && show openstack security group delete "$sg"
    done
    say "Le VM restano nel database di SG-Learner come storico; i network log dei gruppi cancellati li rimuove Neutron."
}

# --- verifica --------------------------------------------------------------------

cmd_test() {
    check_env
    load_ips
    title "Cosa passa e cosa no"
    say "Traffico osservato (deve passare):"
    probe "vm-app -> vm-web:80" passa "vmssh vm-app 'nc -w 3 ${IP[vm-web]} 80'"
    probe "vm-web -> vm-db:5432" passa "vmssh vm-web 'nc -w 3 ${IP[vm-db]} 5432'"
    probe "host -> vm-web:80 (pubblico)" passa "nc -w 3 ${FIP[vm-web]} 80"
    say "Traffico mai visto (deve essere bloccato):"
    probe "vm-app -> vm-db:5432 (laterale)" bloccato "vmssh vm-app 'nc -w 3 ${IP[vm-db]} 5432'"
    probe "host -> vm-db:5432" bloccato "nc -w 3 ${FIP[vm-db]} 5432"
    probe "host ping vm-web" bloccato "ping -c 2 -W 2 ${FIP[vm-web]} | grep ' 0% packet loss'"
}

# --- il ciclo completo -----------------------------------------------------------

cmd_run() {
    check_env
    load_ips

    title "0 · Punto di partenza"
    local vm
    for vm in $VMS; do
        if [[ $(vm_state "$vm") == enforcing ]]; then
            say "$vm ha gia' un gruppo appreso: rollback per ripartire da $SG_OPEN"
            show "$SG_LEARNER" rollback "$vm"
        fi
    done
    for vm in $VMS; do
        echo "  $vm: $(openstack server show "$vm" -f value -c security_groups)"
    done
    local open_ids
    open_ids=$("$SG_LEARNER" alerts list | awk '$1 ~ /^[0-9]+$/ {print $1}')
    if [[ -n $open_ids ]]; then
        say "Anomalie ancora aperte da prove precedenti:"
        "$SG_LEARNER" alerts list
        if ask "Chiuderle (dismiss) prima di iniziare?"; then
            for id in $open_ids; do "$SG_LEARNER" alerts dismiss "$id"; done
        fi
    fi
    say "Con $SG_OPEN vm-app puo' parlare direttamente con il database:"
    probe "vm-app -> vm-db:5432" passa "vmssh vm-app 'nc -w 3 ${IP[vm-db]} 5432'"
    pause

    title "1 · Osservazione"
    for vm in $VMS; do show "$SG_LEARNER" learn "$vm" --duration 10m; done
    show "$SG_LEARNER" status
    pause

    title "2 · Traffico reale dell'applicazione"
    say "Accesso amministrativo via SSH alle tre VM"
    for vm in $VMS; do show "vmssh $vm hostname"; done
    say "vm-app chiama 5 volte il web server"
    show "vmssh vm-app 'for i in 1 2 3 4 5; do nc -w 3 ${IP[vm-web]} 80; done'"
    say "vm-web chiama 5 volte il database"
    show "vmssh vm-web 'for i in 1 2 3 4 5; do nc -w 3 ${IP[vm-db]} 5432; done'"
    say "5 client esterni diversi chiamano il web server (indirizzi temporanei su br-ex)"
    if external_ips_free; then
        local ip
        for ip in $EXTERNAL_IPS; do
            sudo ip addr add "$ip/24" dev br-ex
            echo -n "  client $ip -> "; nc -s "$ip" -w 3 "${FIP[vm-web]}" 80
            sudo ip addr del "$ip/24" dev br-ex
        done
    else
        say "Gli indirizzi $EXTERNAL_IPS sono in uso come floating IP: salto questo passo"
    fi
    say "Attendo che il servizio salvi le ultime connessioni..."
    sleep 10
    say "Il Flow Store (tabella observations):"
    show_observations
    pause

    title "3 · Proposte del Policy Engine"
    for vm in $VMS; do
        show "$SG_LEARNER" proposal generate "$vm"
        echo
    done
    pause

    title "4 · Decisione dell'amministratore"
    if ! ask "Approvare le tre proposte?"; then
        say "Proposte non approvate: le VM restano in 'proposed'."
        return
    fi
    for vm in $VMS; do show "$SG_LEARNER" proposal approve "$vm"; done
    say "L'Enforcer applica le proposte entro 30 secondi..."
    wait_state enforcing 90 || die "le VM non sono passate in 'enforcing': controlla 'sudo journalctl -u devstack@sg-learner -n 30'"
    show "$SG_LEARNER" status
    for vm in $VMS; do
        echo "  $vm: $(openstack server show "$vm" -f value -c security_groups)"
    done
    show openstack security group rule list learned-vm-db \
        -c Direction -c "'IP Protocol'" -c "'Port Range'" -c "'Remote Security Group'"
    pause

    cmd_test
    pause

    title "5 · Anomaly Detector: vm-app scansiona il database"
    show "vmssh vm-app 'for p in 21 22 23 80 443 3306; do nc -w 2 ${IP[vm-db]} \$p < /dev/null; done' 2>/dev/null"
    say "Attendo il giro del detector (35 secondi)..."
    sleep 35
    show "$SG_LEARNER" alerts list
    say "Una scan si puo' solo ignorare: sg-learner alerts dismiss <ID>"
    pause

    title "6 · Rollback (facoltativo)"
    if ask "Provare rollback e riapplicazione su vm-app?"; then
        show "$SG_LEARNER" rollback vm-app
        echo "  vm-app: $(openstack server show vm-app -f value -c security_groups)"
        probe "host ping vm-app" passa "ping -c 2 -W 2 ${FIP[vm-app]} | grep ' 0% packet loss'"
        probe "vm-app -> vm-web:80" passa "vmssh vm-app 'nc -w 3 ${IP[vm-web]} 80'"
        show "$SG_LEARNER" proposal approve vm-app
        say "Attendo la riapplicazione..."
        wait_state enforcing 90 || die "vm-app non e' tornata in 'enforcing'"
        echo "  vm-app: $(openstack server show vm-app -f value -c security_groups)"
        probe "host ping vm-app" bloccato "ping -c 2 -W 2 ${FIP[vm-app]} | grep ' 0% packet loss'"
    fi

    title "Fine della demo"
}

# --- main ------------------------------------------------------------------------

if [[ ${1:-} == --no-pause ]]; then PAUSE=0; shift; fi
case "${1:-}" in
    setup)    cmd_setup ;;
    services) cmd_services ;;
    run)      cmd_run ;;
    test)     cmd_test ;;
    clean)    cmd_clean ;;
    *) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
