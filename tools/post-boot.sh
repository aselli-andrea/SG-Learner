#!/bin/bash
# tools/post-boot.sh - da eseguire come utente stack dopo ogni riavvio della
# VM che ospita DevStack.
#
# Al riavvio i servizi DevStack partono tutti insieme e, su VMware, prima
# che l'orologio sia stato corretto da NTP. Ne seguono errori come
# MessagingTimeout in nova-compute o SG-Learner che non trova Keystone.
# Questo script rimette le cose in ordine:
#   1. aspetta che l'orologio sia sincronizzato;
#   2. ricollega l'host alla rete public di DevStack (br-ex);
#   3. riavvia tutti i servizi DevStack;
#   4. dopo una pausa riavvia per ultimi quelli che dipendono dagli altri;
#   5. chiede a ovn-controller di riaprire il proprio log, nel caso una
#      rotazione lo abbia lasciato a scrivere nel file rinominato.

# 1. Fino a 2 minuti di attesa per NTP
echo "Attendo la sincronizzazione dell'orologio..."
for _ in $(seq 1 60); do
    if [ "$(timedatectl show -p NTPSynchronized --value)" = "yes" ]; then
        break
    fi
    sleep 2
done
timedatectl | grep -E "Local time|synchronized"

# 2. Indirizzo dell'host sulla rete public: senza, floating IP e SSH
#    verso le VM non funzionano
sudo ip link set br-ex up
sudo ip addr replace 172.24.4.1/24 dev br-ex

echo "Riavvio dei servizi DevStack (1-3 minuti, senza output: non interrompere)..."
# 3. e 4. Riavvio di tutti i servizi, poi di nova-compute e SG-Learner
sudo systemctl restart "devstack@*"
echo "Servizi DevStack riavviati, attendo 30 secondi..."
sleep 30
sudo systemctl restart devstack@n-cpu devstack@sg-learner

# 5. ovn-controller riapre /var/log/ovn/ovn-controller.log
sudo ovn-appctl -t ovn-controller vlog/reopen

echo "br-ex configurato, servizi DevStack riavviati, log di OVN riaperto"
