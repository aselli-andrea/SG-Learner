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

echo "Attendo la sincronizzazione dell'orologio..."
for _ in $(seq 1 60); do
    if [ "$(timedatectl show -p NTPSynchronized --value)" = "yes" ]; then
        break
    fi
    sleep 2
done
timedatectl | grep -E "Local time|synchronized"

sudo ip link set br-ex up
sudo ip addr replace 172.24.4.1/24 dev br-ex

echo "Riavvio dei servizi DevStack (1-3 minuti, senza output: non interrompere)..."
sudo systemctl restart "devstack@*"
echo "Servizi DevStack riavviati, attendo 30 secondi..."
sleep 30
sudo systemctl restart devstack@n-cpu devstack@sg-learner

sudo ovn-appctl -t ovn-controller vlog/reopen

echo "br-ex configurato, servizi DevStack riavviati, log di OVN riaperto"
