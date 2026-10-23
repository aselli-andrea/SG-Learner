#!/bin/bash
#
# devstack/plugin.sh - plugin DevStack di SG-Learner
#
# Attivazione nel local.conf:
#   enable_plugin sg-learner <url-della-repo> [branch]
#
# Fasi gestite:
#   stack install     -> installa il pacchetto Python
#   stack post-config -> configura Neutron (Packet Logging), crea l'utente
#                        di servizio in Keystone, scrive la configurazione,
#                        concede la lettura del log di OVN
#   stack extra       -> avvia il servizio (systemd: devstack@sg-learner)
#   unstack / clean   -> ferma il servizio e ripulisce

# Salva lo stato di xtrace e lo disattiva per non stampare le password
_XTRACE_SG_LEARNER=$(set +o | grep xtrace)
set +o xtrace


function install_sg_learner {
    setup_develop $SG_LEARNER_DIR
}

# Abilita il Packet Logging di Neutron.
# Il service plugin "log" viene aggiunto alla lista che DevStack scrive
# in neutron.conf dopo la fase post-config; i limiti di logging vanno
# invece direttamente nella configurazione ML2.
function configure_sg_learner_neutron_log {
    neutron_service_plugin_class_add log
    iniset $SG_LEARNER_ML2_CONF network_log rate_limit $SG_LEARNER_LOG_RATE_LIMIT
    iniset $SG_LEARNER_ML2_CONF network_log burst_limit $SG_LEARNER_LOG_BURST_LIMIT
}

# Utente dedicato nel progetto "service". Il ruolo admin serve per
# vedere le VM di tutti i progetti e gestire i security group altrui.
function create_sg_learner_accounts {
    create_service_user "$SG_LEARNER_SERVICE_USER" "admin"
}

# Il log di ovn-controller appartiene a root (rw-r-----). Una ACL
# concede la lettura all'utente che esegue il servizio; l'ACL di
# default sulla cartella vale anche per i file ricreati dalla rotazione.
function configure_sg_learner_ovn_log_access {
    local log_dir
    log_dir=$(dirname $SG_LEARNER_OVN_LOG)
    install_package acl
    sudo mkdir -p $log_dir
    sudo setfacl -m u:$STACK_USER:rx $log_dir
    sudo setfacl -d -m u:$STACK_USER:r $log_dir
    if [[ -f $SG_LEARNER_OVN_LOG ]]; then
        sudo setfacl -m u:$STACK_USER:r $SG_LEARNER_OVN_LOG
    fi
}

function configure_sg_learner_conf {
    sudo install -d -o $STACK_USER -m 750 $SG_LEARNER_CONF_DIR
    install -d -m 750 $SG_LEARNER_DATA_DIR

    iniset $SG_LEARNER_CONF DEFAULT interval $SG_LEARNER_INTERVAL
    iniset $SG_LEARNER_CONF DEFAULT ovn_log_file $SG_LEARNER_OVN_LOG
    iniset $SG_LEARNER_CONF DEFAULT data_dir $SG_LEARNER_DATA_DIR

    iniset $SG_LEARNER_CONF openstack auth_url $KEYSTONE_SERVICE_URI
    iniset $SG_LEARNER_CONF openstack username $SG_LEARNER_SERVICE_USER
    iniset $SG_LEARNER_CONF openstack password $SERVICE_PASSWORD
    iniset $SG_LEARNER_CONF openstack project_name $SERVICE_PROJECT_NAME
    iniset $SG_LEARNER_CONF openstack user_domain_name $SERVICE_DOMAIN_NAME
    iniset $SG_LEARNER_CONF openstack project_domain_name $SERVICE_DOMAIN_NAME
    iniset $SG_LEARNER_CONF openstack region_name $REGION_NAME

    chmod 640 $SG_LEARNER_CONF
}

function configure_sg_learner {
    configure_sg_learner_neutron_log
    create_sg_learner_accounts
    configure_sg_learner_ovn_log_access
    configure_sg_learner_conf
}

function start_sg_learner {
    run_process sg-learner "$(get_python_exec_prefix)/sg-learner-service --config-file $SG_LEARNER_CONF"
}

function stop_sg_learner {
    stop_process sg-learner
}

function cleanup_sg_learner {
    sudo rm -rf $SG_LEARNER_CONF_DIR
    rm -rf $SG_LEARNER_DATA_DIR
}


if is_service_enabled sg-learner; then
    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        echo_summary "Installazione di SG-Learner"
        install_sg_learner

    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        echo_summary "Configurazione di SG-Learner"
        configure_sg_learner

    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        echo_summary "Avvio di SG-Learner"
        start_sg_learner
    fi

    if [[ "$1" == "unstack" ]]; then
        stop_sg_learner
    fi

    if [[ "$1" == "clean" ]]; then
        cleanup_sg_learner
    fi
fi

# Ripristina lo stato di xtrace
$_XTRACE_SG_LEARNER
