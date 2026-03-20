#!/bin/bash

#############################################
# Nginx Proxy Manager - Script Gestione
# Uso: ./npm-manage.sh {comando}
#############################################

set -e

# Colori output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# Funzione helper
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Header
echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Nginx Proxy Manager - Manager Script    ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}"
echo ""

# Comandi
case "$1" in
    start)
        print_info "Avvio Nginx Proxy Manager..."
        
        # Verifica .env
        if [ ! -f .env ]; then
            print_warning "File .env non trovato. Copia da .env.example"
            cp .env.example .env
            print_info "Modifica .env con i tuoi dati:"
            echo "  nano .env"
            exit 1
        fi
        
        # Avvia container
        docker-compose up -d
        
        # Attendi container ready
        print_info "Attendi container ready (30s)..."
        sleep 5
        
        # Verifica status
        if docker-compose ps | grep -q "Up"; then
            print_success "NPM avviato con successo!"
            echo ""
            echo -e "${GREEN}Accedi a: http://localhost:81${NC}"
            echo -e "${YELLOW}Credenziali default:${NC}"
            echo "  Email: admin@example.com"
            echo "  Password: changeme"
            echo ""
        else
            print_error "Errore avvio container"
            docker-compose logs --tail=50
            exit 1
        fi
        ;;
    
    stop)
        print_info "Stop Nginx Proxy Manager..."
        docker-compose down
        print_success "Container fermati"
        ;;
    
    restart)
        print_info "Restart Nginx Proxy Manager..."
        docker-compose restart
        print_success "Container riavviati"
        ;;
    
    logs)
        print_info "Log real-time (CTRL+C per uscire)..."
        docker-compose logs -f nginx-proxy-manager
        ;;
    
    status)
        print_info "Status container:"
        docker-compose ps
        echo ""
        
        # Health check
        if docker-compose ps | grep -q "Up"; then
            CONTAINER_ID=$(docker-compose ps -q nginx-proxy-manager)
            HEALTH=$(docker inspect --format='{{.State.Health.Status}}' $CONTAINER_ID 2>/dev/null || echo "n/a")
            
            echo "Health: $HEALTH"
            echo ""
            
            # Statistiche
            print_info "Statistiche:"
            echo "Proxy Hosts configurati: $(ls -1 data/nginx/proxy_host/*.conf 2>/dev/null | wc -l)"
            echo "Certificati SSL: $(ls -1d data/letsencrypt/live/*/ 2>/dev/null | wc -l)"
            echo "Dimensione dati: $(du -sh data/ 2>/dev/null | cut -f1)"
        else
            print_warning "Container non in esecuzione"
        fi
        ;;
    
    backup)
        print_info "Backup in corso..."
        
        BACKUP_NAME="npm-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
        
        # Backup completo directory data
        tar -czf "$BACKUP_NAME" data/
        
        BACKUP_SIZE=$(du -h "$BACKUP_NAME" | cut -f1)
        print_success "Backup completato: $BACKUP_NAME ($BACKUP_SIZE)"
        
        # Lista ultimi 5 backup
        echo ""
        print_info "Ultimi backup:"
        ls -lht npm-backup-*.tar.gz 2>/dev/null | head -5 | awk '{print "  " $9 " - " $5}'
        ;;
    
    restore)
        if [ -z "$2" ]; then
            print_error "Specifica file backup: $0 restore npm-backup-YYYYMMDD.tar.gz"
            exit 1
        fi
        
        if [ ! -f "$2" ]; then
            print_error "File backup non trovato: $2"
            exit 1
        fi
        
        print_warning "ATTENZIONE: Restore sovrascriverà i dati attuali!"
        read -p "Confermi? (yes/no): " confirm
        
        if [ "$confirm" == "yes" ]; then
            print_info "Stop container..."
            docker-compose down
            
            print_info "Backup dati attuali..."
            mv data data.old.$(date +%Y%m%d-%H%M%S)
            
            print_info "Restore da $2..."
            tar -xzf "$2"
            
            print_info "Riavvio container..."
            docker-compose up -d
            
            print_success "Restore completato!"
        else
            print_info "Restore annullato"
        fi
        ;;
    
    reset)
        print_warning "ATTENZIONE: Reset completo eliminerà TUTTI i dati!"
        print_warning "- Database"
        print_warning "- Configurazioni Nginx"
        print_warning "- Certificati SSL"
        print_warning "- Log"
        echo ""
        read -p "Confermi reset? (scrivi 'yes' per confermare): " confirm
        
        if [ "$confirm" == "yes" ]; then
            print_info "Stop container..."
            docker-compose down -v
            
            print_info "Backup dati prima di reset..."
            if [ -d data ]; then
                mv data data.reset-backup.$(date +%Y%m%d-%H%M%S)
            fi
            
            print_info "Riavvio container..."
            docker-compose up -d
            
            print_success "Reset completato!"
            echo ""
            echo -e "${YELLOW}Login con credenziali default:${NC}"
            echo "  Email: admin@example.com"
            echo "  Password: changeme"
        else
            print_info "Reset annullato"
        fi
        ;;
    
    update)
        print_info "Update Nginx Proxy Manager..."
        
        print_info "Pull ultima immagine Docker..."
        docker-compose pull
        
        print_info "Ricrea container..."
        docker-compose up -d --force-recreate
        
        print_success "Update completato!"
        ;;
    
    logs-analyze)
        print_info "Analisi log..."
        
        # Cerca log proxy host
        LOG_FILE=$(ls -1 data/logs/proxy-host-*_access.log 2>/dev/null | head -1)
        
        if [ -z "$LOG_FILE" ]; then
            print_warning "Nessun log trovato. Crea prima un proxy host."
            exit 0
        fi
        
        echo ""
        echo "📊 Statistiche da: $LOG_FILE"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        # Richieste totali
        TOTAL=$(wc -l < "$LOG_FILE")
        echo "Richieste totali: $TOTAL"
        
        # Top 10 IP
        echo ""
        echo "Top 10 Client IP:"
        awk '{print $1}' "$LOG_FILE" | sort | uniq -c | sort -rn | head -10 | \
            awk '{printf "  %-15s %s richieste\n", $2, $1}'
        
        # Status codes
        echo ""
        echo "Status HTTP:"
        awk '{print $9}' "$LOG_FILE" | sort | uniq -c | sort -rn | \
            awk '{printf "  %s: %s\n", $2, $1}'
        
        # Metodi HTTP
        echo ""
        echo "Metodi HTTP:"
        awk '{print $6}' "$LOG_FILE" | tr -d '"' | sort | uniq -c | sort -rn | \
            awk '{printf "  %-8s %s\n", $2, $1}'
        
        # Bandwidth
        echo ""
        BANDWIDTH=$(awk '{sum+=$10} END {printf "%.2f", sum/1024/1024}' "$LOG_FILE")
        echo "Bandwidth totale: ${BANDWIDTH} MB"
        ;;
    
    shell)
        print_info "Apertura shell nel container..."
        docker exec -it nginx-proxy-manager /bin/bash
        ;;
    
    help|*)
        echo "Uso: $0 {comando}"
        echo ""
        echo "Comandi disponibili:"
        echo "  ${GREEN}start${NC}          Avvia Nginx Proxy Manager"
        echo "  ${GREEN}stop${NC}           Ferma container"
        echo "  ${GREEN}restart${NC}        Riavvia container"
        echo "  ${GREEN}status${NC}         Mostra stato e statistiche"
        echo "  ${GREEN}logs${NC}           Visualizza log real-time"
        echo "  ${GREEN}logs-analyze${NC}   Analizza log accessi"
        echo ""
        echo "  ${YELLOW}backup${NC}         Crea backup completo"
        echo "  ${YELLOW}restore${NC} FILE  Ripristina da backup"
        echo "  ${YELLOW}reset${NC}          Reset completo (ATTENZIONE!)"
        echo "  ${YELLOW}update${NC}         Aggiorna all'ultima versione"
        echo ""
        echo "  ${BLUE}shell${NC}          Apri shell nel container"
        echo "  ${BLUE}help${NC}           Mostra questo messaggio"
        echo ""
        echo "Esempi:"
        echo "  $0 start"
        echo "  $0 backup"
        echo "  $0 restore npm-backup-20260320.tar.gz"
        echo "  $0 logs-analyze"
        exit 0
        ;;
esac
