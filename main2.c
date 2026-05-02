#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#define PID_FILE ".monitor_pid"

// Structura principala pentru rapoarte
typedef struct {
    int id;
    char inspector[50];
    float latitude;
    float longitude;
    char category[30];
    int severity;
    time_t timestamp;
    char description[256];
} Report;

// Structura pentru filtre
typedef struct {
    char field[30];
    char op[5];
    char value[50];
} Condition;



//////////////////////////////////////////////////////////// verificare permisiuni ////////////////////////////////////////////////////////////////////////
int verifica_permisiuni(const char *cale, const char *rol, int scriere) {
    struct stat st;
    if (stat(cale, &st) == -1) return 1; 

   if (strcmp(rol, "manager") == 0) {
    /* Cazul pentru OWNER (User) */
        if (scriere) {
            // Verifică dacă bitul pentru scriere user este activ
            return (st.st_mode & S_IWUSR);
        } else {
            // Verifică dacă bitul pentru citire user este activ
            return (st.st_mode & S_IRUSR);
        }
    } 
    else {
        /* Cazul pentru GRUP (Group) */
        if (scriere) {
            // Verifică dacă bitul pentru scriere grup este activ
            return (st.st_mode & S_IWGRP);
        } else {
            // Verifică dacă bitul pentru citire grup este activ
            return (st.st_mode & S_IRGRP);
        }
    }
}

///////////////////////////////////////////// Transformam bitii de mod in string-ul clasic rw-rw-r-- /////////////////////////////////////////////////
void mode_to_string(mode_t mode, char *str) {
    strcpy(str, "---------");
    if (mode & S_IRUSR) str[0] = 'r';
    if (mode & S_IWUSR) str[1] = 'w';
    if (mode & S_IXUSR) str[2] = 'x';
    if (mode & S_IRGRP) str[3] = 'r';
    if (mode & S_IWGRP) str[4] = 'w';
    if (mode & S_IXGRP) str[5] = 'x';
    if (mode & S_IROTH) str[6] = 'r';
    if (mode & S_IWOTH) str[7] = 'w';
    if (mode & S_IXOTH) str[8] = 'x';
}

////////////////////////////////////////// Inregistram actiunea in log-ul districtului ////////////////////////////////////////////////////////////////////
void scrie_in_log(const char *cale_log, const char *rol, const char *user, const char *actiune) {

    // int fd = open(cale_log, O_CREAT | O_WRONLY | O_APPEND, 0644);
    int fd = open(cale_log, O_CREAT | O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd != -1) {
        //time
        time_t acum = time(NULL);
        char *timp = ctime(&acum);
        timp[strlen(timp) - 1] = '\0'; 

        char buffer[512];
        int n = sprintf(buffer, "[%s] %s (%s) -> %s\n", timp, user, rol, actiune);
        write(fd, buffer, n);
        close(fd);
    }
}

////////////////////////////////////////////////////// Functii pentru filtrare  ////////////////////////////////////////////////////////////////////////////
int parseaza_conditie(const char *input, Condition *c) {
    return (sscanf(input, "%29[^:]:%4[^:]:%49s", c->field, c->op, c->value) == 3);
}

int verifica_match(Report r, Condition c) {
    if (strcmp(c.field, "severity") == 0) {
        int v = atoi(c.value);
        if (strcmp(c.op, "=") == 0) return r.severity == v;
        if (strcmp(c.op, ">") == 0) return r.severity > v;
        if (strcmp(c.op, "<") == 0) return r.severity < v;
        if (strcmp(c.op, ">=") == 0) return r.severity >= v;
        if (strcmp(c.op, "<=") == 0) return r.severity <= v;
    } else if (strcmp(c.field, "category") == 0) {
        if (strcmp(c.op, "=") == 0) return strcmp(r.category, c.value) == 0;
    }
    return 0;
}

////////////////////////////////////////////////////// --- SUBPROGRAME PENTRU COMENZI ---/////////////////////////////////////////////////////////////////////////

void comanda_add(const char *dist, const char *rol, const char *user) {
    char path[256], link[256], log[256];
    sprintf(path, "%s/reports.dat", dist);
    sprintf(link, "active_reports-%s", dist);
    sprintf(log, "%s/logged_district", dist);

    mkdir(dist, 0750);
    chmod(dist, 0750);

    // Citim datele de la tastatura ca in PDF 
    Report r;
    printf("X(latitudine): "); scanf("%f", &r.latitude);
    printf("Y(logitudine): "); scanf("%f", &r.longitude);
    printf("Categorie (road/lighting/flooding): "); scanf("%s", r.category);
    printf("Severity level (1/2/3): "); scanf("%d", &r.severity);
    getchar(); // curatam buffer-ul
    printf("Descriere: "); fgets(r.description, 256, stdin);
    r.description[strlen(r.description)-1] = '\0';

    if (!verifica_permisiuni(path, rol, 1)) {
        printf("Acces refuzat la scriere!\n");
        return;
    }

    int fd = open(path, O_CREAT | O_RDWR, 0664);
    chmod(path, 0664);

    // Calcul id [cite: 94]
    off_t size = lseek(fd, 0, SEEK_END);
    r.id = (size / sizeof(Report)) + 1;
    r.timestamp = time(NULL);
    strncpy(r.inspector, user, 50);

    write(fd, &r, sizeof(Report));
    close(fd);

    // Actualizam link-ul simbolic 
    unlink(link); 
    symlink(path, link);

    scrie_in_log(log, rol, user, "Adaugare raport");
    printf("Raport %d salvat cu succes.\n", r.id);
}

void comanda_list(const char *dist, const char *rol, const char *user) {
    char path[256], log[256];
    sprintf(path, "%s/reports.dat", dist);
    sprintf(log, "%s/logged_district", dist);

    struct stat st;
    if (stat(path, &st) == -1) {
        printf("District inexistent.\n");
        return;
    }

    char p_str[11];
    mode_to_string(st.st_mode, p_str);
    printf("Fisier: %s | Permisiuni: %s | Marime: %ld\n", path, p_str, st.st_size);

    int fd = open(path, O_RDONLY);
    Report r;
    while (read(fd, &r, sizeof(Report)) > 0) {
        printf("ID: %d | Inspector: %s | Sev: %d\n", r.id, r.inspector, r.severity);
    }
    close(fd);
    scrie_in_log(log, rol, user, "Listare");
}

void comanda_remove_report(const char *dist, const char *rol, const char *user, int target_id) {

    
    if (strcmp(rol, "manager") != 0) {
        printf("Doar managerul poate sterge!\n");
        return;
    }

    char path[256];
    sprintf(path, "%s/reports.dat", dist);
    int fd = open(path, O_RDWR);
    if (fd == -1) return;

    Report r;
    off_t pos = -1;
    while (read(fd, &r, sizeof(Report)) > 0) {
        if (r.id == target_id) {
            pos = lseek(fd, 0, SEEK_CUR) - sizeof(Report);
            break;
        }
    }

    if (pos != -1) {
        Report urm;
        while (read(fd, &urm, sizeof(Report)) > 0) {
            off_t current = lseek(fd, 0, SEEK_CUR);
            lseek(fd, pos, SEEK_SET);
            write(fd, &urm, sizeof(Report));
            pos = lseek(fd, 0, SEEK_CUR);
            lseek(fd, current, SEEK_SET);
        }
        struct stat st;
        fstat(fd, &st);
        ftruncate(fd, st.st_size - sizeof(Report));
        printf("Raport sters cu succes.\n");
        close(fd);
    }
     //scrie_in_log(log, rol, user, "Remove Report");
}

void comanda_remove_district(const char *dist, const char *rol, const char *user){

}

// Handler pentru SIGUSR1 - Notificare raport nou [cite: 110]
void handle_sigusr1(int sig) {
    const char *msg = "\n[Monitor] Alert: A new report has been added to the system!\n";
    write(STDOUT_FILENO, msg, strlen(msg));
}

// Handler pentru SIGINT - Închidere program [cite: 109]
void handle_sigint(int sig) {
    const char *msg = "\n[Monitor] Shutting down. Cleaning up PID file...\n";
    write(STDOUT_FILENO, msg, strlen(msg));
    unlink(PID_FILE); // Șterge fișierul la ieșire [cite: 108]
    exit(0);
}
//////////////////////////////////////////////////////////////// MAIN //////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[]) {
    char *role = "inspector"; // Rolul  
    char *user = "anonim";    // Numele utilizatorului 
    char *dist = NULL;        // Districtul pe care lucram 
    char *cmd = NULL;         // Comanda pe care o vom executa 
    char *extra = NULL;       // Pentru argumente extra, cum e ID-ul raportului 


    for (int i = 1; i < argc; i++) {
        
        // 1. setarile globale (role si user)
        if (strcmp(argv[i], "--role") == 0) {
            if (i + 1 < argc) {
                role = argv[i + 1];
                i++; // Am consumat si urmatorul argument, deci trecem peste el
            }
        } 
        else if (strcmp(argv[i], "--user") == 0) {
            if (i + 1 < argc) {
                user = argv[i + 1];
                i++;
            }
        } 
        
        // 2. ce comanda vrea sa execute utilizatorul
        else if (strcmp(argv[i], "--add") == 0) {
            if (i + 1 < argc) {
                cmd = "add";
                dist = argv[i + 1];
                i++;
            }
        } 
        else if (strcmp(argv[i], "--list") == 0) {
            if (i + 1 < argc) {
                cmd = "list";
                dist = argv[i + 1];
                i++;
            }
        } 
        else if (strcmp(argv[i], "--remove_report") == 0) {
            //  district SI de ID-ul raportului 
            if (i + 2 < argc) {
                cmd = "remove_report";
                dist = argv[i + 1];
                extra = argv[i + 2];
                i += 2; // Am consumat districtul si ID-ul, deci sarim 2 pozitii
            }
        } 
        else if (strcmp(argv[i], "--remove_district") == 0) {
            if (i + 1 < argc) {
                cmd = "remove_district"; 
                dist = argv[i + 1];
                i++;
            }
        }
    }

    // Daca nu avem comanda sau district, nu avem ce face, deci oprim programul
    if (cmd == NULL || dist == NULL) {
        printf("Utilizare: ./city_manager --role [rol] --user [nume] --[comanda] [district] [optional: id]\n");
        return 0;
    }

    // Executăm subprogramul corespunzător comenzii alese
    if (strcmp(cmd, "add") == 0) {
        comanda_add(dist, role, user);
    } 
    else if (strcmp(cmd, "list") == 0) {
        comanda_list(dist, role, user);
    } 
    else if (strcmp(cmd, "remove_report") == 0) {
        comanda_remove_report(dist, role, user, atoi(extra));
    } 
    else if (strcmp(cmd, "remove_district") == 0) {
        comanda_remove_district(dist, role, user); 
    }

    return 0;
}