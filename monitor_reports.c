#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define PID_FILE ".monitor_pid"

volatile sig_atomic_t keep_running = 1;

void  handle_signal(int sig){
    if(sig==SIGINT){
        keep_running=0;
    }
    else if(sig==SIGUSR1){
        const char msg[]="NOTIFICARE: un nou report a fost adugat\n";
        write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    }

}

void setup_signal(){

    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) == -1 || sigaction(SIGUSR1, &sa, NULL) == -1) {
        perror("Eroare la facere semnale");
        exit(EXIT_FAILURE);
    }
}
/////faza 3
void check_if_already_running() {
    int check_fd = open(PID_FILE, O_RDONLY);

    if (check_fd != -1) {
        char existing_pid[16];
        ssize_t n = read(check_fd, existing_pid, sizeof(existing_pid) - 1);
        if (n > 0) {
            existing_pid[n] = '\0';
            // Trimiterea erorii prin pipe către hub 
            dprintf(STDOUT_FILENO, "erroare, monitorul deja ruleaza cu PID  %s\n", existing_pid);
        }
        close(check_fd);
        exit(EXIT_SUCCESS); 
    }
}

void create_pid_file() {
    int fd = open(PID_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644); 
    if (fd == -1) {
        perror("erroare la creare fisier");
        exit(EXIT_FAILURE);
    }
    dprintf(fd, "%d", getpid());
    close(fd);
}

void cleanup() {

    const char exit_msg[] = "STOP:Monitor oprit de SIGINT\n";
    write(STDOUT_FILENO, exit_msg, strlen(exit_msg));
    unlink(PID_FILE); 
}

int main(int argc, const char ** argv){

    //verific
    check_if_already_running(); 
    //creez
    create_pid_file();
    //setez semanle
    setup_signal();

    //rulez
    const char start_msg[] = "INFO:Monitor active\n";
    write(STDOUT_FILENO, start_msg, strlen(start_msg));

    while (keep_running) {
        pause(); 
    }

    //curat
    cleanup();

    //Verific -> Creez PID -> Setez Semnale -> Rulez -> Curăț.
    return 0;
}