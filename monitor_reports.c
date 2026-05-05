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
        const char msg[]="NOTIFICARE din monitor_report: un nou report a fost adugat";
        write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    }

}

int main(int argc, const char ** argv){

   
    pid_t my_pid = getpid();
    char pid_buffer[16];
    struct sigaction sa;

    //creeare sau overrides pentru fisier
    int fd;
    fd=open(PID_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if(fd==-1){
        perror("error opening file!");
        exit(EXIT_FAILURE);
    }

    // Convertim PID-ul in string si il scriem in fisier
    int len =snprintf(pid_buffer, sizeof(pid_buffer), "%d", my_pid);
    if (write(fd, pid_buffer, len) == -1) {
        perror("Error at writing PID");
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd);


    //configurare signaction
    memset(&sa, 0, sizeof(sa));//umplem cu 0 
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask); // Blocam alte semnale in timpul executiei handler-ului
    sa.sa_flags = 0;

    if(sigaction(SIGINT, &sa, NULL)==-1){
        perror("error at sigaction SIGINT");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGUSR1, &sa, NULL) == -1) {
        perror("error at sigaction SIGUSR1");
        exit(EXIT_FAILURE);
    }

    const char start_msg[] = "Running... (Wainting SIGUSR1/SIGINT)\n";
    write(STDOUT_FILENO, start_msg, sizeof(start_msg) - 1);//afisam in terminal

    // 3. Bucla principala - programul se termina DOAR la SIGINT
    while (keep_running) {
        pause(); // Suspendam executia pana la primirea unui semnal
    }

    // 4. Curatenia de final
    const char exit_msg[] = "SIGINT primit.Closing monitor and deleting the PID.\n";
    write(STDOUT_FILENO, exit_msg, sizeof(exit_msg) - 1);

    if (unlink(PID_FILE) == -1) {
        perror("Eroare la stergerea .monitor_pid");
    }
    return 0;

}