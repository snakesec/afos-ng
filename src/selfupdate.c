#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>

#define UPDATE_SCRIPT "/opt/AFOS/afos/POSAFOS.sh"

void start_update_via_script() {

    pid_t pid1 = fork();

    if (pid1 == -1) {
        perror("AFOS-NG Self UPDATE Failed: First Fork CREATION");
        return; 
    }

    if (pid1 > 0) {
        
        exit(0); 
    }


    if (setsid() == -1) {
        perror("AFOS-NG Self UPDATE Failed: setsid");
        exit(1);
    }
    
    pid_t pid2 = fork();
    
    if (pid2 == -1) {
        perror("AFOS-NG Self UPDATE Failed: Second Fork CREATION");
        exit(1);
    }
    
    if (pid2 > 0) {        
        exit(0); 
    }
    
    printf("AFOS-NG GC STARTED: Running: %s\n\n", UPDATE_SCRIPT);

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    execlp("bash", "bash", UPDATE_SCRIPT, (char *)NULL);
    
    perror("AFOS-NG GC FAILED: execlp");
    exit(1); 
}