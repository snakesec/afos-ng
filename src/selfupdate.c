#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>

#define UPDATE_SCRIPT "/opt/AFOS/afos/POSAFOS.sh"

void start_update_via_script() {

    pid_t pid = fork();

    if (pid == -1) {
        perror("AFOS-NG Self UPDATE Failed: Fork CREATION");
        return; 
    }

    if (pid == 0) {        
        printf("AFOS-NG Fork STARTED: Running: %s\n", UPDATE_SCRIPT);
        execlp("bash", "bash", UPDATE_SCRIPT, (char *)NULL);
        system("rm -rf /opt/AFOS/afos");
        exit(0);
    } else {
        exit(0); 
    }
}