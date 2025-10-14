#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>

#define UPDATE_SCRIPT "/tmp/afos-ng/POSAFOS.sh"

void start_update_via_script() {

    pid_t pid = fork();

    if (pid == -1) {
        perror("AFOS-NG Self UPDATE Failed: Fork CREATION");
        return; 
    }

    if (pid == 0) {        
        printf("AFOS-NG Frok STARTED: Running: %s\n", UPDATE_SCRIPT);
        execlp("bash", "bash", UPDATE_SCRIPT, (char *)NULL);
        exit(0);
    } else {
        exit(0); 
    }
}