AI USAGE

------------------------------PHASE 1--------------------------

    The AI assistant was prompted to generate two specific functions for the filter command:

parse_condition: Designed to take a user-provided string and split it into its constituent parts for logical processing.

match_condition: Designed to evaluate an existing Report structure against a parsed condition
    
    The functions were mostly correct and the use of AI significantly reduced the time spent on string manipulation logic.
    The logic was integrated into the main execution loop, connecting the AI-generated parsing with the system-level read() calls from the binary reports.dat file.
    
    
    ------------------------------PHASE 2--------------------------
    
The AI assistant was prompted to

prompt 1: show me an example of using sigaction(not signal) to catch SIGUSR1 and SIGINT 

prompt 2: how to use execlp when passing multiple arguments and how to use wait to synchronize it with the parent process. 


The sigaction logic was harder to implement in monitor_reports. Ai suggested the structure with printf in handler, witch is unsafe. Also I needed to add volatile sig_atomic_t witch was not in the initial structure.

Fork and execlp were easier to implement int he remove comand function, I just needed to adapt by adding my own arguments in the function, but AI made me understood the logic better.This synchronization ensures that the parent process only unlinks the symbolic link after the child process has finished.






