# automatic-potato

## A simple process monitor for performing various tasks
### Zombie Process Detection:
Detects processes in STATUS_ZOMBIE state
Kills zombies after 10 seconds
Identifies parent processes that aren't cleaning up
### Infinite Recursion Detection:
Pattern matching for recursion-related command lines
Thread count monitoring (>100 threads = suspicious)
File descriptor monitoring (>1000 FDs = potential leak)
### Memory Leak Detection:
Tracks memory usage over time
Detects sustained memory growth (>50% increase over 60s)
Samples memory every check to build growth profile
### Enhanced Test Process Monitoring:
5-second high CPU kill for TEST processes
5-minute maximum runtime for any test process
Categorizes test types (pytest, unittest, etc.)
Immediate kill on infinite recursion detection

### Process Tracking (runtime for all processes)
### Memory and CPU usage monitoring and History
Process lifecycle logging

###Detection Priorities:
Immediate kill: Infinite recursion, excessive FDs
5 seconds: TEST processes with high CPU  ( for people who are, not yet the best at async cases with callbacks.. not me /s )
10 seconds: Zombie processes
30 seconds: Normal processes with high CPU
60 seconds: Memory leak detection
300 seconds: TEST process max runtime
