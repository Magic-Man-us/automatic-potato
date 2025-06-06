#!/usr/bin/env python3
"""
Advanced Process Monitor and Auto-Kill Script Monitors processes
under the os environmental variable Set for 'USER', (LOGNAME for backup) for multiple issues:
- High CPU usage (TEST processes killed in 5s, others in 30s)
- Zombie processes
- Infinite recursion detection
- Memory leaks
- Excessive file descriptors
- Long-running test processes
"""

import psutil
import time
import logging
import sys
import os
from collections import defaultdict, deque
from typing import Dict, Set, List, Tuple, Optional
import signal
from datetime import datetime
import re

# Configuration
USER_TO_MONITOR = os.getenv("USER", os.getenv("LOGNAME", None)
HIGH_CPU_THRESHOLD = 95.0
HIGH_MEMORY_THRESHOLD = 1024 * 1024 * 1024  # 1GB in bytes
MAX_FILE_DESCRIPTORS = 1000
NORMAL_KILL_THRESHOLD = 30  # seconds
TEST_KILL_THRESHOLD = 5     # seconds - very fast for TEST processes
ZOMBIE_KILL_THRESHOLD = 10  # seconds for zombie processes
MEMORY_LEAK_THRESHOLD = 60  # seconds of growing memory
TEST_MAX_RUNTIME = 300      # 5 minutes max for any test process
CHECK_INTERVAL = 1.0
MEMORY_GROWTH_SAMPLES = 10  # Number of samples to detect memory growth

# Lightweight logging
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

if not USER_TO_MONITOR:
    raise ValueError("A user must be available to monitor for processes')

class ProcessState:
    """Track process state over time."""
    def __init__(self, pid: int, name: str, is_test: bool):
        self.pid = pid
        self.name = name
        self.is_test = is_test
        self.start_time = time.time()
        self.high_cpu_start = None
        self.zombie_start = None
        self.memory_samples = deque(maxlen=MEMORY_GROWTH_SAMPLES)
        self.last_check = time.time()
        self.kill_reason = None


class AdvancedProcessMonitor:
    """Advanced process monitor with multiple detection methods."""
    
    def __init__(self):
        self.user = USER_TO_MONITOR
        self.process_states: Dict[int, ProcessState] = {}
        self.killed_pids: Set[int] = set()
        self.last_cleanup = time.time()
        
        # Patterns for detecting infinite recursion
        self.recursion_patterns = [
            re.compile(r'.*test.*recursion.*', re.IGNORECASE),
            re.compile(r'.*infinite.*loop.*', re.IGNORECASE),
            re.compile(r'.*stack.*overflow.*', re.IGNORECASE),
        ]
        
        # Get target UID for optimization
        self.target_uid = None
        try:
            import pwd
            self.target_uid = pwd.getpwnam(self.user).pw_uid
        except:
            pass
        
        print("Advanced Process Monitor Started")
        print(f"Monitoring user: {self.user}")
        print(f"TEST process max runtime: {TEST_MAX_RUNTIME}s")
        print(f"Zombie detection enabled")
        print(f"Memory leak detection enabled")
        print(f"Infinite recursion detection enabled")
    
    def _is_target_process(self, proc) -> bool:
        """Fast check if process belongs to target user."""
        try:
            if self.target_uid and hasattr(proc, 'uids'):
                return proc.uids().real == self.target_uid
            return proc.username() == self.user
        except:
            return False
    
    def _is_test_process(self, proc) -> Tuple[bool, str]:
        """Detect if process is a test with detailed categorization."""
        try:
            name = proc.name().lower()
            cmdline = ' '.join(proc.cmdline()[:5]).lower()  # Check first 5 args
            
            # Test markers
            test_markers = ['test', 'pytest', 'unittest', 'nose', 'tox']
            
            is_test = any(marker in name or marker in cmdline for marker in test_markers)
            
            # Specific test type detection
            test_type = "unknown"
            if 'pytest' in name or 'pytest' in cmdline:
                test_type = "pytest"
            elif 'unittest' in name or 'unittest' in cmdline:
                test_type = "unittest"
            elif 'test' in name:
                test_type = "test"
            
            return is_test, test_type
        except:
            return False, "unknown"
    
    def _detect_zombie_process(self, proc) -> bool:
        """Detect zombie processes."""
        try:
            return proc.status() == psutil.STATUS_ZOMBIE
        except:
            return False
    
    def _detect_infinite_recursion(self, proc) -> bool:
        """Detect potential infinite recursion."""
        try:
            # Check for stack overflow patterns in cmdline
            cmdline = ' '.join(proc.cmdline())
            for pattern in self.recursion_patterns:
                if pattern.match(cmdline):
                    return True
            
            # Check for excessive thread count (potential recursion)
            try:
                num_threads = proc.num_threads()
                if num_threads > 100:  # Unusual number of threads
                    return True
            except:
                pass
            
            # Check for excessive file descriptors
            try:
                num_fds = proc.num_fds()
                if num_fds > MAX_FILE_DESCRIPTORS:
                    return True
            except:
                pass
            
            return False
        except:
            return False
    
    def _detect_memory_leak(self, state: ProcessState, proc) -> bool:
        """Detect memory leaks by tracking memory growth."""
        try:
            memory_info = proc.memory_info()
            current_memory = memory_info.rss  # Resident Set Size
            current_time = time.time()
            
            state.memory_samples.append((current_time, current_memory))
            
            # Need at least 5 samples to detect trend
            if len(state.memory_samples) < 5:
                return False
            
            # Check if memory is consistently growing
            samples = list(state.memory_samples)
            memory_values = [sample[1] for sample in samples]
            
            # Simple growth detection: last value > first value * 1.5
            if memory_values[-1] > memory_values[0] * 1.5:
                # Check if growth is sustained
                growth_time = samples[-1][0] - samples[0][0]
                if growth_time > MEMORY_LEAK_THRESHOLD:
                    return True
            
            return False
        except:
            return False
    
    def _should_kill_process(self, state: ProcessState, proc) -> Tuple[bool, str]:
        """Determine if process should be killed and why."""
        current_time = time.time()
        
        # Check for zombie processes
        if self._detect_zombie_process(proc):
            if state.zombie_start is None:
                state.zombie_start = current_time
                print(f"Zombie detected: PID={state.pid} {state.name}")
            elif current_time - state.zombie_start > ZOMBIE_KILL_THRESHOLD:
                return True, f"ZOMBIE ({current_time - state.zombie_start:.1f}s)"
        else:
            state.zombie_start = None
        
        # Check for infinite recursion
        if self._detect_infinite_recursion(proc):
            return True, "INFINITE_RECURSION"
        
        # Check for memory leaks
        if self._detect_memory_leak(state, proc):
            return True, "MEMORY_LEAK"
        
        # Check test process max runtime
        if state.is_test:
            runtime = current_time - state.start_time
            if runtime > TEST_MAX_RUNTIME:
                return True, f"TEST_TIMEOUT ({runtime:.1f}s)"
        
        # Check high CPU usage
        try:
            cpu_percent = proc.cpu_percent(interval=0.1)
            
            if cpu_percent >= HIGH_CPU_THRESHOLD:
                if state.high_cpu_start is None:
                    state.high_cpu_start = current_time
                    test_marker = " [TEST]" if state.is_test else ""
                    print(f"⚠High CPU: PID={state.pid} {state.name} ({cpu_percent:.1f}%){test_marker}")
                else:
                    sustained_time = current_time - state.high_cpu_start
                    kill_threshold = TEST_KILL_THRESHOLD if state.is_test else NORMAL_KILL_THRESHOLD
                    
                    if sustained_time >= kill_threshold:
                        return True, f"HIGH_CPU ({sustained_time:.1f}s)"
            else:
                if state.high_cpu_start is not None:
                    sustained_time = current_time - state.high_cpu_start
                    print(f"CPU normalized: PID={state.pid} {state.name} (was high {sustained_time:.1f}s)")
                state.high_cpu_start = None
        except:
            pass
        
        return False, ""
    
    def _kill_process(self, proc, state: ProcessState, reason: str):
        """Kill a process with detailed logging."""
        pid = proc.pid
        try:
            # Get additional process info before killing
            try:
                memory_mb = proc.memory_info().rss / 1024 / 1024
                cpu_percent = proc.cpu_percent()
                runtime = time.time() - state.start_time
                
                details = f"Runtime:{runtime:.1f}s Memory:{memory_mb:.1f}MB CPU:{cpu_percent:.1f}%"
            except:
                details = "Details unavailable"
            
            # Try graceful termination first
            proc.terminate()
            
            # Wait briefly for graceful termination
            try:
                proc.wait(timeout=3)
                kill_method = "SIGTERM"
            except psutil.TimeoutExpired:
                # Force kill if graceful termination failed
                proc.kill()
                kill_method = "SIGKILL"
            
            # Log the kill
            test_marker = "[TEST]" if state.is_test else ""
            print(f"KILLED: PID={pid} {state.name} {test_marker}")
            print(f"   Reason: {reason}")
            print(f"   Method: {kill_method}")
            print(f"   Details: {details}")
            
            logger.warning(f"Killed process PID={pid} {state.name} - {reason}")
            
            self.killed_pids.add(pid)
            
        except Exception as e:
            logger.error(f"Failed to kill PID={pid}: {e}")
    
    def _get_user_processes(self) -> List[psutil.Process]:
        """Get all user processes efficiently."""
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if self._is_target_process(proc):
                        processes.append(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except:
            pass
        return processes
    
    def _cleanup_dead_processes(self):
        """Clean up tracking for dead processes."""
        current_time = time.time()
        if current_time - self.last_cleanup < 15:  # Cleanup every 15 seconds
            return
        
        try:
            current_pids = {p.pid for p in psutil.process_iter(['pid'])}
        except:
            current_pids = set()
        
        # Clean up dead processes
        dead_pids = set(self.process_states.keys()) - current_pids
        for pid in dead_pids:
            if pid in self.process_states:
                state = self.process_states[pid]
                runtime = current_time - state.start_time
                print(f"Process ended: PID={pid} {state.name} (Runtime: {runtime:.1f}s)")
                del self.process_states[pid]
        
        # Clean up killed processes set
        self.killed_pids &= current_pids
        
        self.last_cleanup = current_time
    
    def monitor_loop(self):
        """Main monitoring loop with advanced detection."""
        try:
            while True:
                loop_start = time.time()
                
                processes = self._get_user_processes()
                
                if not processes:
                    time.sleep(CHECK_INTERVAL)
                    continue
                
                current_time = time.time()
                active_pids = set()
                
                for proc in processes:
                    try:
                        pid = proc.pid
                        active_pids.add(pid)
                        
                        # Skip already killed processes
                        if pid in self.killed_pids:
                            continue
                        
                        # Get or create process state
                        if pid not in self.process_states:
                            is_test, test_type = self._is_test_process(proc)
                            name = f"{proc.name()}"
                            if is_test:
                                name += f"[{test_type}]"
                            
                            self.process_states[pid] = ProcessState(pid, name, is_test)
                            
                            if is_test:
                                print(f"New test process: PID={pid} {name}")
                            else:
                                print(f"New process: PID={pid} {name}")
                        
                        state = self.process_states[pid]
                        state.last_check = current_time
                        
                        # Check if process should be killed
                        should_kill, reason = self._should_kill_process(state, proc)
                        
                        if should_kill:
                            self._kill_process(proc, state, reason)
                            del self.process_states[pid]
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                    except Exception as e:
                        continue
                
                # Cleanup dead processes
                self._cleanup_dead_processes()
                
                # Adaptive sleep
                loop_duration = time.time() - loop_start
                sleep_time = max(0.1, CHECK_INTERVAL - loop_duration)
                time.sleep(sleep_time)
                
        except KeyboardInterrupt:
            print("\nMonitor stopped")
        except Exception as e:
            logger.error(f"Monitor crashed: {e}")
            raise


def setup_signal_handlers(monitor):
    """Setup signal handlers for graceful shutdown."""
    def signal_handler(signum, frame):
        print(f"\nReceived signal {signum}, shutting down...")
        
        # Show summary
        active_processes = len(monitor.process_states)
        killed_processes = len(monitor.killed_pids)
        print(f"📊 Summary: {active_processes} active, {killed_processes} killed")
        
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def main():
    """Main entry point."""
    try:
        import psutil
    except ImportError:
        print("psutil not installed. Run: pip install psutil")
        sys.exit(1)
    
    monitor = AdvancedProcessMonitor()
    setup_signal_handlers(monitor)
    
    try:
        monitor.monitor_loop()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
