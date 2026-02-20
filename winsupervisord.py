import os
import yaml
import threading
import subprocess
import time
import signal
import sys
import argparse
from pathlib import Path
from functools import wraps

os.makedirs('jobs', exist_ok=True)
os.makedirs('logs', exist_ok=True)

# Global dict to track processes: {job_name: {'pid': int, 'process': Popen, 'restart_count': int}}
running_processes = {}


def create_example_job():
    """Create an example disabled job file on startup if it doesn't exist."""
    example_job_path = 'jobs/example_job.yaml.disabled'
    if not os.path.exists(example_job_path):
        example_config = {
            'job': 'notepad',
            'command': 'notepad.exe',
            'numprocs': 1,
            'directory': '.',
            'autostart': True,
            'autorestart': True
        }
        with open(example_job_path, 'w') as f:
            yaml.dump(example_config, f, default_flow_style=False)


create_example_job()


def get_base_path():
    """Get the base path for the application, handling both normal and PyInstaller execution."""
    if getattr(sys, 'frozen', False):
        # PyInstaller sets sys.frozen and sys._MEIPASS
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))


def get_config():
    try:
        with open('winsupervisor_config.yaml', 'r') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        default_config = {"inet_http_control": {"enabled": False,
                                                "username": "admin",
                                                "password": "admin",
                                                "host": "0.0.0.0",
                                                "port": 5000},
                          "gui": True,
                          "monitor_interval": 5}
        with open('winsupervisor_config.yaml', 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False)
        return default_config


config = get_config()

# Parse command line arguments
parser = argparse.ArgumentParser(description='Windows Supervisord Service')
parser.add_argument('-gui', action='store_true', help='Enable GUI mode')
parser.add_argument('-nogui', action='store_true', help='Disable GUI mode')
args = parser.parse_args()

# Determine if GUI should be enabled
enable_gui = config.get('gui', True)
if args.gui:
    enable_gui = True
elif args.nogui:
    enable_gui = False


def is_process_alive(pid):
    """Check if a process with the given PID is still running."""
    try:
        # First check in our running_processes dictionary
        for job_name, proc_info in running_processes.items():
            if proc_info['pid'] == pid and 'process' in proc_info:
                # Use Popen.poll() which is reliable across platforms
                # Returns None if process is still running, returns exit code if done
                return proc_info['process'].poll() is None
        
        # If not found in our dict, fall back to platform-specific check
        if sys.platform == 'win32':
            # On Windows, use tasklist with filtered output
            result = subprocess.run(['tasklist', '/FI', f'PID eq {pid}'], 
                                  capture_output=True, text=True, timeout=2)
            # tasklist output includes header, check if PID appears in output
            lines = result.stdout.strip().split('\n')
            # If more than just the header line, process exists
            return len(lines) > 1
        else:
            # On Unix-like systems, sending signal 0 checks if process exists
            os.kill(pid, 0)
            return True
    except Exception as e:
        # If there's any error checking, assume process is dead
        return False


def kill_process_tree(proc_info):
    """Kill a process and its children. Handles the process tree on Windows."""
    try:
        if proc_info['process'].poll() is None:  # Process is still running
            if sys.platform == 'win32':
                # On Windows, use taskkill to kill the entire process tree
                pid = proc_info['pid']
                subprocess.run(['taskkill', '/F', '/T', '/PID', str(pid)], 
                             capture_output=True, timeout=5)
            else:
                # On Unix, use process group kill
                try:
                    os.killpg(os.getpgid(proc_info['process'].pid), signal.SIGKILL)
                except:
                    # Fallback to regular kill
                    proc_info['process'].kill()
            
            # Wait for it to actually terminate
            proc_info['process'].wait(timeout=5)
    except Exception as e:
        print(f"Error killing process tree: {e}")



def start_job(config_name, numproc_index=0):
    """Start a job and track its PID."""
    try:
        with open(f'jobs/{config_name}.yaml', 'r') as f:
            job_config = yaml.safe_load(f)

        command = job_config.get('command')
        directory = job_config.get('directory', '.')
        startsecs = job_config.get('startsecs', 0)
        numprocs = job_config.get('numprocs', 1)
        autorestart = job_config.get('autorestart', True)

        if not command:
            print(f"Error: No command specified for job '{config_name}'")
            return None

        # If directory is ".", extract it from the command's executable path
        if directory == '.':
            # Parse the executable path from the command
            executable_path = command.strip()
            if executable_path.startswith('"'):
                # Command is quoted: "path\to\exe" args...
                end_quote = executable_path.find('"', 1)
                if end_quote != -1:
                    executable_path = executable_path[1:end_quote]
            else:
                # Command is unquoted: path\to\exe args...
                space_pos = executable_path.find(' ')
                if space_pos != -1:
                    executable_path = executable_path[:space_pos]

            # Get directory from the executable path
            directory = os.path.dirname(os.path.abspath(executable_path))
            if not directory:
                directory = '.'

        # Determine job instance name for multi-process jobs
        job_instance_name = config_name
        if numprocs > 1:
            job_instance_name = f"{config_name}:{numproc_index}"

        log_file = f'logs/{job_instance_name}.log'

        # Open log file in append mode to preserve history
        with open(log_file, 'a') as f:
            f.write(f"\n--- Job started at {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")

        # Start the subprocess
        log_handle = open(log_file, 'a')
        
        # On Windows, use CREATE_NEW_PROCESS_GROUP to allow killing the entire process tree
        creationflags = 0
        if sys.platform == 'win32':
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            cwd=directory,
            creationflags=creationflags,
            preexec_fn=None  # Required for proper signal handling on Unix
        )

        # Track the process with its config
        running_processes[job_instance_name] = {
            'pid': process.pid,
            'process': process,
            'config_name': config_name,
            'numproc_index': numproc_index,
            'numprocs': numprocs,
            'restart_count': running_processes.get(job_instance_name, {}).get('restart_count', 0),
            'log_handle': log_handle,
            'command': command,
            'directory': directory,
            'startsecs': startsecs,
            'autorestart': autorestart,
            'start_time': time.time(),
            'startup_successful': False,
            'stopped': False
        }

        print(f"[{time.strftime('%H:%M:%S')}] Started job '{job_instance_name}' with PID {process.pid} (cwd={directory})")
        return process.pid
    except Exception as e:
        print(f"Error starting job '{config_name}': {e}")
        return None


def monitor_processes():
    """Monitor all running processes and restart dead ones."""
    while True:
        try:
            time.sleep(config.get('monitor_interval', 5))

            # Check each tracked process
            dead_jobs = []
            for job_instance_name, proc_info in list(running_processes.items()):
                pid = proc_info['pid']
                uptime = time.time() - proc_info['start_time']
                startsecs = proc_info.get('startsecs', 0)

                # Mark as successfully started if it's been running for startsecs
                if not proc_info.get('startup_successful') and uptime >= startsecs:
                    proc_info['startup_successful'] = True
                    print(f"[{time.strftime('%H:%M:%S')}] Process '{job_instance_name}' (PID {pid}) successfully started")

                # Check if process is still alive
                if not is_process_alive(pid):
                    print(f"[{time.strftime('%H:%M:%S')}] Process '{job_instance_name}' (PID {pid}) died!")
                    dead_jobs.append(job_instance_name)

                    # Clean up the process handle and log file
                    if 'process' in proc_info:
                        proc_info['process'].poll()
                    if 'log_handle' in proc_info:
                        try:
                            proc_info['log_handle'].close()
                        except:
                            pass

            # Restart dead jobs based on autorestart policy
            for job_instance_name in dead_jobs:
                proc_info = running_processes[job_instance_name]
                config_name = proc_info['config_name']
                autorestart = proc_info.get('autorestart', True)
                stopped = proc_info.get('stopped', False)  # Check if job was manually stopped

                # Determine if we should restart based on autorestart setting and stopped flag
                should_restart = (autorestart is True or autorestart == 'true' or autorestart == True) and not stopped

                if should_restart:
                    proc_info['restart_count'] += 1
                    new_restart_count = proc_info['restart_count']
                    print(f"[{time.strftime('%H:%M:%S')}] Restarting '{job_instance_name}' (restart #{new_restart_count})")
                    start_job(config_name, proc_info['numproc_index'])
                else:
                    if stopped:
                        print(f"[{time.strftime('%H:%M:%S')}] Not restarting '{job_instance_name}' (manually stopped)")
                    else:
                        print(f"[{time.strftime('%H:%M:%S')}] Not restarting '{job_instance_name}' (autorestart=false)")



        except Exception as e:
            print(f"Error in monitor_processes: {e}")


def gui_thread():
    """Run tkinter GUI for managing processes."""
    try:
        import tkinter as tk
        from tkinter import ttk, scrolledtext, messagebox
        import webbrowser
        
        root = tk.Tk()
        root.title("Windows Supervisord")
        root.geometry("900x600")
        
        selected_process = {'job': None, 'item_id': None}
        
        def refresh_process_list():
            """Refresh the process list display while preserving selection."""
            # Preserve current selection
            selected_items = tree.selection()
            previously_selected = selected_items[0] if selected_items else None
            
            # Clear the tree
            for item in tree.get_children():
                tree.delete(item)
            
            # Rebuild the list
            for job_instance_name, proc_info in sorted(running_processes.items()):
                pid = proc_info['pid']
                alive = is_process_alive(pid)
                status = "Running" if alive else "Dead"
                command = proc_info.get('command', '')[:40]
                
                item_id = tree.insert('', 'end', values=(
                    job_instance_name,
                    pid,
                    status,
                    proc_info.get('restart_count', 0),
                    command
                ))
                
                # Restore selection if this is the previously selected item
                if previously_selected and job_instance_name == selected_process['job']:
                    tree.selection_set(item_id)
                    selected_process['item_id'] = item_id
        
        def on_select(event):
            """Handle process selection."""
            selection = tree.selection()
            if selection:
                item = selection[0]
                values = tree.item(item)['values']
                selected_process['job'] = values[0]
        
        def start_process():
            """Start a selected job."""
            if not selected_process['job']:
                messagebox.showwarning("Warning", "Please select a process first")
                return
            
            job_name = selected_process['job'].split(':')[0]
            try:
                with open(f'jobs/{job_name}.yaml', 'r') as f:
                    job_config = yaml.safe_load(f)
                numprocs = job_config.get('numprocs', 1)
                
                # Try to start all instances of this job
                for i in range(numprocs):
                    job_instance_name = f"{job_name}:{i}" if numprocs > 1 else job_name
                    if job_instance_name in running_processes or (job_name not in running_processes and i == 0):
                        # Clear stopped flag for previously stopped jobs
                        if job_instance_name in running_processes:
                            running_processes[job_instance_name]['stopped'] = False
                        start_job(job_name, i)
                
                refresh_process_list()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to start job: {e}")
        
        def stop_process():
            """Stop a selected process."""
            if not selected_process['job']:
                messagebox.showwarning("Warning", "Please select a process first")
                return
            
            job_instance = selected_process['job']
            try:
                if job_instance in running_processes:
                    proc_info = running_processes[job_instance]
                    if proc_info['process'].poll() is None:
                        try:
                            kill_process_tree(proc_info)
                        except Exception as kill_error:
                            print(f"Error killing process: {kill_error}")
                        # Mark as stopped to prevent auto-restart
                        proc_info['stopped'] = True
                        if 'log_handle' in proc_info:
                            try:
                                proc_info['log_handle'].close()
                            except:
                                pass
                        refresh_process_list()
                    else:
                        messagebox.showwarning("Warning", f"Process '{job_instance}' is not running")
                else:
                    messagebox.showwarning("Warning", f"Process '{job_instance}' not found")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to stop process: {e}")
        
        def restart_process():
            """Restart a selected process."""
            if not selected_process['job']:
                messagebox.showwarning("Warning", "Please select a process first")
                return
            
            job_instance = selected_process['job']
            try:
                if job_instance in running_processes:
                    proc_info = running_processes[job_instance]
                    config_name = proc_info['config_name']
                    numproc_index = proc_info['numproc_index']
                    
                    # Stop the process
                    if proc_info['process'].poll() is None:
                        try:
                            kill_process_tree(proc_info)
                        except Exception as kill_error:
                            print(f"Error killing process: {kill_error}")
                    if 'log_handle' in proc_info:
                        try:
                            proc_info['log_handle'].close()
                        except:
                            pass
                    
                    # Clear the stopped flag so it can be restarted
                    proc_info['stopped'] = False
                    
                    # Start it again
                    start_job(config_name, numproc_index)
                    refresh_process_list()
                else:
                    pass
            except Exception as e:
                messagebox.showerror("Error", f"Failed to restart process: {e}")
        
        def view_log():
            """View the log file for a selected process."""
            if not selected_process['job']:
                messagebox.showwarning("Warning", "Please select a process first")
                return
            
            job_instance = selected_process['job']
            log_file = f'logs/{job_instance}.log'
            
            try:
                if os.path.exists(log_file):
                    # Create a new window with the log content
                    log_window = tk.Toplevel(root)
                    log_window.title(f"Log - {job_instance}")
                    log_window.geometry("800x600")
                    
                    text_widget = scrolledtext.ScrolledText(log_window, wrap=tk.WORD)
                    text_widget.pack(fill=tk.BOTH, expand=True)
                    
                    with open(log_file, 'r') as f:
                        log_content = f.read()
                    
                    text_widget.insert(tk.END, log_content)
                    text_widget.config(state=tk.DISABLED)
                    
                    # Auto-scroll to end
                    text_widget.see(tk.END)
                else:
                    messagebox.showwarning("Warning", f"Log file not found for '{job_instance}'")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to view log: {e}")
        
        # Create main frame
        main_frame = ttk.Frame(root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Title
        title_label = ttk.Label(main_frame, text="Running Processes", font=("Arial", 14, "bold"))
        title_label.pack(pady=5)
        
        # Tree view for processes
        columns = ('Job', 'PID', 'Status', 'Restarts', 'Command')
        tree = ttk.Treeview(main_frame, columns=columns, height=15)
        tree.column('#0', width=0, stretch=tk.NO)
        tree.column('Job', anchor=tk.W, width=150)
        tree.column('PID', anchor=tk.CENTER, width=80)
        tree.column('Status', anchor=tk.CENTER, width=80)
        tree.column('Restarts', anchor=tk.CENTER, width=80)
        tree.column('Command', anchor=tk.W, width=300)
        
        tree.heading('#0', text='', anchor=tk.W)
        tree.heading('Job', text='Job', anchor=tk.W)
        tree.heading('PID', text='PID', anchor=tk.CENTER)
        tree.heading('Status', text='Status', anchor=tk.CENTER)
        tree.heading('Restarts', text='Restarts', anchor=tk.CENTER)
        tree.heading('Command', text='Command', anchor=tk.W)
        
        tree.bind('<<TreeviewSelect>>', on_select)
        tree.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        start_btn = ttk.Button(button_frame, text="Start", command=start_process, width=12)
        start_btn.pack(side=tk.LEFT, padx=5)
        
        stop_btn = ttk.Button(button_frame, text="Stop", command=stop_process, width=12)
        stop_btn.pack(side=tk.LEFT, padx=5)
        
        restart_btn = ttk.Button(button_frame, text="Restart", command=restart_process, width=12)
        restart_btn.pack(side=tk.LEFT, padx=5)
        
        log_btn = ttk.Button(button_frame, text="View Log", command=view_log, width=12)
        log_btn.pack(side=tk.LEFT, padx=5)
        
        # Refresh loop
        def auto_refresh():
            try:
                refresh_process_list()
            except:
                pass
            root.after(1000, auto_refresh)  # Refresh every 1 second
        
        def on_close():
            """Handle window close event."""
            if messagebox.askokcancel("Quit", "Terminate all processes and exit?"):
                print("\nShutting down gracefully...")
                # Kill all child processes
                for job_name, proc_info in list(running_processes.items()):
                    try:
                        if proc_info['process'].poll() is None:
                            proc_info['process'].terminate()
                            print(f"Terminated job '{job_name}'")
                    except:
                        pass
                # Close all log handles
                for proc_info in running_processes.values():
                    if 'log_handle' in proc_info:
                        try:
                            proc_info['log_handle'].close()
                        except:
                            pass
                print("Shutdown complete.")
                root.destroy()
        
        root.protocol("WM_DELETE_WINDOW", on_close)
        auto_refresh()
        root.mainloop()
    
    except ImportError:
        print("Error: tkinter is not available. Install it or run with -nogui flag")
        sys.exit(1)
    except Exception as e:
        print(f"GUI Error: {e}")


def flask_thread():
    """Run Flask web server for remote control and monitoring."""
    from flask import Flask, request, send_file, make_response

    # Get the base path for both frozen and normal execution
    base_path = get_base_path()
    
    app = Flask(__name__)
    
    # Create basic auth decorator if username and password are configured
    def require_basic_auth(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Only require auth if credentials are configured
            username = config['inet_http_control'].get('username')
            password = config['inet_http_control'].get('password')
            
            if not username or not password:
                # No auth required if credentials not configured
                return f(*args, **kwargs)
            
            # Check for Authorization header
            auth = request.authorization
            if auth and auth.username == username and auth.password == password:
                return f(*args, **kwargs)
            
            # Return 401 Unauthorized with WWW-Authenticate header to prompt browser
            response = make_response('Unauthorized', 401)
            response.headers['WWW-Authenticate'] = 'Basic realm="Login Required"'
            return response
        return decorated_function

    @app.route('/')
    @require_basic_auth
    def index():
        index_path = os.path.join(base_path, 'index.html')
        return send_file(index_path)

    @app.route('/add_job', methods=['POST'])
    @require_basic_auth
    def add_job():
        job_name = request.form['job_name']
        command = request.form['command']
        numprocs = int(request.form.get('numprocs', 1))
        directory = request.form.get('directory', '.')
        autostart = request.form.get('autostart', 'true').lower() == 'true'
        autorestart = request.form.get('autorestart', 'true').lower() == 'true'
        startsecs = int(request.form.get('startsecs', 0))

        job_config = {
            'command': command,
            'numprocs': numprocs,
            'directory': directory,
            'autostart': autostart,
            'autorestart': autorestart,
            'startsecs': startsecs
        }

        with open(f'jobs/{job_name}.yaml', 'w') as f:
            yaml.dump(job_config, f, default_flow_style=False)

        # Start the job immediately if autostart is enabled
        if autostart:
            for i in range(numprocs):
                start_job(job_name, i)

        return 'Job added and started successfully!'

    @app.route('/status')
    @require_basic_auth
    def status():
        """Return status of all running processes."""
        status_info = {}
        for job_instance_name, proc_info in running_processes.items():
            pid = proc_info['pid']
            status_info[job_instance_name] = {
                'pid': pid,
                'alive': is_process_alive(pid),
                'restart_count': proc_info.get('restart_count', 0),
                'startup_successful': proc_info.get('startup_successful', False),
                'command': proc_info.get('command'),
                'autorestart': proc_info.get('autorestart'),
                'directory': proc_info.get('directory')
            }
        return status_info

    @app.route('/start_job', methods=['POST'])
    @require_basic_auth
    def start_job_endpoint():
        """Start a job via POST."""
        try:
            data = request.get_json()
            job_name = data.get('job_name')
            
            if not job_name:
                return {'status': 'error', 'message': 'job_name is required'}, 400
            
            with open(f'jobs/{job_name}.yaml', 'r') as f:
                job_config = yaml.safe_load(f)
            
            numprocs = job_config.get('numprocs', 1)
            
            # Start all instances of this job
            for i in range(numprocs):
                job_instance_name = f"{job_name}:{i}" if numprocs > 1 else job_name
                # Clear stopped flag for previously stopped jobs
                if job_instance_name in running_processes:
                    running_processes[job_instance_name]['stopped'] = False
                start_job(job_name, i)
            
            return {'status': 'success', 'message': f'Started job {job_name}'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}, 500

    @app.route('/stop_job', methods=['POST'])
    @require_basic_auth
    def stop_job_endpoint():
        """Stop a job via POST."""
        try:
            data = request.get_json()
            job_instance = data.get('job_name')
            
            if not job_instance:
                return {'status': 'error', 'message': 'job_name is required'}, 400
            
            if job_instance in running_processes:
                proc_info = running_processes[job_instance]
                if proc_info['process'].poll() is None:
                    try:
                        kill_process_tree(proc_info)
                    except Exception as kill_error:
                        print(f"Error killing process: {kill_error}")
                    # Mark as stopped to prevent auto-restart
                    proc_info['stopped'] = True
                    if 'log_handle' in proc_info:
                        try:
                            proc_info['log_handle'].close()
                        except:
                            pass
                    return {'status': 'success', 'message': f'Stopped job {job_instance}'}
                else:
                    return {'status': 'error', 'message': f'Process {job_instance} is not running'}, 400
            else:
                return {'status': 'error', 'message': f'Job {job_instance} not found'}, 404
        except Exception as e:
            return {'status': 'error', 'message': str(e)}, 500

    @app.route('/restart_job', methods=['POST'])
    @require_basic_auth
    def restart_job_endpoint():
        """Restart a job via POST."""
        try:
            data = request.get_json()
            job_instance = data.get('job_name')
            
            if not job_instance:
                return {'status': 'error', 'message': 'job_name is required'}, 400
            
            if job_instance in running_processes:
                proc_info = running_processes[job_instance]
                config_name = proc_info['config_name']
                numproc_index = proc_info['numproc_index']
                
                # Stop the process
                if proc_info['process'].poll() is None:
                    try:
                        kill_process_tree(proc_info)
                    except Exception as kill_error:
                        print(f"Error killing process: {kill_error}")
                if 'log_handle' in proc_info:
                    try:
                        proc_info['log_handle'].close()
                    except:
                        pass
                
                # Clear the stopped flag so it can be restarted and auto-restart will work again
                proc_info['stopped'] = False
                
                # Start it again
                start_job(config_name, numproc_index)
                return {'status': 'success', 'message': f'Restarted job {job_instance}'}
            else:
                return {'status': 'error', 'message': f'Job {job_instance} not found'}, 404
        except Exception as e:
            return {'status': 'error', 'message': str(e)}, 500

    @app.route('/view_log/<job_instance>')
    @require_basic_auth
    def view_log_endpoint(job_instance):
        """View log file for a job."""
        try:
            log_file = f'logs/{job_instance}.log'
            
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    return f.read()
            else:
                return f'Log file not found for {job_instance}', 404
        except Exception as e:
            return str(e), 500

    app.run(host=config['inet_http_control']['host'], port=config['inet_http_control']['port'], debug=False, use_reloader=False)


if config['inet_http_control']['enabled']:
    threading.Thread(target=flask_thread, daemon=True).start()

# Start the process monitor in a background thread
monitor_thread = threading.Thread(target=monitor_processes, daemon=True)
monitor_thread.start()


def get_jobs():
    jobs = {}
    for filename in os.listdir('jobs'):
        if filename.endswith('.yaml'):
            with open(f'jobs/{filename}', 'r') as f:
                jobs[filename[:-5]] = yaml.safe_load(f)
    return jobs


# Load and start all configured jobs on startup
print("Loading and starting configured jobs...")
for job_name, job_config in get_jobs().items():
    autostart = job_config.get('autostart', True)
    numprocs = job_config.get('numprocs', 1)

    if autostart:
        # Start multiple instances if numprocs > 1
        for i in range(numprocs):
            start_job(job_name, i)
    else:
        print(f"Skipping autostart for job '{job_name}' (autostart=false)")

# Start GUI if enabled
if enable_gui:
    print("Starting GUI...")
    gui_thread()
else:
    # main loop - keep the service running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
        # Kill all child processes
        for job_name, proc_info in running_processes.items():
            try:
                if proc_info['process'].poll() is None:  # Process still running
                    proc_info['process'].terminate()
                    print(f"Terminated job '{job_name}'")
            except:
                pass
        # Close all log handles
        for proc_info in running_processes.values():
            if 'log_handle' in proc_info:
                try:
                    proc_info['log_handle'].close()
                except:
                    pass
        print("Shutdown complete.")
