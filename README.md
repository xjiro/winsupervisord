# Windows Supervisord

A lightweight Windows process supervisor with an optional web UI and GUI. Manage and monitor long-running applications with automatic restart, log tracking, and HTTP control.

## Features

- Auto-start and auto-restart failed processes
- Multi-process job support (spawn multiple instances)
- Web UI and REST API with HTTP Basic Auth
- Optional Tkinter GUI
- Process logging
- YAML-based job configuration

## Usage

Run winsupervisord.exe once and close it to generate default configs and directory structure.

Try renaming `example_job.yaml.disabled` in `jobs/` to `example_job.yaml` to test with `notepad.exe`

### Main Configuration

Edit `winsupervisor_config.yaml`:
```yaml
gui: false
monitor_interval: 5
inet_http_control:
  enabled: true
  username: admin
  password: admin
  host: 0.0.0.0
  port: 5000
```

### Define Jobs

Create job configs in `jobs/` directory. Example `jobs/myapp.yaml`:
```yaml
job: myapp
command: python app.py
numprocs: 1
directory: .
autostart: true
autorestart: true
```

## Web API

The http interface is disabled by default. When enabled, if either username or password is not set, there's no HTTP basic auth. Visit `/` (http://localhost:5000) to use a form similar to linux supervisord's inet_http_server.

- `GET /` - Web UI
- `POST /start_job` - Start a job
- `POST /stop_job` - Stop a job
- `POST /restart_job` - Restart a job
- `GET /jobs` - List job status

## Build

```bash
python build.py
```

Generates `winsupervisord.exe` in `dist/`

## License

MIT
