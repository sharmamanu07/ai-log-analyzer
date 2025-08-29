#!/usr/bin/env python3
"""
Generate sample log files for testing the AI log analysis system
This creates anonymized sample data for demonstration purposes
"""

import os
import random
from datetime import datetime, timedelta
from pathlib import Path

def generate_sample_logs():
    """Generate various types of sample log files"""
    
    # Create logs directory
    Path("logs").mkdir(exist_ok=True)
    
    # Generate different types of logs
    generate_security_logs()
    generate_backup_logs()
    generate_vault_logs()
    generate_system_logs()
    generate_web_server_logs()
    
    print("Sample log files generated in 'logs' directory:")
    print("- security.log (authentication and access logs)")
    print("- backup.log (backup system logs)")
    print("- vault.log (secret management logs)")
    print("- system.log (general system logs)")
    print("- apache_access.log (web server logs)")

def generate_security_logs():
    """Generate security/authentication logs"""
    
    base_time = datetime.now() - timedelta(days=7)
    
    # Sample IPs - anonymized but realistic
    ips = [
        '10.0.1.100', '10.0.1.101', '10.0.1.102',  # Internal IPs
        '203.0.113.10', '203.0.113.15',  # External IPs (RFC 5737)
        '198.51.100.20', '198.51.100.25',  # More external IPs
        '192.0.2.50'  # Suspicious IP
    ]
    
    users = ['admin', 'jdoe', 'ssmith', 'service_account', 'backup_user', 'developer1']
    
    logs = []
    
    # Generate normal authentication logs
    for i in range(1000):
        timestamp = base_time + timedelta(minutes=random.randint(0, 10080))  # 7 days
        ip = random.choice(ips[:5])  # Normal IPs
        user = random.choice(users)
        
        if random.random() < 0.95:  # 95% success rate
            logs.append(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} [INFO] auth: Successful login for user {user} from {ip}")
        else:
            logs.append(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} [WARN] auth: Failed login attempt for user {user} from {ip}")
    
    # Generate suspicious activity (failed login attempts)
    attack_time = base_time + timedelta(days=3, hours=2)
    for i in range(20):
        timestamp = attack_time + timedelta(minutes=i)
        logs.append(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} [ERROR] auth: Failed login attempt for user admin from 192.0.2.50")
    
    # Add some privilege escalation attempts
    for i in range(5):
        timestamp = attack_time + timedelta(hours=1, minutes=i*10)
        logs.append(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} [CRITICAL] auth: Unauthorized privilege escalation attempt by user jdoe from 10.0.1.101")
    
    # Write security logs
    with open("logs/security.log", "w") as f:
        for log in sorted(logs):
            f.write(log + "\n")

def generate_backup_logs():
    """Generate backup system logs"""
    
    base_time = datetime.now() - timedelta(days=7)
    logs = []
    
    backup_jobs = ['database_prod', 'fileserver_backup', 'user_data', 'config_backup', 'log_archive']
    
    # Generate daily backup logs
    for day in range(7):
        for job in backup_jobs:
            timestamp = base_time + timedelta(days=day, hours=2, minutes=random.randint(0, 60))
            
            if random.random() < 0.9:  # 90% success rate
                size = random.randint(500, 5000)
                duration = random.randint(10, 120)
                logs.append(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} INFO {job}: Backup completed successfully, {size}MB in {duration}min")
            else:
                error_msgs = [
                    "Cannot connect to storage backend",
                    "Insufficient disk space",
                    "Database connection timeout",
                    "Permission denied on target directory"
                ]
                error = random.choice(error_msgs)
                logs.append(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} ERROR {job}: Backup failed - {error}")
    
    # Add some critical backup failures
    critical_time = base_time + timedelta(days=5)
    for i in range(3):
        timestamp = critical_time + timedelta(hours=i*8)
        logs.append(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} CRITICAL database_prod: Multiple backup attempts failed - data loss risk!")
    
    with open("logs/backup.log", "w") as f:
        for log in sorted(logs):
            f.write(log + "\n")

def generate_vault_logs():
    """Generate HashiCorp Vault-style logs"""
    
    base_time = datetime.now() - timedelta(days=7)
    logs = []
    
    vault_paths = [
        'secret/database/credentials',
        'secret/api/keys', 
        'secret/ssl/certificates',
        'auth/ldap/login',
        'sys/policy'
    ]
    
    users = ['service_app1', 'service_app2', 'admin_user', 'deploy_service']
    
    # Generate normal vault operations
    for i in range(500):
        timestamp = base_time + timedelta(minutes=random.randint(0, 10080))
        user = random.choice(users)
        path = random.choice(vault_paths)
        
        operations = ['read', 'write', 'delete', 'list']
        op = random.choice(operations)
        
        if random.random() < 0.95:  # 95% success
            logs.append(f"{timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')} [INFO] core: {op} operation on {path} by {user} - success")
        else:
            logs.append(f"{timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')} [WARN] core: {op} operation on {path} by {user} - permission denied")
    
    # Add some suspicious vault access
    suspicious_time = base_time + timedelta(days=4, hours=22)  # Late night
    for i in range(15):
        timestamp = suspicious_time + timedelta(minutes=i*2)
        logs.append(f"{timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')} [ERROR] core: unauthorized access attempt to secret/database/credentials by unknown_user")
    
    with open("logs/vault.log", "w") as f:
        for log in sorted(logs):
            f.write(log + "\n")

def generate_system_logs():
    """Generate system/syslog style logs"""
    
    base_time = datetime.now() - timedelta(days=7)
    logs = []
    
    services = ['sshd', 'systemd', 'kernel', 'cron', 'NetworkManager']
    hosts = ['web-server-01', 'db-server-01', 'app-server-01']
    
    for i in range(800):
        timestamp = base_time + timedelta(minutes=random.randint(0, 10080))
        host = random.choice(hosts)
        service = random.choice(services)
        
        normal_messages = [
            "Service started successfully",
            "Configuration reloaded",
            "Health check passed",
            "Connection established",
            "Process completed"
        ]
        
        error_messages = [
            "Service failed to start",
            "Configuration error detected", 
            "Disk space low",
            "Network connection timeout",
            "Process crashed"
        ]
        
        if random.random() < 0.85:  # 85% normal
            message = random.choice(normal_messages)
            logs.append(f"{timestamp.strftime('%b %d %H:%M:%S')} {host} {service}: {message}")
        else:
            message = random.choice(error_messages)
            logs.append(f"{timestamp.strftime('%b %d %H:%M:%S')} {host} {service}: {message}")
    
    # Add some system alerts
    alert_time = base_time + timedelta(days=2, hours=14)
    for i in range(3):
        timestamp = alert_time + timedelta(hours=i)
        logs.append(f"{timestamp.strftime('%b %d %H:%M:%S')} db-server-01 kernel: Out of memory: Kill process 1234 (mysql)")
    
    with open("logs/system.log", "w") as f:
        for log in sorted(logs):
            f.write(log + "\n")

def generate_web_server_logs():
    """Generate Apache/Nginx style access logs"""
    
    base_time = datetime.now() - timedelta(days=7)
    logs = []
    
    ips = ['10.0.1.100', '10.0.1.101', '203.0.113.10', '198.51.100.20', '192.0.2.50']
    
    paths = [
        '/index.html', '/api/v1/users', '/api/v1/login', '/dashboard',
        '/admin/config.php', '/wp-admin/admin.php', '/.env',
        '/api/v1/data', '/health', '/metrics'
    ]
    
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'curl/7.68.0',
        'Python-urllib/3.8',
        'Googlebot/2.1'
    ]
    
    # Generate normal web traffic
    for i in range(2000):
        timestamp = base_time + timedelta(minutes=random.randint(0, 10080))
        ip = random.choice(ips[:4])  # Normal IPs
        path = random.choice(paths[:6])  # Normal paths
        status = random.choices([200, 404, 500, 301], weights=[80, 10, 5, 5])[0]
        size = random.randint(1024, 102400)
        user_agent = random.choice(user_agents)
        
        log_entry = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" {status} {size} "-" "{user_agent}"'
        logs.append((timestamp, log_entry))
    
    # Generate suspicious scanning activity
    scan_time = base_time + timedelta(days=3, hours=3)
    suspicious_paths = ['/admin/config.php', '/.env', '/wp-admin/admin.php', '/api/v1/admin', '/backup.sql']
    
    for i in range(50):
        timestamp = scan_time + timedelta(seconds=i*10)
        ip = '192.0.2.50'  # Suspicious IP
        path = random.choice(suspicious_paths)
        status = random.choices([404, 403, 401], weights=[70, 20, 10])[0]
        size = random.randint(0, 1024)
        
        log_entry = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" {status} {size} "-" "curl/7.68.0"'
        logs.append((timestamp, log_entry))
    
    # Sort logs by timestamp and write to file
    logs.sort(key=lambda x: x[0])
    
    with open("logs/apache_access.log", "w") as f:
        for _, log_entry in logs:
            f.write(log_entry + "\n")

if __name__ == "__main__":
