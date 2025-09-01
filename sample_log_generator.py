#!/usr/bin/env python3
"""
Fixed Sample Log Generator for AI-Augmented Log Analysis System
Creates realistic, comprehensive sample logs for demonstration and testing
"""

import os
import random
import json
from datetime import datetime, timedelta
from pathlib import Path

def generate_comprehensive_sample_logs():
    """Generate various types of sample log files with realistic scenarios"""
    
    # Create logs directory
    Path("logs").mkdir(exist_ok=True)
    
    print("🔄 Generating comprehensive sample logs...")
    
    # Generate different types of logs
    generate_security_logs()
    generate_backup_logs() 
    generate_vault_logs()
    generate_system_logs()
    generate_web_server_logs()
    generate_database_logs()
    generate_application_logs()
    
    print("✅ Sample log files generated:")
    for log_file in Path("logs").glob("*.log"):
        size = os.path.getsize(log_file)
        print(f"   📄 {log_file.name} ({size:,} bytes)")

def generate_security_logs():
    """Generate comprehensive security/authentication logs"""
    
    base_time = datetime.now() - timedelta(days=7)
    
    # Realistic IP addresses and users
    internal_ips = ['10.0.1.100', '10.0.1.101', '10.0.1.102', '10.0.1.103', '10.0.1.104']
    external_ips = ['203.0.113.10', '198.51.100.20', '192.0.2.50', '203.0.113.25', '198.51.100.30']
    users = ['admin', 'jdoe', 'ssmith', 'mwilson', 'kbrown', 'service_account', 'backup_user', 'developer1', 'analyst1']
    
    logs = []
    
    # Generate normal authentication activity (80% success rate)
    for day in range(7):
        day_start = base_time + timedelta(days=day, hours=8)  # Business hours start
        day_end = base_time + timedelta(days=day, hours=18)   # Business hours end
        
        # Business hours activity
        for _ in range(random.randint(50, 100)):
            timestamp = day_start + timedelta(minutes=random.randint(0, 600))  # 10 hours
            ip = random.choice(internal_ips)
            user = random.choice(users[:6])  # Normal users
            
            if random.random() < 0.85:  # 85% success rate during business hours
                logs.append(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} [INFO] auth: Successful login for user {user} from {ip}")
            else:
                logs.append(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} [WARN] auth: Failed login attempt for user {user} from {ip}")
    
    # Generate specific attack scenarios
    
    # Scenario 1: Brute force attack (day 3)
    attack_time = base_time + timedelta(days=3, hours=14, minutes=30)
    attacker_ip = '203.0.113.10'
    target_user = 'admin'
    
    for i in range(25):  # 25 failed attempts over 15 minutes
        timestamp = attack_time + timedelta(minutes=i//2)
        logs.append(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} [ERROR] auth: Failed login attempt for user {target_user} from {attacker_ip}")
    
    # Add successful breach after attempts
    breach_time = attack_time + timedelta(minutes=20)
    logs.append(f"{breach_time.strftime('%Y-%m-%d %H:%M:%S')} [CRITICAL] auth: Successful login for user {target_user} from {attacker_ip}")
    logs.append(f"{(breach_time + timedelta(minutes=2)).strftime('%Y-%m-%d %H:%M:%S')} [CRITICAL] auth: Privilege escalation attempt by user {target_user} from {attacker_ip}")
    
    # Write security logs
    with open("logs/security.log", "w") as f:
        for log in sorted(logs, key=lambda x: x[:19]):  # Sort by timestamp
            f.write(log + "\n")

def generate_backup_logs():
    """Generate realistic backup system logs"""
    
    base_time = datetime.now() - timedelta(days=7)
    logs = []
    
    backup_jobs = {
        'database_prod': {'size_range': (800, 1500), 'duration_range': (15, 45), 'failure_rate': 0.1},
        'fileserver_backup': {'size_range': (2000, 5000), 'duration_range': (30, 90), 'failure_rate': 0.15},
        'user_data': {'size_range': (500, 1000), 'duration_range': (20, 40), 'failure_rate': 0.08},
        'config_backup': {'size_range': (10, 50), 'duration_range': (2, 8), 'failure_rate': 0.12},
        'vault_backup': {'size_range': (50, 150), 'duration_range': (5, 15), 'failure_rate': 0.20}
    }
    
    error_messages = [
        "Cannot connect to storage backend",
        "Insufficient disk space on target",
        "Database connection timeout during backup",
        "Permission denied on target directory", 
        "Network timeout during transfer",
        "Backup verification failed"
    ]
    
    # Generate daily backup logs
    for day in range(7):
        for job_name, config in backup_jobs.items():
            # Most jobs run daily at 2 AM + some offset
            backup_time = base_time + timedelta(days=day, hours=2, minutes=random.randint(0, 60))
            
            if random.random() < config['failure_rate']:
                # Backup failed
                error_msg = random.choice(error_messages)
                logs.append(f"{backup_time.strftime('%Y-%m-%d %H:%M:%S')} ERROR {job_name}: Backup failed - {error_msg}")
            else:
                # Backup successful
                size = random.randint(*config['size_range'])
                duration = random.randint(*config['duration_range'])
                logs.append(f"{backup_time.strftime('%Y-%m-%d %H:%M:%S')} INFO {job_name}: Backup completed successfully, {size}MB in {duration}min")
    
    # Add critical backup incident (day 4)
    storage_failure_time = base_time + timedelta(days=4, hours=2, minutes=15)
    for job_name in ['database_prod', 'fileserver_backup']:
        logs.append(f"{storage_failure_time.strftime('%Y-%m-%d %H:%M:%S')} CRITICAL {job_name}: Backup failed - Primary storage system unreachable")
    
    with open("logs/backup.log", "w") as f:
        for log in sorted(logs, key=lambda x: x[:19]):
            f.write(log + "\n")

def generate_vault_logs():
    """Generate HashiCorp Vault-style logs"""
    
    base_time = datetime.now() - timedelta(days=7)
    logs = []
    
    vault_paths = [
        'secret/database/prod-credentials',
        'secret/api/external-keys',
        'secret/ssl/certificates',
        'secret/encryption/master-keys',
        'auth/ldap/config',
        'sys/policy/admin-policy'
    ]
    
    users = ['service_app1', 'service_app2', 'admin_user', 'deploy_service']
    operations = ['read', 'write', 'delete', 'list']
    
    # Generate normal vault operations
    for day in range(7):
        day_start = base_time + timedelta(days=day)
        
        # Normal operations throughout the day
        for _ in range(random.randint(50, 100)):
            timestamp = day_start + timedelta(minutes=random.randint(0, 1440))
            user = random.choice(users)
            path = random.choice(vault_paths)
            operation = random.choice(operations)
            
            if random.random() < 0.95:  # 95% success rate
                logs.append(f"{timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')} [INFO] core: {operation} operation on {path} by {user} - success")
            else:
                logs.append(f"{timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')} [WARN] core: {operation} operation on {path} by {user} - permission denied")
    
    # Generate suspicious vault access (day 2)
    attack_time = base_time + timedelta(days=2, hours=22, minutes=30)
    for i in range(15):
        timestamp = attack_time + timedelta(minutes=i*2)
        path = random.choice(['secret/database/prod-credentials', 'secret/encryption/master-keys'])
        logs.append(f"{timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')} [ERROR] core: read operation on {path} by unknown_user - authentication failed")
    
    # Vault seal event (day 5)
    seal_time = base_time + timedelta(days=5, hours=3, minutes=45)
    logs.append(f"{seal_time.strftime('%Y-%m-%dT%H:%M:%SZ')} [CRITICAL] core: Vault sealed due to security incident")
    logs.append(f"{(seal_time + timedelta(minutes=30)).strftime('%Y-%m-%dT%H:%M:%SZ')} [INFO] core: Vault successfully unsealed")
    
    with open("logs/vault.log", "w") as f:
        for log in sorted(logs, key=lambda x: x[:19]):
            f.write(log + "\n")

def generate_system_logs():
    """Generate system/syslog style logs - FIXED VERSION"""
    
    base_time = datetime.now() - timedelta(days=7)
    logs = []
    
    services = ['sshd', 'systemd', 'kernel', 'cron', 'NetworkManager']
    hosts = ['web-server-01', 'db-server-01', 'app-server-01']
    
    # Generate normal system activity
    for day in range(7):
        day_start = base_time + timedelta(days=day)
        
        for _ in range(random.randint(100, 200)):
            timestamp = day_start + timedelta(minutes=random.randint(0, 1440))
            host = random.choice(hosts)
            service = random.choice(services)
            
            # Simple, safe messages without complex formatting
            if service == 'sshd':
                user = random.choice(['root', 'admin', 'service'])
                ip = f"192.168.1.{random.randint(100, 200)}"
                messages = [
                    f"Accepted publickey for {user} from {ip}",
                    f"Connection closed by {ip}",
                    f"Starting session for {user}"
                ]
                message = random.choice(messages)
            
            elif service == 'systemd':
                service_name = random.choice(['nginx', 'mysql', 'redis'])
                messages = [
                    f"Started {service_name}.service",
                    f"Stopped {service_name}.service", 
                    "Reloading configuration",
                    f"{service_name}.service: Main process exited successfully"
                ]
                message = random.choice(messages)
            
            elif service == 'kernel':
                messages = [
                    "TCP: request_sock_TCP: Possible SYN flooding on port 80",
                    f"Out of memory: Kill process {random.randint(1000, 9999)}",
                    "EXT4-fs warning: running low on space"
                ]
                message = random.choice(messages)
            
            elif service == 'cron':
                user = random.choice(['root', 'backup'])
                messages = [
                    "(CRON) info (No MTA installed, discarding output)",
                    f"({user}) CMD (/usr/bin/backup-script)",
                    f"({user}) CMD (/usr/bin/system-cleanup)"
                ]
                message = random.choice(messages)
            
            else:  # NetworkManager or others
                messages = [
                    "Connection established",
                    "Interface eth0 up",
                    "DHCP lease renewed"
                ]
                message = random.choice(messages)
            
            logs.append(f"{timestamp.strftime('%b %d %H:%M:%S')} {host} {service}: {message}")
    
    # Generate system incidents
    
    # Incident 1: Disk space issues (day 3)
    disk_issue_time = base_time + timedelta(days=3, hours=10, minutes=15)
    for host in hosts:
        logs.append(f"{disk_issue_time.strftime('%b %d %H:%M:%S')} {host} kernel: EXT4-fs warning: running low on space")
        logs.append(f"{(disk_issue_time + timedelta(minutes=10)).strftime('%b %d %H:%M:%S')} {host} systemd: Cleaned up 2.1GB of temporary files")
    
    # Incident 2: Memory pressure (day 4)
    memory_issue_time = base_time + timedelta(days=4, hours=14, minutes=30)
    for i in range(5):
        timestamp = memory_issue_time + timedelta(minutes=i*2)
        pid = random.randint(1000, 9999)
        process = random.choice(['mysqld', 'apache2', 'python3'])
        logs.append(f"{timestamp.strftime('%b %d %H:%M:%S')} app-server-01 kernel: Out of memory: Kill process {pid} ({process})")
    
    with open("logs/system.log", "w") as f:
        # Sort by date (approximate, since we don't have year in the format)
        for log in sorted(logs):
            f.write(log + "\n")

def generate_web_server_logs():
    """Generate Apache/Nginx style access logs"""
    
    base_time = datetime.now() - timedelta(days=7)
    logs = []
    
    # IP addresses
    legitimate_ips = ['192.168.1.' + str(i) for i in range(100, 110)]
    malicious_ips = ['203.0.113.10', '198.51.100.20', '192.0.2.50']
    
    # Paths
    normal_paths = ['/', '/index.html', '/about', '/login', '/dashboard', '/api/v1/users']
    attack_paths = ['/admin/config.php', '/.env', '/backup.sql', '/phpmyadmin/']
    
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'curl/7.68.0'
    ]
    
    # Generate normal web traffic
    for day in range(7):
        day_start = base_time + timedelta(days=day)
        
        # Normal traffic during business hours
        for _ in range(random.randint(200, 400)):
            timestamp = day_start + timedelta(hours=random.randint(8, 18), minutes=random.randint(0, 59))
            ip = random.choice(legitimate_ips)
            path = random.choice(normal_paths)
            status = random.choices([200, 404, 500], weights=[85, 10, 5])[0]
            size = random.randint(1024, 51200)
            user_agent = random.choice(user_agents)
            
            logs.append(f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" {status} {size} "-" "{user_agent}"')
    
    # Generate attack scenarios
    
    # Scenario 1: Vulnerability scanning (day 2)
    scan_time = base_time + timedelta(days=2, hours=3, minutes=15)  # 3 AM
    scanner_ip = '203.0.113.10'
    
    for i in range(50):  # Rapid scanning
        timestamp = scan_time + timedelta(seconds=i*10)  # Every 10 seconds
        path = random.choice(attack_paths + normal_paths)
        status = random.choices([404, 403, 200], weights=[70, 20, 10])[0]
        size = random.randint(0, 5120)
        
        logs.append(f'{scanner_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" {status} {size} "-" "security-scanner/1.0"')
    
    # Scenario 2: SQL injection attempts (day 4)
    injection_time = base_time + timedelta(days=4, hours=11, minutes=30)
    attacker_ip = '198.51.100.20'
    
    injection_payloads = [
        "/login?username=admin'OR'1'='1",
        "/search?q=' UNION SELECT * FROM users--",
        "/product?id=1' OR 1=1--"
    ]
    
    for i in range(15):
        timestamp = injection_time + timedelta(minutes=i*2)
        payload = random.choice(injection_payloads)
        status = random.choices([400, 403, 500], weights=[50, 30, 20])[0]
        size = random.randint(500, 2048)
        
        logs.append(f'{attacker_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "POST {payload} HTTP/1.1" {status} {size} "-" "curl/7.68.0"')
    
    # Scenario 3: Successful breach and data exfiltration (day 6)
    breach_time = base_time + timedelta(days=6, hours=2, minutes=45)
    breach_ip = '203.0.113.25'
    
    # Initial successful login
    logs.append(f'{breach_ip} - - [{breach_time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "POST /login HTTP/1.1" 302 0 "-" "Mozilla/5.0 (X11; Linux x86_64)"')
    
    # Data exfiltration
    exfil_time = breach_time + timedelta(minutes=20)
    large_downloads = ['/export/users.csv', '/backup/database.sql']
    
    for i, download_path in enumerate(large_downloads):
        timestamp = exfil_time + timedelta(minutes=i*5)
        size = random.randint(10485760, 52428800)  # 10-50 MB files
        logs.append(f'{breach_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {download_path} HTTP/1.1" 200 {size} "-" "curl/7.68.0"')
    
    with open("logs/apache_access.log", "w") as f:
        # Sort logs by timestamp for realism
        sorted_logs = sorted(logs, key=lambda x: datetime.strptime(x.split('[')[1].split(']')[0], "%d/%b/%Y:%H:%M:%S +0000"))
        for log in sorted_logs:
            f.write(log + "\n")

def generate_database_logs():
    """Generate database audit and error logs"""
    
    base_time = datetime.now() - timedelta(days=7)
    logs = []
    
    # Database users and operations
    db_users = ['app_user', 'admin_user', 'backup_service', 'analytics_user']
    databases = ['production', 'staging', 'analytics']
    tables = ['users', 'orders', 'products', 'sessions']
    
    # Generate normal database activity
    for day in range(7):
        day_start = base_time + timedelta(days=day)
        
        # Business hours database activity
        for _ in range(random.randint(200, 400)):
            timestamp = day_start + timedelta(hours=random.randint(6, 22), minutes=random.randint(0, 59))
            user = random.choice(db_users)
            database = random.choice(databases)
            table = random.choice(tables)
            operation = random.choices(['SELECT', 'INSERT', 'UPDATE', 'DELETE'], weights=[60, 20, 15, 5])[0]
            
            if operation == 'SELECT' and random.random() < 0.1:  # 10% of selects are slow
                duration = random.uniform(2.0, 10.0)
                logs.append(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} [WARN] SLOW QUERY: {operation} FROM {database}.{table} by {user} - {duration:.2f}s")
            else:
                duration = random.uniform(0.01, 1.0)
                logs.append(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} [INFO] QUERY: {operation} {database}.{table} by {user} - {duration:.2f}s")
    
    # Database incidents
    
    # Incident 1: Connection pool exhaustion (day 2)
    pool_issue_time = base_time + timedelta(days=2, hours=13, minutes=45)
    for i in range(15):
        timestamp = pool_issue_time + timedelta(minutes=i)
        logs.append(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} [ERROR] CONNECTION: Pool exhausted, rejecting connection from app_user")
    
    # Recovery
    recovery_time = pool_issue_time + timedelta(minutes=20)
    logs.append(f"{recovery_time.strftime('%Y-%m-%d %H:%M:%S')} [INFO] ADMIN: Connection pool size increased")
    
    # Incident 2: Suspicious data access (day 4)
    suspicious_time = base_time + timedelta(days=4, hours=22, minutes=30)  # Off hours
    suspicious_user = 'analytics_user'
    
    # Unusual access pattern
    for i in range(20):
        timestamp = suspicious_time + timedelta(minutes=i*2)
        table = random.choice(['users', 'sessions', 'transactions'])
        logs.append(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} [WARN] AUDIT: SELECT * FROM production.{table} by {suspicious_user} - unusual access pattern")
    
    # Large data extraction
    bulk_time = suspicious_time + timedelta(hours=1)
    logs.append(f"{bulk_time.strftime('%Y-%m-%d %H:%M:%S')} [CRITICAL] AUDIT: Bulk SELECT query returned 50000+ rows from production.users by {suspicious_user}")
    
    with open("logs/database.log", "w") as f:
        for log in sorted(logs, key=lambda x: x[:19]):
            f.write(log + "\n")

def generate_application_logs():
    """Generate application-specific logs"""
    
    base_time = datetime.now() - timedelta(days=7)
    logs = []
    
    # Application components
    components = ['auth-service', 'user-service', 'order-service', 'payment-service']
    log_levels = ['INFO', 'WARN', 'ERROR', 'FATAL']
    
    # Generate normal application logs
    for day in range(7):
        day_start = base_time + timedelta(days=day)
        
        for _ in range(random.randint(200, 400)):
            timestamp = day_start + timedelta(minutes=random.randint(0, 1440))
            component = random.choice(components)
            level = random.choices(log_levels, weights=[70, 20, 8, 2])[0]  # Mostly INFO logs
            
            # Generate realistic messages
            user_id = random.randint(1000, 9999)
            
            if component == 'auth-service':
                messages = [
                    f'User authentication successful for user_id: {user_id}',
                    f'Token refresh for user_id: {user_id}',
                    f'Invalid login attempt for user_id: {user_id}'
                ]
            elif component == 'user-service':
                messages = [
                    f'User profile updated for user_id: {user_id}',
                    f'New user registration: user_id {user_id}',
                    f'Failed to load user profile for user_id: {user_id}'
                ]
            elif component == 'order-service':
                order_id = random.randint(10000, 99999)
                messages = [
                    f'Order created: order_id {order_id}',
                    f'Order status updated: order_id {order_id}',
                    f'Payment processed for order_id: {order_id}'
                ]
            else:  # payment-service
                transaction_id = random.randint(100000, 999999)
                messages = [
                    f'Payment authorization successful: transaction_id {transaction_id}',
                    'Payment declined: insufficient funds',
                    f'Refund processed: transaction_id {transaction_id}'
                ]
            
            message = random.choice(messages)
            logs.append(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} [{level}] {component}: {message}")
    
    # Application incidents
    
    # Incident 1: Payment service outage (day 3)
    outage_time = base_time + timedelta(days=3, hours=14, minutes=30)
    for i in range(30):  # 30 minutes of issues
        timestamp = outage_time + timedelta(minutes=i)
        if i < 10:
            logs.append(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} [ERROR] payment-service: Connection timeout to payment gateway")
        elif i < 20:
            logs.append(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} [FATAL] payment-service: Service unavailable - circuit breaker open")
        else:
            logs.append(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} [INFO] payment-service: Service restored - circuit breaker closed")
    
    # Incident 2: Security breach in auth-service (day 6)
    breach_time = base_time + timedelta(days=6, hours=16, minutes=45)
    
    # Unusual authentication patterns
    for i in range(15):
        timestamp = breach_time + timedelta(minutes=i*2)
        user_id = random.randint(1000, 1500)
        logs.append(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} [WARN] auth-service: Failed login attempt for user_id: {user_id} from IP: 203.0.113.10")
    
    # Successful breach
    compromise_time = breach_time + timedelta(minutes=35)
    logs.append(f"{compromise_time.strftime('%Y-%m-%d %H:%M:%S')} [ERROR] auth-service: Successful login for admin user from unauthorized IP: 203.0.113.10")
    logs.append(f"{(compromise_time + timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S')} [CRITICAL] user-service: Bulk user data access from compromised session")
    
    # Incident response
    response_time = compromise_time + timedelta(minutes=15)
    logs.append(f"{response_time.strftime('%Y-%m-%d %H:%M:%S')} [INFO] auth-service: Emergency session termination for suspicious activity")
    
    with open("logs/application.log", "w") as f:
        for log in sorted(logs, key=lambda x: x[:19]):
            f.write(log + "\n")

def generate_summary_report():
    """Generate a summary of all created logs"""
    
    summary = {
        'generation_time': datetime.now().isoformat(),
        'period_covered': '7 days',
        'files_created': [],
        'scenarios_included': [
            'Brute force authentication attacks',
            'Vault security breaches',
            'System resource exhaustion',
            'Backup system failures',
            'Web application attacks (SQL injection, scanning)',
            'Database corruption and recovery',
            'Application service outages',
            'Data exfiltration attempts'
        ]
    }
    
    # Count log entries in each file
    log_files = ['security.log', 'backup.log', 'vault.log', 'system.log', 
                 'apache_access.log', 'database.log', 'application.log']
    
    for log_file in log_files:
        file_path = f"logs/{log_file}"
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                line_count = sum(1 for line in f)
            
            file_size = os.path.getsize(file_path)
            summary['files_created'].append({
                'filename': log_file,
                'entries': line_count,
                'size_bytes': file_size,
                'size_human': f"{file_size:,} bytes"
            })
    
    # Save summary
    with open("logs/generation_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    
    return summary

if __name__ == "__main__":
    print("🚀 Enhanced Sample Log Generator")
    print("=" * 50)
    
    generate_comprehensive_sample_logs()
    summary = generate_summary_report()
    
    print(f"\n📊 Generation Summary:")
    print(f"   📅 Period: {summary['period_covered']}")
    print(f"   📁 Files created: {len(summary['files_created'])}")
    
    total_entries = sum(file_info['entries'] for file_info in summary['files_created'])
    total_size = sum(file_info['size_bytes'] for file_info in summary['files_created'])
    
    print(f"   📝 Total log entries: {total_entries:,}")
    print(f"   💾 Total size: {total_size:,} bytes")
    
    print(f"\n🎯 Realistic scenarios included:")
    for scenario in summary['scenarios_included']:
        print(f"   • {scenario}")
    
    print(f"\n✅ Ready for AI analysis!")
    print(f"   • 'Which systems had the most critical issues?'")
    print(f"   • 'Show me signs of coordinated attacks'")
