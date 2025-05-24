tailwind.config = {
    theme: {
        extend: {
            colors: {
                cyber: {
                    primary: '#00f7ff',
                    secondary: '#ff00f7',
                    dark: '#0a0a1a',
                    darker: '#050510',
                    panel: 'rgba(15, 15, 35, 0.8)'
                }
            },
            animation: {
                'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                'glow': 'glow 2s ease-in-out infinite alternate',
                'glow-blue': 'glow-blue 2s ease-in-out infinite alternate',
                'glow-pink': 'glow-pink 2s ease-in-out infinite alternate',
            },
            keyframes: {
                glow: {
                    'from': { 'box-shadow': '0 0 5px #00f7ff' },
                    'to': { 'box-shadow': '0 0 20px #00f7ff' }
                },
                'glow-blue': {
                    'from': { 'box-shadow': '0 0 5px #00f7ff' },
                    'to': { 'box-shadow': '0 0 20px #00f7ff' }
                },
                'glow-pink': {
                    'from': { 'box-shadow': '0 0 5px #ff00f7' },
                    'to': { 'box-shadow': '0 0 20px #ff00f7' }
                }
            }
        }
    }
}


// Sample data for logs
const systemLogs = [
    { timestamp: '2023-07-18 09:15:23', level: 'INFO', model: 'Kitsune', message: 'Initialisation du système terminée' },
    { timestamp: '2023-07-18 09:16:45', level: 'INFO', model: 'LUCID', message: 'Mode de surveillance activé' },
    { timestamp: '2023-07-18 09:18:12', level: 'WARNING', model: 'Kitsune', message: 'Activité réseau inhabituelle détectée' },
    { timestamp: '2023-07-18 09:20:37', level: 'INFO', model: 'Vertex AI', message: 'Modèle chargé avec succès' },
    { timestamp: '2023-07-18 09:22:05', level: 'ERROR', model: 'Kitsune', message: 'Échec de connexion à la base de données' },
    { timestamp: '2023-07-18 09:25:18', level: 'INFO', model: 'LUCID', message: 'Analyse des paquets en cours' },
    { timestamp: '2023-07-18 09:28:42', level: 'WARNING', model: 'Vertex AI', message: 'Confiance du modèle en dessous du seuil' },
    { timestamp: '2023-07-18 09:30:15', level: 'INFO', model: 'Kitsune', message: 'Sauvegarde des logs effectuée' },
    { timestamp: '2023-07-18 09:33:27', level: 'ERROR', model: 'LUCID', message: 'Timeout lors de l\'analyse' },
    { timestamp: '2023-07-18 09:35:50', level: 'INFO', model: 'Vertex AI', message: 'Nouvelle prédiction générée' }
];

// Sample data for user activity
const userActivities = [
    { username: 'admin_kitsune', action: 'Connexion', timestamp: '2023-07-18 08:30:15', result: 'success' },
    { username: 'analyst_1', action: 'Mise à jour règles', timestamp: '2023-07-18 08:42:33', result: 'success' },
    { username: 'auditor_2', action: 'Export données', timestamp: '2023-07-18 09:05:47', result: 'fail' },
    { username: 'admin_kitsune', action: 'Modification paramètres', timestamp: '2023-07-18 09:18:22', result: 'success' },
    { username: 'analyst_3', action: 'Connexion', timestamp: '2023-07-18 09:25:10', result: 'fail' },
    { username: 'auditor_1', action: 'Lecture logs', timestamp: '2023-07-18 09:40:55', result: 'success' }
];

// Sample data for analysis
const analyses = [
    { file: 'traffic_0718.pcap', models: 'Kitsune+LUCID', score: '0.92', duration: '2m 15s', verdict: 'Clean', status: 'Completed' },
    { file: 'suspicious_0717.pcap', models: 'Kitsune+Vertex', score: '0.65', duration: '3m 42s', verdict: 'Suspect', status: 'Completed' },
    { file: 'malware_sample.pcap', models: 'All', score: '0.23', duration: '1m 58s', verdict: 'Malicious', status: 'Completed' },
    { file: 'network_dump.pcap', models: 'LUCID', score: '0.78', duration: '4m 15s', verdict: 'Clean', status: 'Failed' },
    { file: 'internal_scan.pcap', models: 'Kitsune', score: '0.85', duration: '2m 30s', verdict: 'Clean', status: 'Completed' },
    { file: 'external_probe.pcap', models: 'Vertex AI', score: '0.41', duration: '3m 05s', verdict: 'Suspect', status: 'Completed' }
];

// Initialize the dashboard
document.addEventListener('DOMContentLoaded', function() {
    // Populate system logs
    const systemLogsContainer = document.getElementById('systemLogs');
    systemLogs.forEach(log => {
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry ${log.level}`;
        logEntry.innerHTML = `
            <span class="text-gray-400">[${log.timestamp}]</span>
            <span class="font-bold ${log.level === 'INFO' ? 'text-cyber-primary' : log.level === 'WARNING' ? 'text-yellow-500' : 'text-red-500'}">${log.level}</span>
            <span class="text-cyber-primary">${log.model}:</span>
            <span>${log.message}</span>
        `;
        systemLogsContainer.appendChild(logEntry);
    });

    // Populate user activity
    const userActivityContainer = document.getElementById('userActivity');
    userActivities.forEach(activity => {
        const card = document.createElement('div');
        card.className = 'user-card p-4 rounded-lg animate-glow-pink';
        card.innerHTML = `
            <div class="flex justify-between items-start mb-2">
                <h3 class="font-bold text-cyber-secondary">${activity.username}</h3>
                <span class="text-xs text-gray-400">${activity.timestamp}</span>
            </div>
            <p class="text-sm mb-3">Action: ${activity.action}</p>
            <div class="flex justify-between items-center">
                <span class="text-xs px-2 py-1 rounded-full ${activity.result === 'success' ? 'success-badge' : 'fail-badge'}">
                    ${activity.result === 'success' ? 'Succès' : 'Échec'}
                </span>
                <button class="text-xs text-cyber-secondary hover:text-cyber-primary">
                    <i class="fas fa-ellipsis-h"></i>
                </button>
            </div>
        `;
        userActivityContainer.appendChild(card);
    });

    // Populate analysis table
    const analysisTable = document.getElementById('analysisTable');
    analyses.forEach(analysis => {
        const row = document.createElement('tr');
        row.className = `analysis-row ${analysis.status === 'Failed' ? 'text-red-500' : ''}`;
        row.innerHTML = `
            <td class="py-3">${analysis.file}</td>
            <td>${analysis.models}</td>
            <td>${analysis.score}</td>
            <td>${analysis.duration}</td>
            <td class="${analysis.verdict === 'Clean' ? 'text-cyber-primary' : analysis.verdict === 'Suspect' ? 'text-yellow-500' : 'text-red-500'}">
                ${analysis.verdict}
            </td>
            <td class="${analysis.status === 'Completed' ? 'text-cyber-primary' : 'text-red-500'}">
                ${analysis.status}
            </td>
            <td class="text-right">
                <button class="text-cyber-secondary hover:text-cyber-primary">
                    <i class="fas fa-download"></i>
                </button>
            </td>
        `;
        analysisTable.appendChild(row);
    });

    // Panel toggle functionality
    const panelHeaders = document.querySelectorAll('.panel-header');
    panelHeaders.forEach(header => {
        header.addEventListener('click', function() {
            const panel = this.nextElementSibling;
            const icon = this.querySelector('.toggle-panel i');
            
            if (panel.style.maxHeight) {
                panel.style.maxHeight = null;
                icon.className = 'fas fa-chevron-down';
            } else {
                panel.style.maxHeight = panel.scrollHeight + 'px';
                icon.className = 'fas fa-chevron-up';
            }
        });
    });

    // Filter logs by level
    const filterButtons = document.querySelectorAll('.filter-btn');
    filterButtons.forEach(button => {
        button.addEventListener('click', function() {
            const filter = this.getAttribute('data-filter');
            
            // Update active state
            filterButtons.forEach(btn => btn.classList.remove('filter-active'));
            if (filter !== 'all') this.classList.add('filter-active');
            
            // Filter logs
            const logEntries = document.querySelectorAll('.log-entry');
            logEntries.forEach(entry => {
                if (filter === 'all' || entry.classList.contains(filter)) {
                    entry.style.display = 'block';
                } else {
                    entry.style.display = 'none';
                }
            });
        });
    });

    // Show failed analyses only toggle
    const showFailedOnly = document.getElementById('showFailedOnly');
    showFailedOnly.addEventListener('change', function() {
        const rows = document.querySelectorAll('.analysis-row');
        rows.forEach(row => {
            if (this.checked) {
                if (row.textContent.includes('Failed')) {
                    row.style.display = 'table-row';
                } else {
                    row.style.display = 'none';
                }
            } else {
                row.style.display = 'table-row';
            }
        });
    });

    // Refresh button
    document.getElementById('refreshBtn').addEventListener('click', function() {
        this.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Actualisation...';
        setTimeout(() => {
            this.innerHTML = '<i class="fas fa-sync-alt mr-2"></i>🔄 Actualiser';
            // In a real app, you would fetch new data here
        }, 1500);
    });

    // Export button
    document.getElementById('exportBtn').addEventListener('click', function() {
        this.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Export...';
        setTimeout(() => {
            this.innerHTML = '<i class="fas fa-file-export mr-2"></i>Exporter CSV';
            alert('Export CSV démarré!');
        }, 1000);
    });

    // Toggle switch animation
    const toggleSwitches = document.querySelectorAll('.toggle-checkbox');
    toggleSwitches.forEach(switchEl => {
        switchEl.addEventListener('change', function() {
            const dot = this.nextElementSibling.querySelector('.dot');
            if (this.checked) {
                dot.classList.remove('translate-x-0');
                dot.classList.add('translate-x-5');
            } else {
                dot.classList.remove('translate-x-5');
                dot.classList.add('translate-x-0');
            }
        });
    });
});

// Simulate real-time log updates
setInterval(() => {
    const levels = ['INFO', 'WARNING', 'ERROR'];
    const models = ['Kitsune', 'LUCID', 'Vertex AI'];
    const messages = [
        'Nouvelle connexion détectée',
        'Analyse des paquets en cours',
        'Activité suspecte détectée',
        'Mise à jour des règles effectuée',
        'Timeout lors de la requête',
        'Sauvegarde des logs terminée'
    ];
    
    const now = new Date();
    const timestamp = now.toISOString().replace('T', ' ').substring(0, 19);
    const level = levels[Math.floor(Math.random() * levels.length)];
    const model = models[Math.floor(Math.random() * models.length)];
    const message = messages[Math.floor(Math.random() * messages.length)];
    
    const logEntry = document.createElement('div');
    logEntry.className = `log-entry ${level}`;
    logEntry.innerHTML = `
        <span class="text-gray-400">[${timestamp}]</span>
        <span class="font-bold ${level === 'INFO' ? 'text-cyber-primary' : level === 'WARNING' ? 'text-yellow-500' : 'text-red-500'}">${level}</span>
        <span class="text-cyber-primary">${model}:</span>
        <span>${message}</span>
    `;
    
    const logsContainer = document.getElementById('systemLogs');
    logsContainer.insertBefore(logEntry, logsContainer.firstChild);
    
    // Keep only the last 50 logs
    if (logsContainer.children.length > 50) {
        logsContainer.removeChild(logsContainer.lastChild);
    }
    
    // Auto-scroll if not scrolled up
    if (logsContainer.scrollTop === 0) {
        logsContainer.scrollTop = 0;
    }
}, 3000);