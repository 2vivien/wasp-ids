// Sample alert data
const alerts = [
    {
        id: 'ALERT-2025-05-02-001',
        timestamp: '2025-05-02 15:36',
        file: 'wednesday.pcap',
        sourceIP: '192.168.1.45',
        destIP: '104.18.25.93',
        model: 'Kitsune',
        score: 0.85,
        verdict: '🚨 Anomalie',
        severity: 'high',
        sourcePort: 49234,
        destPort: 443,
        protocol: 'TCP',
        payloadSize: '1.2 MB',
        flowDuration: '2 minutes 34 seconds',
        kitsuneScore: 0.85,
        lucidDetection: 'Zero-Day',
        vertexLabel: 'DoS',
        vertexConfidence: 0.92,
        recommendations: ['Isoler IP', 'Vérifier flux', 'Augmenter seuil modèle Kitsune']
    },
    {
        id: 'ALERT-2025-05-02-002',
        timestamp: '2025-05-02 14:22',
        file: 'thursday.pcap',
        sourceIP: '10.0.0.12',
        destIP: '172.217.14.206',
        model: 'LUCID',
        score: 0.78,
        verdict: '🔥 Zero-Day',
        severity: 'high',
        sourcePort: 54123,
        destPort: 80,
        protocol: 'HTTP',
        payloadSize: '3.5 MB',
        flowDuration: '5 minutes 12 seconds',
        kitsuneScore: 0.62,
        lucidDetection: 'Zero-Day',
        vertexLabel: 'Phishing',
        vertexConfidence: 0.87,
        recommendations: ['Isoler IP', 'Analyser payload', 'Bloquer domaine']
    },
    {
        id: 'ALERT-2025-05-02-003',
        timestamp: '2025-05-02 13:15',
        file: 'friday.pcap',
        sourceIP: '192.168.1.67',
        destIP: '35.186.238.101',
        model: 'Vertex AI',
        score: 0.65,
        verdict: '🚨 Anomalie',
        severity: 'medium',
        sourcePort: 32891,
        destPort: 443,
        protocol: 'TLS',
        payloadSize: '850 KB',
        flowDuration: '1 minute 48 seconds',
        kitsuneScore: 0.45,
        lucidDetection: 'Normal',
        vertexLabel: 'Anomalie',
        vertexConfidence: 0.65,
        recommendations: ['Vérifier flux', 'Analyser certificat']
    },
    {
        id: 'ALERT-2025-05-02-004',
        timestamp: '2025-05-02 12:08',
        file: 'saturday.pcap',
        sourceIP: '10.0.0.45',
        destIP: '8.8.8.8',
        model: 'Kitsune',
        score: 0.42,
        verdict: '✅ Normal',
        severity: 'low',
        sourcePort: 49876,
        destPort: 53,
        protocol: 'UDP',
        payloadSize: '120 KB',
        flowDuration: '45 seconds',
        kitsuneScore: 0.42,
        lucidDetection: 'Normal',
        vertexLabel: 'Normal',
        vertexConfidence: 0.95,
        recommendations: ['Aucune action requise']
    },
    {
        id: 'ALERT-2025-05-02-005',
        timestamp: '2025-05-02 11:30',
        file: 'sunday.pcap',
        sourceIP: '192.168.1.89',
        destIP: '142.250.190.46',
        model: 'Vertex AI',
        score: 0.91,
        verdict: '🔥 Zero-Day',
        severity: 'high',
        sourcePort: 54128,
        destPort: 443,
        protocol: 'HTTPS',
        payloadSize: '2.8 MB',
        flowDuration: '3 minutes 22 seconds',
        kitsuneScore: 0.78,
        lucidDetection: 'Zero-Day',
        vertexLabel: 'Exploit',
        vertexConfidence: 0.91,
        recommendations: ['Isoler IP', 'Analyser payload', 'Mettre à jour IDS']
    },
    {
        id: 'ALERT-2025-05-02-006',
        timestamp: '2025-05-02 10:45',
        file: 'monday.pcap',
        sourceIP: '10.0.0.22',
        destIP: '172.217.14.195',
        model: 'LUCID',
        score: 0.55,
        verdict: '✅ Normal',
        severity: 'low',
        sourcePort: 49872,
        destPort: 80,
        protocol: 'HTTP',
        payloadSize: '750 KB',
        flowDuration: '1 minute 15 seconds',
        kitsuneScore: 0.35,
        lucidDetection: 'Normal',
        vertexLabel: 'Normal',
        vertexConfidence: 0.98,
        recommendations: ['Aucune action requise']
    },
    {
        id: 'ALERT-2025-05-02-007',
        timestamp: '2025-05-02 09:20',
        file: 'tuesday.pcap',
        sourceIP: '192.168.1.33',
        destIP: '104.16.85.20',
        model: 'Kitsune',
        score: 0.72,
        verdict: '🚨 Anomalie',
        severity: 'medium',
        sourcePort: 54129,
        destPort: 443,
        protocol: 'TLS',
        payloadSize: '1.5 MB',
        flowDuration: '2 minutes 10 seconds',
        kitsuneScore: 0.72,
        lucidDetection: 'Anomalie',
        vertexLabel: 'Anomalie',
        vertexConfidence: 0.68,
        recommendations: ['Vérifier flux', 'Analyser certificat']
    },
    {
        id: 'ALERT-2025-05-02-008',
        timestamp: '2025-05-02 08:15',
        file: 'wednesday.pcap',
        sourceIP: '10.0.0.18',
        destIP: '142.250.190.46',
        model: 'Vertex AI',
        score: 0.88,
        verdict: '🔥 Zero-Day',
        severity: 'high',
        sourcePort: 49879,
        destPort: 443,
        protocol: 'HTTPS',
        payloadSize: '3.2 MB',
        flowDuration: '4 minutes 5 seconds',
        kitsuneScore: 0.75,
        lucidDetection: 'Zero-Day',
        vertexLabel: 'Malware',
        vertexConfidence: 0.88,
        recommendations: ['Isoler IP', 'Analyser payload', 'Scanner endpoint']
    },
    {
        id: 'ALERT-2025-05-02-009',
        timestamp: '2025-05-02 07:30',
        file: 'thursday.pcap',
        sourceIP: '192.168.1.52',
        destIP: '8.8.4.4',
        model: 'LUCID',
        score: 0.38,
        verdict: '✅ Normal',
        severity: 'low',
        sourcePort: 54130,
        destPort: 53,
        protocol: 'UDP',
        payloadSize: '95 KB',
        flowDuration: '30 seconds',
        kitsuneScore: 0.38,
        lucidDetection: 'Normal',
        vertexLabel: 'Normal',
        vertexConfidence: 0.96,
        recommendations: ['Aucune action requise']
    },
    {
        id: 'ALERT-2025-05-02-010',
        timestamp: '2025-05-02 06:45',
        file: 'friday.pcap',
        sourceIP: '10.0.0.29',
        destIP: '104.18.25.93',
        model: 'Kitsune',
        score: 0.68,
        verdict: '🚨 Anomalie',
        severity: 'medium',
        sourcePort: 49880,
        destPort: 443,
        protocol: 'TLS',
        payloadSize: '1.8 MB',
        flowDuration: '2 minutes 50 seconds',
        kitsuneScore: 0.68,
        lucidDetection: 'Anomalie',
        vertexLabel: 'Anomalie',
        vertexConfidence: 0.72,
        recommendations: ['Vérifier flux', 'Analyser certificat']
    }
];

// Current sort state
let currentSort = {
    column: 'timestamp',
    direction: 'asc'
};

// Pagination state
const itemsPerPage = 5;
let currentPage = 1;
let filteredAlerts = [...alerts];

// Initialize the table
function initTable() {
    renderTable();
    setupEventListeners();
    updatePagination();
}

// Render the table with current alerts
function renderTable() {
    const tableBody = document.getElementById('alertTableBody');
    tableBody.innerHTML = '';
    
    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = Math.min(startIndex + itemsPerPage, filteredAlerts.length);
    
    document.getElementById('startItem').textContent = startIndex + 1;
    document.getElementById('endItem').textContent = endIndex;
    document.getElementById('totalItems').textContent = filteredAlerts.length;
    
    for (let i = startIndex; i < endIndex; i++) {
        const alert = filteredAlerts[i];
        const row = document.createElement('tr');
        row.className = `alert-row border-b border-gray-700 ${alert.severity === 'high' ? 'critical-alert' : ''}`;
        row.dataset.id = alert.id;
        
        row.innerHTML = `
            <td class="px-4 py-3 tooltip">
                ${alert.timestamp}
                <div class="tooltip-text">
                    <strong>ID:</strong> ${alert.id}<br>
                    <strong>Heure exacte:</strong> ${alert.timestamp}:00
                </div>
            </td>
            <td class="px-4 py-3 tooltip">
                ${alert.file}
                <div class="tooltip-text">
                    <strong>Taille:</strong> ${alert.payloadSize}<br>
                    <strong>Durée:</strong> ${alert.flowDuration}
                </div>
            </td>
            <td class="px-4 py-3 tooltip">
                <span class="font-mono">${alert.sourceIP}</span> → <span class="font-mono">${alert.destIP}</span>
                <div class="tooltip-text">
                    <strong>Ports:</strong> ${alert.sourcePort} → ${alert.destPort}<br>
                    <strong>Protocole:</strong> ${alert.protocol}
                </div>
            </td>
            <td class="px-4 py-3">
                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                    alert.model === 'Kitsune' ? 'bg-blue-900 text-blue-300' : 
                    alert.model === 'LUCID' ? 'bg-purple-900 text-purple-300' : 
                    'bg-orange-900 text-orange-300'
                }">
                    ${alert.model}
                </span>
            </td>
            <td class="px-4 py-3">
                <div class="flex items-center">
                    <div class="w-16 mr-2">
                        <div class="progress-bar">
                            <div class="progress-fill ${
                                alert.severity === 'high' ? 'high-severity' : 
                                alert.severity === 'medium' ? 'medium-severity' : 
                                'low-severity'
                            }" style="width: ${alert.score * 100}%"></div>
                        </div>
                    </div>
                    <span class="text-sm font-mono">${alert.score.toFixed(2)}</span>
                </div>
            </td>
            <td class="px-4 py-3">
                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                    alert.verdict.includes('Anomalie') ? 'bg-red-900 text-red-300' : 
                    alert.verdict.includes('Zero-Day') ? 'bg-yellow-900 text-yellow-300' : 
                    'bg-green-900 text-green-300'
                }">
                    ${alert.verdict}
                </span>
            </td>
        `;
        
        row.addEventListener('click', () => openModal(alert));
        tableBody.appendChild(row);
    }
}

// Update pagination controls
function updatePagination() {
    const pagination = document.getElementById('pagination');
    pagination.innerHTML = '';
    
    const totalPages = Math.ceil(filteredAlerts.length / itemsPerPage);
    
    if (currentPage > 1) {
        const prevBtn = document.createElement('button');
        prevBtn.className = 'pagination-btn px-3 py-1 rounded-lg';
        prevBtn.innerHTML = '<i class="fas fa-chevron-left"></i>';
        prevBtn.addEventListener('click', () => {
            currentPage--;
            renderTable();
            updatePagination();
        });
        pagination.appendChild(prevBtn);
    }
    
    for (let i = 1; i <= totalPages; i++) {
        const pageBtn = document.createElement('button');
        pageBtn.className = `pagination-btn px-3 py-1 rounded-lg ${i === currentPage ? 'active' : ''}`;
        pageBtn.textContent = i;
        pageBtn.addEventListener('click', () => {
            currentPage = i;
            renderTable();
            updatePagination();
        });
        pagination.appendChild(pageBtn);
    }
    
    if (currentPage < totalPages) {
        const nextBtn = document.createElement('button');
        nextBtn.className = 'pagination-btn px-3 py-1 rounded-lg';
        nextBtn.innerHTML = '<i class="fas fa-chevron-right"></i>';
        nextBtn.addEventListener('click', () => {
            currentPage++;
            renderTable();
            updatePagination();
        });
        pagination.appendChild(nextBtn);
    }
}

// Sort alerts by column
function sortAlerts(column) {
    if (currentSort.column === column) {
        currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
    } else {
        currentSort.column = column;
        currentSort.direction = 'asc';
    }
    
    filteredAlerts.sort((a, b) => {
        let valueA, valueB;
        
        switch (column) {
            case 'timestamp':
                valueA = new Date(a.timestamp);
                valueB = new Date(b.timestamp);
                break;
            case 'file':
                valueA = a.file.toLowerCase();
                valueB = b.file.toLowerCase();
                break;
            case 'model':
                valueA = a.model.toLowerCase();
                valueB = b.model.toLowerCase();
                break;
            case 'score':
                valueA = a.score;
                valueB = b.score;
                break;
            case 'verdict':
                valueA = a.verdict.toLowerCase();
                valueB = b.verdict.toLowerCase();
                break;
            default:
                valueA = a[column];
                valueB = b[column];
        }
        
        if (valueA < valueB) {
            return currentSort.direction === 'asc' ? -1 : 1;
        }
        if (valueA > valueB) {
            return currentSort.direction === 'asc' ? 1 : -1;
        }
        return 0;
    });
    
    currentPage = 1;
    renderTable();
    updatePagination();
}

// Filter alerts based on toggle and model filter
function filterAlerts() {
    const criticalOnly = document.getElementById('criticalToggle').checked;
    const modelFilter = document.getElementById('modelFilter').value;
    
    filteredAlerts = alerts.filter(alert => {
        const matchesCritical = !criticalOnly || alert.severity === 'high';
        const matchesModel = modelFilter === 'all' || alert.model === modelFilter;
        return matchesCritical && matchesModel;
    });
    
    currentPage = 1;
    renderTable();
    updatePagination();
}

// Open modal with alert details
function openModal(alert) {
    const modal = document.getElementById('alertModal');
    const modalContent = document.getElementById('modalContent');
    
    // Set modal content
    document.getElementById('modalTitle').innerHTML = `
        <i class="fas fa-${alert.severity === 'high' ? 'exclamation-triangle' : 'info-circle'} mr-2"></i> 
        Détail d'une Alerte
    `;
    document.getElementById('modalSubtitle').textContent = `ID: ${alert.id}`;
    document.getElementById('modalSourceIP').textContent = alert.sourceIP;
    document.getElementById('modalDestIP').textContent = alert.destIP;
    document.getElementById('modalSourcePort').textContent = alert.sourcePort;
    document.getElementById('modalDestPort').textContent = alert.destPort;
    document.getElementById('modalProtocol').textContent = alert.protocol;
    document.getElementById('modalPayloadSize').textContent = alert.payloadSize;
    document.getElementById('modalPcapFile').textContent = alert.file;
    document.getElementById('modalFlowDuration').textContent = alert.flowDuration;
    document.getElementById('modalTimestamp').textContent = alert.timestamp + ':00';
    
    // Model outputs
    document.getElementById('kitsuneScore').textContent = alert.kitsuneScore.toFixed(2);
    document.querySelector('#kitsuneScore').previousElementSibling.querySelector('.progress-fill').style.width = `${alert.kitsuneScore * 100}%`;
    
    document.getElementById('lucidDetection').textContent = alert.lucidDetection;
    
    document.getElementById('vertexLabel').textContent = alert.vertexLabel;
    document.getElementById('vertexConfidence').textContent = alert.vertexConfidence.toFixed(2);
    document.querySelector('#vertexConfidence').previousElementSibling.querySelector('.progress-fill').style.width = `${alert.vertexConfidence * 100}%`;
    
    // Recommendations
    const recommendationsContainer = document.getElementById('recommendations');
    recommendationsContainer.innerHTML = '';
    
    alert.recommendations.forEach(rec => {
        let badgeClass = 'badge-info';
        let icon = 'fa-info-circle';
        
        if (rec.includes('Isoler')) {
            badgeClass = 'badge-danger';
            icon = 'fa-ban';
        } else if (rec.includes('Vérifier') || rec.includes('Analyser')) {
            badgeClass = 'badge-warning';
            icon = 'fa-search';
        } else if (rec.includes('Aucune')) {
            badgeClass = 'badge-success';
            icon = 'fa-check';
        }
        
        const badge = document.createElement('span');
        badge.className = `badge ${badgeClass}`;
        badge.innerHTML = `<i class="fas ${icon} mr-1"></i> ${rec}`;
        recommendationsContainer.appendChild(badge);
    });
    
    // Set modal style based on severity
    if (alert.severity === 'high') {
        modalContent.classList.add('critical-modal');
    } else {
        modalContent.classList.remove('critical-modal');
    }
    
    // Show modal
    modal.classList.add('active');
}

// Setup event listeners
function setupEventListeners() {
    // Sortable columns
    document.querySelectorAll('.sortable').forEach(column => {
        column.addEventListener('click', () => {
            sortAlerts(column.dataset.sort);
        });
    });
    
    // Critical alerts toggle
    document.getElementById('criticalToggle').addEventListener('change', filterAlerts);
    
    // Model filter
    document.getElementById('modelFilter').addEventListener('change', filterAlerts);
    
    // Modal close button
    document.getElementById('closeModal').addEventListener('click', () => {
        document.getElementById('alertModal').classList.remove('active');
    });
    
    // Back to table button
    document.getElementById('backToTable').addEventListener('click', () => {
        document.getElementById('alertModal').classList.remove('active');
    });
    
    // Close modal when clicking outside
    document.getElementById('alertModal').addEventListener('click', (e) => {
        if (e.target === document.getElementById('alertModal')) {
            document.getElementById('alertModal').classList.remove('active');
        }
    });
    
    // Simulate real-time updates
    setInterval(() => {
        // In a real app, this would fetch new alerts from an API
        console.log('Checking for new alerts...');
    }, 10000);
}

// Initialize the app
document.addEventListener('DOMContentLoaded', initTable);