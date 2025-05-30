// Connect to Socket.IO
const socket = io();

let alerts = []; // Main store for all alerts
let filteredAlerts = [];
let currentPage = 1;
const itemsPerPage = 10;
let sortColumn = 'timestamp';
let sortDirection = 'desc';

// DOM Elements
const alertTableBody = document.getElementById('alertTableBody');
const paginationContainer = document.getElementById('pagination');
const startItemSpan = document.getElementById('startItem');
const endItemSpan = document.getElementById('endItem');
const totalItemsSpan = document.getElementById('totalItems');
const criticalToggle = document.getElementById('criticalToggle');
const modelFilter = document.getElementById('modelFilter');
const modal = document.getElementById('alertModal');
const closeModalButton = document.getElementById('closeModal');
const backToTableButton = document.getElementById('backToTable');

// Function to fetch initial alerts from the API
async function fetchInitialAlerts() {
    try {
        const response = await fetch('/api/logs/alertes');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const backendAlerts = await response.json();
        // console.log('Fetched backend alerts:', backendAlerts);

        // Transform backend alerts to frontend format
        alerts = backendAlerts.map(transformAlertData);
        // console.log('Transformed frontend alerts:', alerts);
        
        filterAlerts(); // This will also call renderTable and updatePagination
    } catch (error) {
        console.error("Could not fetch initial alerts:", error);
        // Display some error to the user or keep table empty
        alerts = [];
        filterAlerts();
    }
}

// Function to transform backend alert data to frontend's expected structure
function transformAlertData(backendAlert) {
    // Basic mapping
    const frontendAlert = {
        id: backendAlert.id || `gen-${Math.random().toString(36).substr(2, 9)}`, // Use DB id or generate one
        timestamp: backendAlert.timestamp ? new Date(backendAlert.timestamp).toLocaleString() : 'N/A',
        original_timestamp: backendAlert.timestamp ? new Date(backendAlert.timestamp) : new Date(0), // For sorting
        file: backendAlert.pcap_file || 'N/A', // PCAP file info not in IDSLog model directly
        sourceIP: backendAlert.source_ip || 'N/A',
        destIP: backendAlert.destination_ip || 'N/A',
        model: backendAlert.scan_type || 'Unknown Model', // Use scan_type as model
        score: backendAlert.severity ? mapSeverityToScore(backendAlert.severity) : 0.5, // Infer score from severity
        verdict: backendAlert.scan_type || 'N/A', // scan_type can be verdict
        severity: backendAlert.severity || 'N/A',
        sourcePort: backendAlert.source_port !== null ? backendAlert.source_port : 'N/A',
        destPort: backendAlert.destination_port !== null ? backendAlert.destination_port : 'N/A',
        protocol: backendAlert.protocol || 'N/A',
        details: backendAlert.details || 'No additional details.',
        
        // Fields that are in the old static data but not directly in IDSLog:
        payloadSize: 'N/A', 
        flowDuration: 'N/A',
        kitsuneScore: (backendAlert.scan_type === 'Kitsune' || backendAlert.model_name === 'Kitsune') ? mapSeverityToScore(backendAlert.severity) : 'N/A', // Example
        lucidDetection: (backendAlert.scan_type === 'LUCID' || backendAlert.model_name === 'LUCID') ? backendAlert.details : 'N/A', // Example
        vertexLabel: (backendAlert.scan_type === 'Vertex AI' || backendAlert.model_name === 'Vertex AI') ? backendAlert.details : 'N/A', // Example
        vertexConfidence: 'N/A',
        recommendations: ['Check firewall rules', 'Investigate source IP'] // Generic recommendations
    };
    // console.log(`Transformed alert ID ${frontendAlert.id} from backend ID ${backendAlert.id}`);
    return frontendAlert;
}

// Helper to map severity to a numeric score (example)
function mapSeverityToScore(severity) {
    if (!severity) return 0.5;
    switch (severity.toLowerCase()) {
        case 'critical': return 0.95;
        case 'high': return 0.85;
        case 'medium': return 0.6;
        case 'low': return 0.3;
        default: return 0.5;
    }
}

// Socket.IO listener for new alerts
socket.on('new_alert', function(newAlertData) {
    // console.log('New alert received via Socket.IO:', newAlertData);
    const transformedAlert = transformAlertData(newAlertData);
    alerts.unshift(transformedAlert); // Add to the beginning of the main alerts array
    
    // Potentially provide a visual cue, e.g., a toast notification
    // console.log(`New alert added: ${transformedAlert.id}, total alerts now: ${alerts.length}`);

    filterAlerts(); // Re-apply filters and re-render
});


function filterAlerts() {
    let tempAlerts = [...alerts];

    if (criticalToggle && criticalToggle.checked) {
        tempAlerts = tempAlerts.filter(alert => 
            alert.severity && (alert.severity.toLowerCase() === 'critical' || alert.severity.toLowerCase() === 'high')
        );
    }

    if (modelFilter && modelFilter.value !== 'all') {
        tempAlerts = tempAlerts.filter(alert => alert.model === modelFilter.value);
    }
    
    // Sorting
    tempAlerts.sort((a, b) => {
        let valA, valB;

        if (sortColumn === 'timestamp') {
            valA = a.original_timestamp;
            valB = b.original_timestamp;
        } else if (sortColumn === 'score') {
            valA = parseFloat(a.score);
            valB = parseFloat(b.score);
        } else {
            valA = a[sortColumn] ? (typeof a[sortColumn] === 'string' ? a[sortColumn].toLowerCase() : a[sortColumn]) : '';
            valB = b[sortColumn] ? (typeof b[sortColumn] === 'string' ? b[sortColumn].toLowerCase() : b[sortColumn]) : '';
        }

        if (valA < valB) return sortDirection === 'asc' ? -1 : 1;
        if (valA > valB) return sortDirection === 'asc' ? 1 : -1;
        return 0;
    });

    filteredAlerts = tempAlerts;
    currentPage = 1; // Reset to first page after filtering/sorting
    renderTable();
    updatePagination();
}

function renderTable() {
    if (!alertTableBody) return;
    alertTableBody.innerHTML = ''; // Clear existing rows

    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = startIndex + itemsPerPage;
    const paginatedAlerts = filteredAlerts.slice(startIndex, endIndex);

    paginatedAlerts.forEach(alert => {
        const row = alertTableBody.insertRow();
        row.className = 'border-b border-gray-800 hover:bg-gray-700/50 transition-colors duration-150 ease-in-out';
        
        // Determine severity class for verdict styling
        let verdictClass = 'text-green-400'; // Default for low/info
        if (alert.severity) {
            switch (alert.severity.toLowerCase()) {
                case 'critical':
                case 'high':
                    verdictClass = 'text-red-400';
                    break;
                case 'medium':
                    verdictClass = 'text-yellow-400';
                    break;
            }
        }

        row.innerHTML = `
            <td class="px-4 py-3 text-sm">${alert.timestamp}</td>
            <td class="px-4 py-3 text-sm truncate max-w-xs" title="${alert.file}">${alert.file}</td>
            <td class="px-4 py-3 text-sm font-mono">${alert.sourceIP} → ${alert.destIP}</td>
            <td class="px-4 py-3 text-sm">${alert.model}</td>
            <td class="px-4 py-3 text-sm">
                <span class="px-2 py-1 rounded-full text-xs ${alert.score > 0.7 ? 'bg-red-500/30 text-red-300' : (alert.score > 0.4 ? 'bg-yellow-500/30 text-yellow-300' : 'bg-green-500/30 text-green-300')}">
                    ${alert.score.toFixed(2)}
                </span>
            </td>
            <td class="px-4 py-3 text-sm ${verdictClass}">${alert.verdict}</td>
        `;
        row.addEventListener('click', () => openModal(alert));
    });
     if (paginatedAlerts.length === 0) {
        const row = alertTableBody.insertRow();
        const cell = row.insertCell(0);
        cell.colSpan = 6; // Number of columns
        cell.textContent = 'Aucune alerte correspondante trouvée.';
        cell.className = 'text-center py-4 text-gray-500';
    }
}

function updatePagination() {
    if (!paginationContainer || !startItemSpan || !endItemSpan || !totalItemsSpan) return;

    const totalPages = Math.max(1, Math.ceil(filteredAlerts.length / itemsPerPage));
    paginationContainer.innerHTML = ''; // Clear existing buttons

    // Previous Button
    const prevButton = document.createElement('button');
    prevButton.innerHTML = `<i class="fas fa-chevron-left"></i>`;
    prevButton.className = `px-3 py-1 rounded-lg ${currentPage === 1 ? 'bg-gray-700 text-gray-500 cursor-not-allowed' : 'bg-gray-800 hover:bg-cyan-700'}`;
    prevButton.disabled = currentPage === 1;
    prevButton.addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            renderTable();
            updatePagination();
        }
    });
    paginationContainer.appendChild(prevButton);

    // Page Numbers (simplified: first, current, last, with ellipses)
    let pageNumbers = [];
    if (totalPages <= 5) {
        for (let i = 1; i <= totalPages; i++) pageNumbers.push(i);
    } else {
        pageNumbers.push(1);
        if (currentPage > 3) pageNumbers.push('...');
        if (currentPage > 2) pageNumbers.push(currentPage - 1);
        if (currentPage !== 1 && currentPage !== totalPages) pageNumbers.push(currentPage);
        if (currentPage < totalPages - 1) pageNumbers.push(currentPage + 1);
        if (currentPage < totalPages - 2) pageNumbers.push('...');
        pageNumbers.push(totalPages);
    }
    
    // Deduplicate page numbers that might appear due to proximity (e.g. 1, 2, 3 when currentPage is 2)
    pageNumbers = [...new Set(pageNumbers)];


    pageNumbers.forEach(num => {
        const pageButton = document.createElement('button');
        if (num === '...') {
            pageButton.textContent = '...';
            pageButton.className = 'px-3 py-1 text-gray-400 cursor-default';
            pageButton.disabled = true;
        } else {
            pageButton.textContent = num;
            pageButton.className = `px-3 py-1 rounded-lg ${num === currentPage ? 'bg-cyan-600 text-white' : 'bg-gray-800 hover:bg-cyan-700'}`;
            pageButton.addEventListener('click', () => {
                currentPage = num;
                renderTable();
                updatePagination();
            });
        }
        paginationContainer.appendChild(pageButton);
    });
    

    // Next Button
    const nextButton = document.createElement('button');
    nextButton.innerHTML = `<i class="fas fa-chevron-right"></i>`;
    nextButton.className = `px-3 py-1 rounded-lg ${currentPage === totalPages ? 'bg-gray-700 text-gray-500 cursor-not-allowed' : 'bg-gray-800 hover:bg-cyan-700'}`;
    nextButton.disabled = currentPage === totalPages;
    nextButton.addEventListener('click', () => {
        if (currentPage < totalPages) {
            currentPage++;
            renderTable();
            updatePagination();
        }
    });
    paginationContainer.appendChild(nextButton);

    const startItem = filteredAlerts.length > 0 ? (currentPage - 1) * itemsPerPage + 1 : 0;
    const endItem = Math.min(currentPage * itemsPerPage, filteredAlerts.length);
    startItemSpan.textContent = startItem;
    endItemSpan.textContent = endItem;
    totalItemsSpan.textContent = filteredAlerts.length;
}


function openModal(alert) {
    if (!modal) return;

    document.getElementById('modalTitle').textContent = `Détail Alerte #${alert.id}`;
    document.getElementById('modalSubtitle').textContent = `ID: ${alert.id} | Sévérité: ${alert.severity}`;
    
    // Network Info
    document.getElementById('modalSourceIP').textContent = alert.sourceIP;
    document.getElementById('modalDestIP').textContent = alert.destIP;
    document.getElementById('modalSourcePort').textContent = alert.sourcePort;
    document.getElementById('modalDestPort').textContent = alert.destPort;
    document.getElementById('modalProtocol').textContent = alert.protocol;
    document.getElementById('modalPayloadSize').textContent = alert.payloadSize || 'N/A'; // Was static

    // PCAP Info
    document.getElementById('modalPcapFile').textContent = alert.file;
    document.getElementById('modalFlowDuration').textContent = alert.flowDuration || 'N/A'; // Was static
    document.getElementById('modalTimestamp').textContent = alert.timestamp;

    // Model Outputs - adapt based on available transformed data
    const kitsuneScoreEl = document.getElementById('kitsuneScore');
    // const kitsuneProgressFill = document.querySelector('#kitsuneScore_progress .progress-fill'); // Assuming progress bar has id like this
    if (kitsuneScoreEl) kitsuneScoreEl.textContent = typeof alert.kitsuneScore === 'number' ? alert.kitsuneScore.toFixed(2) : (alert.kitsuneScore || 'N/A');
    // if (kitsuneProgressFill) kitsuneProgressFill.style.width = `${(alert.kitsuneScore || 0) * 100}%`;


    const lucidDetectionEl = document.getElementById('lucidDetection');
    if (lucidDetectionEl) lucidDetectionEl.textContent = alert.lucidDetection || 'N/A';

    const vertexLabelEl = document.getElementById('vertexLabel');
    const vertexConfidenceEl = document.getElementById('vertexConfidence');
    // const vertexProgressFill = document.querySelector('#vertexConfidence_progress .progress-fill');
    if (vertexLabelEl) vertexLabelEl.textContent = alert.vertexLabel || 'N/A';
    if (vertexConfidenceEl) vertexConfidenceEl.textContent = typeof alert.vertexConfidence === 'number' ? alert.vertexConfidence.toFixed(2) : (alert.vertexConfidence || 'N/A');
    // if (vertexProgressFill) vertexProgressFill.style.width = `${(alert.vertexConfidence || 0) * 100}%`;
    
    // Recommendations (example, can be dynamic later)
    const recommendationsContainer = document.getElementById('recommendations');
    recommendationsContainer.innerHTML = ''; // Clear old ones
    (alert.recommendations || ['Verify IP reputation', 'Monitor traffic from source']).forEach(rec => {
        const badge = document.createElement('span');
        badge.className = 'badge badge-info'; // Simplified class
        badge.innerHTML = `<i class="fas fa-shield-alt mr-1"></i> ${rec}`;
        recommendationsContainer.appendChild(badge);
    });

    modal.classList.remove('modal-hidden');
    modal.classList.add('modal-visible');
}

function closeModal() {
    if (!modal) return;
    modal.classList.remove('modal-visible');
    modal.classList.add('modal-hidden');
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    fetchInitialAlerts(); // Load initial data

    if (criticalToggle) criticalToggle.addEventListener('change', filterAlerts);
    if (modelFilter) modelFilter.addEventListener('change', filterAlerts);
    if (closeModalButton) closeModalButton.addEventListener('click', closeModal);
    if (backToTableButton) backToTableButton.addEventListener('click', closeModal);
    
    // Click outside modal to close
    if (modal) {
        modal.addEventListener('click', (event) => {
            if (event.target === modal) { // Check if click is on overlay itself
                closeModal();
            }
        });
    }

    // Sortable table headers
    document.querySelectorAll('.sortable').forEach(header => {
        header.addEventListener('click', () => {
            const newSortColumn = header.dataset.sort;
            if (sortColumn === newSortColumn) {
                sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                sortColumn = newSortColumn;
                sortDirection = 'asc'; // Default to ascending for new column
            }
            
            // Update sort icons (optional visual feedback)
            document.querySelectorAll('.sortable i').forEach(icon => icon.className = 'fas fa-sort ml-2 text-gray-400');
            const currentIcon = header.querySelector('i');
            if (currentIcon) {
                if (sortDirection === 'asc') {
                    currentIcon.className = 'fas fa-sort-up ml-2 text-white';
                } else {
                    currentIcon.className = 'fas fa-sort-down ml-2 text-white';
                }
            }
            filterAlerts();
        });
    });
});

// Removed: Old setInterval for checking new alerts
// setInterval(() => {
//     console.log("Checking for new alerts..."); 
// }, 10000);
