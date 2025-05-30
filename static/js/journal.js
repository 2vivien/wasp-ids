// Tailwind config might be here in the original file, but it's not standard JS.
// If it was part of the original static/js/journal.js, it should be removed or handled appropriately
// as JS files typically don't contain Tailwind configurations.
// For this task, I will assume it's not needed in the JS logic itself.

let actualSystemLogs = []; // Global store for system logs

// DOM Elements
const systemLogsContainer = document.getElementById('systemLogs');
// Add other DOM elements if needed for user activities and analyses later

// Function to fetch system logs from the API
async function fetchSystemLogs() {
    try {
        const response = await fetch('/api/logs');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const backendLogs = await response.json();
        actualSystemLogs = backendLogs; // Store fetched logs
        renderSystemLogs(); // Render the fetched logs
    } catch (error) {
        console.error("Could not fetch system logs:", error);
        if(systemLogsContainer) {
            systemLogsContainer.innerHTML = '<p class="text-red-500">Erreur de chargement des journaux système.</p>';
        }
        actualSystemLogs = []; // Ensure it's empty on error
    }
}

// Function to render system logs
function renderSystemLogs() {
    if (!systemLogsContainer) {
        console.error("System logs container not found in DOM.");
        return;
    }
    systemLogsContainer.innerHTML = ''; // Clear existing logs

    if (actualSystemLogs.length === 0) {
        systemLogsContainer.innerHTML = '<p class="text-gray-500">Aucun journal système à afficher.</p>';
        return;
    }

    actualSystemLogs.forEach(log => {
        const logEntryElement = formatLogEntry(log);
        systemLogsContainer.appendChild(logEntryElement);
    });
}

// Helper function to determine log level class
function getLogLevelClass(severity) {
    if (!severity) return 'INFO'; // Default
    const s = severity.toLowerCase();
    if (s === 'critical' || s === 'high') return 'ERROR'; // Map high/critical to ERROR style
    if (s === 'medium') return 'WARNING';
    if (s === 'low') return 'INFO';
    return 'INFO'; // Default for unknown severities
}


// Helper function to format a single log entry with random styling
function formatLogEntry(log) {
    const styles = ['Vertex', 'Kitsune', 'Lucid'];
    const chosenStyle = styles[Math.floor(Math.random() * styles.length)];
    
    const logEntry = document.createElement('div');
    const timestamp = log.timestamp ? new Date(log.timestamp).toLocaleString() : 'N/A';
    const level = log.severity || 'INFO'; // Default to INFO if severity is null/undefined
    const logLevelClass = getLogLevelClass(level); // Gets INFO, WARNING, ERROR

    logEntry.className = `log-entry ${logLevelClass} log-style-${chosenStyle.toLowerCase()}`; // Add style-specific class

    let messageContent = ``;
    const details = log.details ? ` - ${log.details}` : '';
    const scanInfo = log.scan_type ? ` (${log.scan_type})` : '';

    switch (chosenStyle) {
        case 'Kitsune':
            messageContent = `
                <span class="log-meta">[${timestamp}]</span>
                <span class="log-level">${level.toUpperCase()}</span>
                <span class="log-source">Kitsune-Style:</span>
                <span class="log-message">
                    ${log.protocol}: ${log.source_ip}:${log.source_port || '?'} &rarr; ${log.destination_ip}:${log.destination_port || '?'} ${scanInfo}${details}
                </span>`;
            break;
        case 'Lucid':
            messageContent = `
                <span class="log-meta">[${timestamp}]</span>
                <span class="log-level">${level.toUpperCase()}</span>
                <span class="log-source">LUCID-Style:</span>
                <span class="log-message">
                    Event${scanInfo}: ${log.source_ip} to ${log.destination_ip}. Severity: ${level}. Details: ${details || 'N/A'}
                </span>`;
            break;
        case 'Vertex': // Vertex AI style
        default:
            messageContent = `
                <span class="log-meta">[${timestamp}]</span>
                <span class="log-level">${level.toUpperCase()}</span>
                <span class="log-source">Vertex-Style:</span>
                <span class="log-message">
                    Log ID ${log.id}: ${log.protocol} traffic from ${log.source_ip} to ${log.destination_ip}${scanInfo}.${details}
                </span>`;
            break;
    }
    logEntry.innerHTML = messageContent;
    return logEntry;
}


// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    fetchSystemLogs();

    // Clear out User Activity and Analyses sections for now
    const userActivityContainer = document.getElementById('userActivity');
    if (userActivityContainer) userActivityContainer.innerHTML = '<p class="text-gray-500">Journal des activités utilisateurs non implémenté.</p>';
    
    const analysisTable = document.getElementById('analysisTable');
    if (analysisTable) analysisTable.innerHTML = '<tr><td colspan="7" class="text-center text-gray-500 py-4">Journal des analyses non implémenté.</td></tr>';


    // Panel toggle functionality (can be kept if HTML structure uses it)
    const panelHeaders = document.querySelectorAll('.panel-header');
    panelHeaders.forEach(header => {
        header.addEventListener('click', function() {
            const panel = this.nextElementSibling;
            const icon = this.querySelector('.toggle-panel i');
            if (!panel || !icon) return;
            
            if (panel.style.maxHeight && panel.style.maxHeight !== '0px') {
                panel.style.maxHeight = '0px'; // Explicitly set to 0 for closing
                icon.className = 'fas fa-chevron-down';
            } else {
                panel.style.maxHeight = panel.scrollHeight + 'px';
                icon.className = 'fas fa-chevron-up';
            }
        });
    });

    // Filter logs by level (can be kept and adapted if systemLogsContainer is the target)
    const filterButtons = document.querySelectorAll('.filter-btn');
    filterButtons.forEach(button => {
        button.addEventListener('click', function() {
            const filter = this.getAttribute('data-filter').toUpperCase(); // ERROR, WARNING, INFO
            
            filterButtons.forEach(btn => btn.classList.remove('filter-active'));
            this.classList.add('filter-active');
            
            const logEntries = systemLogsContainer.querySelectorAll('.log-entry');
            logEntries.forEach(entry => {
                // Check if the entry's level class matches the filter
                if (filter === 'ALL' || entry.classList.contains(filter)) {
                    entry.style.display = 'block';
                } else {
                    entry.style.display = 'none';
                }
            });
        });
    });
    
    // Refresh button for system logs
    const refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function() {
            this.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Actualisation...';
            fetchSystemLogs().finally(() => {
                 setTimeout(() => { // Add a small delay to show refresh
                    this.innerHTML = '<i class="fas fa-sync-alt mr-2"></i>🔄 Actualiser';
                }, 500);
            });
        });
    }

    // Export button (remains mock for now)
    const exportBtn = document.getElementById('exportBtn');
    if (exportBtn) {
        exportBtn.addEventListener('click', function() {
            this.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Export...';
            setTimeout(() => {
                this.innerHTML = '<i class="fas fa-file-export mr-2"></i>Exporter CSV';
                alert('Export CSV démarré! (simulation)');
            }, 1000);
        });
    }

    // Toggle switch animation (general UI, can be kept)
    const toggleSwitches = document.querySelectorAll('.toggle-checkbox');
    toggleSwitches.forEach(switchEl => {
        switchEl.addEventListener('change', function() {
            const dot = this.nextElementSibling.querySelector('.dot');
            if (!dot) return;
            if (this.checked) {
                dot.classList.remove('translate-x-0');
                dot.classList.add('translate-x-5');
            } else {
                dot.classList.remove('translate-x-5');
                dot.classList.add('translate-x-0');
            }
        });
    });

    // Remove the old 'Show failed analyses only' toggle logic if it's no longer relevant
    const showFailedOnly = document.getElementById('showFailedOnly');
    if (showFailedOnly) {
      // If this element is removed or repurposed, this listener might not be needed
      // For now, let's assume it might still exist but do nothing if table is cleared
      showFailedOnly.addEventListener('change', function() {
        // This logic would need to be re-evaluated if analysis logs are fetched from backend
        console.log("Toggle 'Show Failed Analyses' changed. Functionality may need update.");
      });
    }
});

// Removed the old setInterval that simulated real-time log updates.
// Real-time updates for the journal page would require a new Socket.IO event from the backend.
