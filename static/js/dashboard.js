// dashboard.js

// --- Configuration Globale et Utilitaires ---
const API_BASE_URL = ''; // Laisser vide si les routes API sont relatives au domaine actuel

// Fonction pour formater le temps écoulé (ex: "il y a 5 minutes")
function formatTimeAgo(date) {
    if (!date) return 'N/A';
    const seconds = Math.floor((new Date() - new Date(date)) / 1000);
    let interval = Math.floor(seconds / 31536000);
    if (interval > 1) return `il y a ${interval} ans`;
    interval = Math.floor(seconds / 2592000);
    if (interval > 1) return `il y a ${interval} mois`;
    interval = Math.floor(seconds / 86400);
    if (interval > 1) return `il y a ${interval} jours`;
    interval = Math.floor(seconds / 3600);
    if (interval > 1) return `il y a ${interval} heures`;
    interval = Math.floor(seconds / 60);
    if (interval > 1) return `il y a ${interval} minutes`;
    if (seconds < 10) return `à l'instant`;
    return `il y a ${Math.floor(seconds)} secondes`;
}


// --- Initialisation des Graphiques et Éléments Visuels ---

 // Create floating particles
 function createParticles() {
    const container = document.getElementById('particles-container');
    const particleCount = 40;
    
    for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        particle.classList.add('particle');
        
        // Random size between 1px and 4px
        const size = Math.random() * 3 + 1;
        particle.style.width = `${size}px`;
        particle.style.height = `${size}px`;
        
        // Random position
        particle.style.left = `${Math.random() * 100}%`;
        particle.style.top = `${Math.random() * 100}%`;
        
        // Random animation delay and duration
        particle.style.animationDelay = `${Math.random() * 8}s`;
        particle.style.animationDuration = `${Math.random() * 5 + 5}s`;
        
        // Random opacity
        particle.style.opacity = Math.random() * 0.5 + 0.1;
        
        container.appendChild(particle);
    }
}

// Initialize attack chart
function initAttackChart() {
    const ctx = document.getElementById('attackChart').getContext('2d');
    
    // Generate random data for the chart
    const labels = [];
    const attackData = [];
    const normalData = [];
    
    for (let i = 0; i < 24; i++) {
        labels.push(`${i}h`);
        attackData.push(Math.floor(Math.random() * 100) + 50);
        normalData.push(Math.floor(Math.random() * 30) + 10);
    }
    
    // Add some spikes for anomalies
    attackData[5] = 180;
    attackData[12] = 220;
    attackData[18] = 190;
    
    const chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Anomalies',
                    data: attackData,
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    borderWidth: 2,
                    tension: 0.3,
                    fill: true,
                    pointRadius: 0
                },
                {
                    label: 'Trafic normal',
                    data: normalData,
                    borderColor: '#4ade80',
                    backgroundColor: 'rgba(74, 222, 128, 0.1)',
                    borderWidth: 2,
                    tension: 0.3,
                    fill: true,
                    pointRadius: 0
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    mode: 'index',
                    intersect: false
                }
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(226, 232, 240, 0.1)',
                        drawBorder: false
                    },
                    ticks: {
                        color: '#e2e8f0'
                    }
                },
                y: {
                    grid: {
                        color: 'rgba(226, 232, 240, 0.1)',
                        drawBorder: false
                    },
                    ticks: {
                        color: '#e2e8f0'
                    },
                    beginAtZero: true
                }
            },
            animation: {
                duration: 2000
            }
        }
    });
    
    // Simulate real-time updates
    setInterval(() => {
        const now = new Date();
        labels.shift();
        labels.push(`${now.getHours()}h${now.getMinutes()}`);
        
        attackData.shift();
        normalData.shift();
        
        // Generate new data points
        const newAttack = Math.floor(Math.random() * 30) + 20;
        const newNormal = Math.floor(Math.random() * 15) + 5;
        
        // Occasionally add spikes
        if (Math.random() > 0.95) {
            attackData.push(newAttack * 3);
        } else {
            attackData.push(newAttack);
        }
        
        normalData.push(newNormal);
        
        chart.update();
    }, 5000);
}

// Initialize Kitsune chart
function initKitsuneChart() {
    const ctx = document.getElementById('kitsuneChart').getContext('2d');
    
    const data = Array.from({length: 10}, () => Math.floor(Math.random() * 100) / 100);
    data[3] = 0.95;
    data[7] = 0.98;
    
    const chart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.map((_, i) => i+1),
            datasets: [{
                data: data,
                backgroundColor: [
                    '#3b82f6', '#3b82f6', '#3b82f6', 
                    '#ef4444', '#3b82f6', '#3b82f6', 
                    '#3b82f6', '#ef4444', '#3b82f6', 
                    '#3b82f6'
                ],
                borderColor: [
                    '#3b82f6', '#3b82f6', '#3b82f6', 
                    '#ef4444', '#3b82f6', '#3b82f6', 
                    '#3b82f6', '#ef4444', '#3b82f6', 
                    '#3b82f6'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    grid: {
                        display: false,
                        drawBorder: false
                    },
                    ticks: {
                        color: '#e2e8f0'
                    }
                },
                y: {
                    grid: {
                        color: 'rgba(226, 232, 240, 0.1)',
                        drawBorder: false
                    },
                    ticks: {
                        color: '#e2e8f0',
                        callback: function(value) {
                            return value.toFixed(1);
                        }
                    },
                    min: 0,
                    max: 1
                }
            }
        }
    });
}

// Initialize LUCID chart
function initLucidChart() {
    const ctx = document.getElementById('lucidChart').getContext('2d');
    
    const labels = Array.from({length: 24}, (_, i) => `${i}h`);
    const data = Array.from({length: 24}, () => 0);
    data[3] = 1;
    data[12] = 1;
    data[20] = 1;
    
    const chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                borderColor: '#a855f7',
                backgroundColor: 'rgba(168, 85, 247, 0.1)',
                borderWidth: 2,
                pointRadius: 5,
                pointBackgroundColor: '#ef4444',
                pointHoverRadius: 7,
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(226, 232, 240, 0.1)',
                        drawBorder: false
                    },
                    ticks: {
                        color: '#e2e8f0',
                        maxRotation: 0,
                        autoSkip: true,
                        maxTicksLimit: 12
                    }
                },
                y: {
                    display: false,
                    min: 0,
                    max: 1
                }
            }
        }
    });
}

// Initialize Vertex AI chart
function initVertexChart() {
    const ctx = document.getElementById('vertexChart').getContext('2d');
    
    const chart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['DDoS', 'Brute Force', 'Port Scan', 'Zero-Day', 'Autre'],
            datasets: [{
                data: [35, 25, 20, 15, 5],
                backgroundColor: [
                    '#ef4444',
                    '#f97316',
                    '#f59e0b',
                    '#a855f7',
                    '#64748b'
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            cutout: '70%',
            animation: {
                animateScale: true,
                animateRotate: true
            }
        }
    });
}

// Initialize system status ring
function initSystemStatus() {
    const circle = document.querySelector('.progress-ring-circle');
    const radius = circle.r.baseVal.value;
    const circumference = radius * 2 * Math.PI;
    
    circle.style.strokeDasharray = circumference;
    circle.style.strokeDashoffset = circumference - (0.85 * circumference);
}

// Initialize everything when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    createParticles();
    initAttackChart();
    initKitsuneChart();
    initLucidChart();
    initVertexChart();
    initSystemStatus();
    
    // Simulate blinking alerts
    setInterval(() => {
        const alerts = document.querySelectorAll('.alert-glow');
        alerts.forEach(alert => {
            alert.style.animation = 'none';
            alert.offsetHeight; // Trigger reflow
            alert.style.animation = null;
        });
    }, 2000);
    
    // Simulate system status updates
    setInterval(() => {
        const statusText = document.querySelector('.progress-ring-circle');
        const newValue = Math.min(0.95, Math.max(0.75, parseFloat(statusText.textContent) + (Math.random() * 0.1 - 0.05)));
        
        const circle = document.querySelector('.progress-ring-circle');
        const radius = circle.r.baseVal.value;
        const circumference = radius * 2 * Math.PI;
        
        circle.style.strokeDashoffset = circumference - (newValue * circumference);
        document.querySelector('.progress-ring-circle + text').textContent = `${Math.round(newValue * 100)}%`;
    }, 10000);
});

function toggleProfileMenu() {
    const menu = document.getElementById('profile-menu');
    const chevron = document.getElementById('chevron-icon');

    const isOpen = menu.classList.contains('opacity-100');

    if (isOpen) {
        menu.classList.remove('opacity-100', 'visible', 'scale-100');
        menu.classList.add('opacity-0', 'invisible', 'scale-95');
        chevron.classList.remove('rotate-180');
    } else {
        menu.classList.remove('opacity-0', 'invisible', 'scale-95');
        menu.classList.add('opacity-100', 'visible', 'scale-100');
        chevron.classList.add('rotate-180');
    }
}

// --- Logique des Alertes Critiques et Modal du Dashboard ---

async function fetchCriticalAlerts() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/dashboard/critical-alerts`);
        if (!response.ok) {
            console.error('Échec de la récupération des alertes critiques:', response.status, await response.text());
            return [];
        }
        return await response.json();
    } catch (error) {
        console.error('Erreur lors de la récupération des alertes critiques:', error);
        return [];
    }
}

function renderCriticalAlerts(alertsData) {
    const tableBody = document.getElementById('criticalAlertsTableBody');
    if (!tableBody) { console.error('Tableau des alertes critiques (criticalAlertsTableBody) non trouvé!'); return; }
    tableBody.innerHTML = ''; 

    if (!alertsData || alertsData.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-gray-500">Aucune alerte critique récente.</td></tr>`;
        return;
    }

    alertsData.forEach(alert => {
        const row = tableBody.insertRow();
        row.className = 'border-b border-gray-700/30 hover:bg-gray-700/30 transition cursor-pointer';
        row.onclick = () => showDashboardAlertModal(alert.id);

        row.insertCell().textContent = alert.timestamp;
        row.cells[0].className = 'py-3 px-2 text-xs';
        
        row.insertCell().textContent = alert.source_ip;
        row.cells[1].className = 'py-3 px-2 font-mono text-red-400 text-xs';
        
        row.insertCell().textContent = alert.model;
        row.cells[2].className = 'py-3 px-2 text-xs';
        
        row.insertCell().textContent = alert.type;
        row.cells[3].className = 'py-3 px-2 text-xs';

        const scoreCell = row.insertCell();
        scoreCell.className = 'py-3 px-2 text-xs';
        const scoreValue = parseFloat(alert.threat_score);
        let scoreColor = 'text-yellow-400';
        if (scoreValue >= 0.85) scoreColor = 'text-red-400';
        else if (scoreValue >= 0.6) scoreColor = 'text-orange-400';
        scoreCell.innerHTML = `<span class="font-bold ${scoreColor}">${scoreValue.toFixed(2)}</span>`;
        
        const actionsCell = row.insertCell();
        actionsCell.className = 'py-3 px-2 text-center';
        actionsCell.innerHTML = `<button class="text-blue-400 hover:text-blue-300 transition focus:outline-none" title="Voir détails">
                                     <i class="fas fa-search-plus"></i>
                                 </button>`;
        actionsCell.firstChild.onclick = (e) => {
            e.stopPropagation();
            showDashboardAlertModal(alert.id);
        };
    });
}

async function fetchAndRenderCriticalAlerts() {
    const alerts = await fetchCriticalAlerts();
    renderCriticalAlerts(alerts);
    // Mettre à jour le badge de nombre d'alertes
    const alertCountBadge = document.getElementById('alert-count-badge');
    if(alertCountBadge) {
        alertCountBadge.textContent = alerts.length > 0 ? alerts.length : '0'; // Ou un total plus global si disponible
    }
}

// Éléments du Modal du Dashboard
const dashboardModal = {
    el: document.getElementById('dashboardAlertModal'),
    title: document.getElementById('modalDashboardTitle'),
    subtitle: document.getElementById('modalDashboardSubtitle'),
    timestamp: document.getElementById('modalDashboardTimestamp'),
    sourceIP: document.getElementById('modalDashboardSourceIP'),
    destIP: document.getElementById('modalDashboardDestIP'),
    sourcePort: document.getElementById('modalDashboardSourcePort'),
    destPort: document.getElementById('modalDashboardDestPort'),
    protocol: document.getElementById('modalDashboardProtocol'),
    model: document.getElementById('modalDashboardModel'),
    type: document.getElementById('modalDashboardType'),
    score: document.getElementById('modalDashboardScore'),
    severity: document.getElementById('modalDashboardSeverity'),
    rawDetails: document.getElementById('modalDashboardRawDetails'),
    closeButton: document.getElementById('closeDashboardModal'),
    closeButtonSecondary: document.getElementById('closeDashboardModalBtnSecondary'),
    investigateButton: document.getElementById('investigateFurtherBtn'),
    contentEl: null // Sera défini dans l'init
};
if (dashboardModal.el) {
    dashboardModal.contentEl = dashboardModal.el.querySelector('.modal-content-dashboard');
}


let currentDashboardAlertId = null;

async function showDashboardAlertModal(alertId) {
    if (!alertId || !dashboardModal.el || !dashboardModal.contentEl) return;
    currentDashboardAlertId = alertId;

    // Afficher un état de chargement
    dashboardModal.title.innerHTML = `<i class="fas fa-spinner fa-spin mr-2"></i> Chargement...`;
    dashboardModal.rawDetails.textContent = "Récupération des détails...";
    
    dashboardModal.el.classList.remove('hidden');
    requestAnimationFrame(() => { // Permet au 'hidden' d'être retiré avant d'appliquer l'opacité
        dashboardModal.el.classList.remove('opacity-0');
        dashboardModal.contentEl.classList.remove('scale-95');
        dashboardModal.el.classList.add('opacity-100');
        dashboardModal.contentEl.classList.add('scale-100');
    });

    try {
        const response = await fetch(`${API_BASE_URL}/api/alert/${alertId}`);
        if (!response.ok) throw new Error(`HTTP error ${response.status}`);
        const details = await response.json();

        dashboardModal.title.innerHTML = `<i class="fas fa-${details.severity === 'high' || details.severity === 'critique' ? 'exclamation-triangle text-red-400' : (details.severity === 'medium' ? 'exclamation-circle text-orange-400' : 'info-circle text-yellow-400')} mr-2"></i> Détail de l'Alerte`;
        dashboardModal.subtitle.textContent = `ID: ${details.id || 'DB-' + alertId}`;
        dashboardModal.timestamp.textContent = new Date(details.timestamp).toLocaleString('fr-FR');
        dashboardModal.sourceIP.textContent = details.sourceIP;
        dashboardModal.destIP.textContent = details.destIP || 'N/A';
        dashboardModal.sourcePort.textContent = details.sourcePort || 'N/A';
        dashboardModal.destPort.textContent = details.destPort || 'N/A';
        dashboardModal.protocol.textContent = details.protocol;
        dashboardModal.model.textContent = details.model;
        dashboardModal.type.textContent = details.scan_type || details.type || 'N/A'; // 'type' est un fallback
        dashboardModal.score.textContent = parseFloat(details.score).toFixed(2);
        
        const severityText = details.severity ? details.severity.charAt(0).toUpperCase() + details.severity.slice(1) : 'N/A';
        dashboardModal.severity.textContent = severityText;
        let severityColorClass = 'text-yellow-400'; // Default low
        if (details.severity === 'high' || details.severity === 'critique') severityColorClass = 'text-red-400';
        else if (details.severity === 'medium' || details.severity === 'moyen') severityColorClass = 'text-orange-400';
        dashboardModal.severity.className = `font-semibold ${severityColorClass}`;
        
        dashboardModal.rawDetails.textContent = details.raw_details || 'Aucun détail brut disponible.';

        // Ajuster la bordure du modal en fonction de la sévérité
        dashboardModal.contentEl.classList.remove('border-red-500', 'border-orange-500', 'border-yellow-500', 'border-gray-700/50');
        if (details.severity === 'high' || details.severity === 'critique') dashboardModal.contentEl.classList.add('border-red-500');
        else if (details.severity === 'medium' || details.severity === 'moyen') dashboardModal.contentEl.classList.add('border-orange-500');
        else dashboardModal.contentEl.classList.add('border-yellow-500');


    } catch (error) {
        console.error('Erreur lors de la récupération des détails de l’alerte pour le modal:', error);
        dashboardModal.title.innerHTML = `<i class="fas fa-exclamation-circle text-red-400 mr-2"></i> Erreur`;
        dashboardModal.rawDetails.textContent = "Impossible de charger les détails de l'alerte.";
        dashboardModal.contentEl.classList.add('border-red-500');
    }
}

function closeDashboardAlertModal() {
    if (!dashboardModal.el || !dashboardModal.contentEl) return;
    dashboardModal.el.classList.add('opacity-0');
    dashboardModal.contentEl.add('scale-95');
    setTimeout(() => {
        dashboardModal.el.classList.add('hidden');
        // Réinitialiser le contenu pour la prochaine ouverture
        dashboardModal.title.textContent = "Détail de l'Alerte";
        dashboardModal.rawDetails.textContent = "";
        dashboardModal.contentEl.classList.remove('border-red-500', 'border-orange-500', 'border-yellow-500');
        dashboardModal.contentEl.classList.add('border-gray-700/50');

    }, 300); // Durée de la transition
}

// --- Gestion des Filtres du Dashboard (Exemple Basique) ---
function applyDashboardFilters() {
    const model = document.getElementById('modelFilterDashboard').value;
    const ip = document.getElementById('ipFilterDashboard').value;
    const period = document.getElementById('periodFilterDashboard').value;

    console.log("Application des filtres du dashboard:", { model, ip, period });
    // Ici, vous feriez un appel API pour récupérer des données filtrées pour les graphiques
    // et potentiellement pour la liste des alertes critiques si l'API le supporte.
    // Pour l'instant, cela ne fait que logger.
    // Exemple: fetchAndRenderCriticalAlerts({ model, ip, period });
    // Et mettre à jour les graphiques:
    // updateChartsWithFilteredData({ model, ip, period });
    alert("Fonctionnalité de filtrage en cours de développement.\nLes filtres sélectionnés ont été enregistrés en console.");
}


// --- Initialisation Générale et Écouteurs d'Événements ---
document.addEventListener('DOMContentLoaded', () => {
    createParticles();
    window.addEventListener('resize', createParticles); // Recréer les particules au redimensionnement

    // Initialiser les graphiques avec des données vides ou par défaut
    initAttackChart(); 
    initKitsuneChart();
    initLucidChart();
    initVertexChart();
    initSystemStatus(); // Pourrait être mis à jour dynamiquement

    // Charger les alertes critiques
    fetchAndRenderCriticalAlerts();
    setInterval(fetchAndRenderCriticalAlerts, 30000); // Actualiser toutes les 30 secondes

    // Gestion du menu profil
    const profileTrigger = document.getElementById("profile-trigger");
    const profileMenu = document.getElementById("profile-menu");
    const chevronIcon = document.getElementById("chevron-icon");

    if (profileTrigger && profileMenu && chevronIcon) {
        profileTrigger.addEventListener("click", function (e) {
            e.stopPropagation();
            profileMenu.classList.toggle("hidden");
            if (!profileMenu.classList.contains("hidden")) {
                 // Forcer le recalcul du style pour que la transition s'applique à l'ouverture
                void profileMenu.offsetWidth; 
                profileMenu.classList.add('opacity-100', 'scale-100');
                profileMenu.classList.remove('opacity-0', 'scale-95');
            } else {
                profileMenu.classList.add('opacity-0', 'scale-95');
                profileMenu.classList.remove('opacity-100', 'scale-100');
            }
            chevronIcon.classList.toggle("rotate-180");
        });

        document.addEventListener("click", function (e) {
            if (!profileMenu.classList.contains("hidden") && !profileMenu.contains(e.target) && !profileTrigger.contains(e.target)) {
                profileMenu.classList.add('opacity-0', 'scale-95');
                profileMenu.classList.remove('opacity-100', 'scale-100');
                setTimeout(() => profileMenu.classList.add("hidden"), 300); // Attendre la fin de la transition
                chevronIcon.classList.remove("rotate-180");
            }
        });
        profileMenu.addEventListener("click", e => e.stopPropagation());
    }

    // Écouteurs pour le modal du dashboard
    if (dashboardModal.closeButton) dashboardModal.closeButton.onclick = closeDashboardAlertModal;
    if (dashboardModal.closeButtonSecondary) dashboardModal.closeButtonSecondary.onclick = closeDashboardAlertModal;
    if (dashboardModal.el) {
        dashboardModal.el.onclick = (event) => {
            if (event.target === dashboardModal.el) closeDashboardAlertModal();
        };
    }
    if (dashboardModal.investigateButton) {
        dashboardModal.investigateButton.onclick = () => {
            if (currentDashboardAlertId) {
                window.location.href = `${API_BASE_URL}/alert?alert_db_id=${currentDashboardAlertId}`;
            }
            closeDashboardAlertModal();
        };
    }
    
    // Écouteurs pour les filtres du dashboard
    const applyFiltersBtn = document.getElementById('applyFiltersDashboard');
    if (applyFiltersBtn) applyFiltersBtn.addEventListener('click', applyDashboardFilters);
    
    const refreshDashboardBtn = document.getElementById('refreshDashboardData');
    if (refreshDashboardBtn) {
        refreshDashboardBtn.addEventListener('click', () => {
            console.log("Actualisation manuelle du dashboard...");
            // Appeler ici les fonctions pour recharger toutes les données dynamiques du dashboard
            fetchAndRenderCriticalAlerts();
            // Ex: updateAttackChartData(); updateModelStats(); updateSystemStatus();
            alert("Données du tableau de bord actualisées (simulation).");
        });
    }
    
    // Mettre à jour l'heure de la dernière analyse périodiquement (exemple)
    setInterval(() => {
        const lastScanEl = document.getElementById('lastScanTime');
        if(lastScanEl) lastScanEl.textContent = formatTimeAgo(new Date());
    }, 60000); // Toutes les minutes


    // TODO: Ajouter des fonctions pour mettre à jour dynamiquement les données des graphiques
    // Ex: updateAttackChartWithData(), updateKitsuneStats(data), etc.
    // Ces fonctions seraient appelées après des fetch API.
});
