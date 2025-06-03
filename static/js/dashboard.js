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

 function createParticles() {
    const container = document.getElementById('particles-container');
    if (!container) return; 
    const particleCount = 40;
    
    container.innerHTML = ''; 
    for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        particle.classList.add('particle');
        
        const size = Math.random() * 3 + 1;
        particle.style.width = `${size}px`;
        particle.style.height = `${size}px`;
        particle.style.left = `${Math.random() * 100}%`;
        particle.style.top = `${Math.random() * 100}%`;
        particle.style.animationDelay = `${Math.random() * 8}s`;
        particle.style.animationDuration = `${Math.random() * 5 + 5}s`;
        particle.style.opacity = Math.random() * 0.5 + 0.1;
        
        container.appendChild(particle);
    }
}

function initAttackChart() {
    const ctxElement = document.getElementById('attackChart');
    if (!ctxElement) return;
    const ctx = ctxElement.getContext('2d');
        
    const labels = [];
    const attackData = [];
    const normalData = [];
    
    for (let i = 0; i < 24; i++) {
        labels.push(`${i}h`);
        attackData.push(Math.floor(Math.random() * 100) + 50);
        normalData.push(Math.floor(Math.random() * 30) + 10);
    }
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
            plugins: { legend: { display: false }, tooltip: { mode: 'index', intersect: false }},
            scales: {
                x: { grid: { color: 'rgba(226,232,240,0.1)', drawBorder: false }, ticks: { color: '#e2e8f0' }},
                y: { grid: { color: 'rgba(226,232,240,0.1)', drawBorder: false }, ticks: { color: '#e2e8f0' }, beginAtZero: true }
            },
            animation: { duration: 2000 }
        }
    });
    
    setInterval(() => {
        const now = new Date();
        labels.shift();
        labels.push(`${now.getHours()}h${now.getMinutes()}`);
        attackData.shift();
        normalData.shift();
        const newAttack = Math.floor(Math.random() * 30) + 20;
        const newNormal = Math.floor(Math.random() * 15) + 5;
        if (Math.random() > 0.95) { attackData.push(newAttack * 3); } else { attackData.push(newAttack); }
        normalData.push(newNormal);
        chart.update();
    }, 5000);
}

function initKitsuneChart() {
    const ctxElement = document.getElementById('kitsuneChart');
    if (!ctxElement) return;
    const ctx = ctxElement.getContext('2d');
    const data = Array.from({length: 10}, () => Math.floor(Math.random() * 100) / 100);
    data[3] = 0.95; data[7] = 0.98;
    new Chart(ctx, { type: 'bar', data: { labels: data.map((_, i) => i+1), datasets: [{ data: data, backgroundColor: ['#3b82f6','#3b82f6','#3b82f6','#ef4444','#3b82f6','#3b82f6','#3b82f6','#ef4444','#3b82f6','#3b82f6'], borderColor: ['#3b82f6','#3b82f6','#3b82f6','#ef4444','#3b82f6','#3b82f6','#3b82f6','#ef4444','#3b82f6','#3b82f6'], borderWidth: 1 }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: {display: false }}, scales: { x: { grid: {display: false, drawBorder: false}, ticks: {color: '#e2e8f0'}}, y: { grid: {color: 'rgba(226,232,240,0.1)', drawBorder: false}, ticks: {color: '#e2e8f0', callback: function(value){return value.toFixed(1);}}, min:0, max:1 }}}});
}

function initLucidChart() {
    const ctxElement = document.getElementById('lucidChart');
    if (!ctxElement) return;
    const ctx = ctxElement.getContext('2d');
    const labels = Array.from({length: 24}, (_, i) => `${i}h`);
    const data = Array.from({length: 24}, () => 0);
    data[3]=1; data[12]=1; data[20]=1;
    new Chart(ctx, { type: 'line', data: { labels: labels, datasets: [{ data: data, borderColor: '#a855f7', backgroundColor: 'rgba(168,85,247,0.1)', borderWidth:2, pointRadius:5, pointBackgroundColor:'#ef4444', pointHoverRadius:7, tension:0.1}] }, options: { responsive:true, maintainAspectRatio:false, plugins: { legend: {display:false}}, scales: { x: { grid: {color:'rgba(226,232,240,0.1)', drawBorder:false}, ticks:{color:'#e2e8f0',maxRotation:0,autoSkip:true,maxTicksLimit:12}}, y: {display:false,min:0,max:1}}}});
}

function initVertexChart() {
    const ctxElement = document.getElementById('vertexChart');
    if (!ctxElement) return;
    const ctx = ctxElement.getContext('2d');
    new Chart(ctx, { type: 'doughnut', data: { labels: ['DDoS','Brute Force','Port Scan','Zero-Day','Autre'], datasets: [{ data:[35,25,20,15,5], backgroundColor:['#ef4444','#f97316','#f59e0b','#a855f7','#64748b'], borderWidth:0}]}, options: { responsive:true, maintainAspectRatio:false, plugins:{legend:{display:false}}, cutout:'70%', animation:{animateScale:true, animateRotate:true}}});
}

function initSystemStatus() {
    const circle = document.querySelector('.progress-ring-circle');
    if (!circle) return;
    const radius = circle.r.baseVal.value;
    const circumference = radius * 2 * Math.PI;
    circle.style.strokeDasharray = circumference;
    circle.style.strokeDashoffset = circumference - (0.85 * circumference);
}


// --- Logique des Alertes Critiques et Modal du Dashboard ---

async function fetchCriticalAlerts() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/dashboard/critical-alerts`);
        if (!response.ok) {
            console.error('Échec de la récupération des alertes critiques:', response.status, await response.text());
            return { alerts_for_display: [], total_critical_count: 0 }; // Return default structure on error
        }
        return await response.json(); // Expected: { alerts_for_display: [], total_critical_count: X }
    } catch (error) {
        console.error('Erreur lors de la récupération des alertes critiques:', error);
        return { alerts_for_display: [], total_critical_count: 0 }; // Return default structure on error
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
    const responseData = await fetchCriticalAlerts(); 
    
    if (responseData && typeof responseData === 'object' && responseData.alerts_for_display) {
        renderCriticalAlerts(responseData.alerts_for_display);

        const alertLink = document.querySelector("a.sidebar-item[href*='/alert']");
        if (alertLink) {
            const alertCountBadge = alertLink.querySelector("span.blink"); 
            if (alertCountBadge) {
                alertCountBadge.textContent = responseData.total_critical_count > 0 ? responseData.total_critical_count : '0';
            } else {
                // console.warn("Sidebar alert count badge (span.blink) not found within alert link.");
            }
        } else {
            // console.warn("Sidebar alert link not found.");
        }
    } else {
        // Fallback for old format or if fetchCriticalAlerts returns array directly on some error paths
        renderCriticalAlerts(Array.isArray(responseData) ? responseData : []); 
        // console.warn("Critical alerts data received in an unexpected format or fetch failed.");
        const alertLink = document.querySelector("a.sidebar-item[href*='/alert']");
        if (alertLink) {
            const alertCountBadge = alertLink.querySelector("span.blink");
            if (alertCountBadge) {
                if (Array.isArray(responseData)) {
                    alertCountBadge.textContent = responseData.length > 0 ? responseData.length : '0';
                } else {
                    alertCountBadge.textContent = '0'; 
                }
            }
        }
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
    recommendations: document.getElementById('modalDashboardRecommendations'),
    closeButton: document.getElementById('closeDashboardAlertModal'),
    contentEl: document.getElementById('dashboardAlertModalContent')
};

let currentDashboardAlertId = null;

async function showDashboardAlertModal(alertId) {
    if (!alertId || !dashboardModal.el || !dashboardModal.contentEl) {
        console.error("Modal elements not found for displaying alert details.");
        return;
    }
    currentDashboardAlertId = alertId;

    if(dashboardModal.title) dashboardModal.title.innerHTML = `<i class="fas fa-spinner fa-spin mr-2"></i> Chargement...`;
    if(dashboardModal.rawDetails) dashboardModal.rawDetails.textContent = "Récupération des détails...";
    if(dashboardModal.recommendations) dashboardModal.recommendations.innerHTML = '<li>Chargement...</li>';
    
    dashboardModal.el.classList.remove('hidden');
    requestAnimationFrame(() => { 
        dashboardModal.el.classList.remove('opacity-0');
        dashboardModal.contentEl.classList.remove('opacity-0', 'scale-95');
        dashboardModal.el.classList.add('opacity-100');
        dashboardModal.contentEl.classList.add('opacity-100', 'scale-100');
    });

    try {
        const response = await fetch(`${API_BASE_URL}/api/alert/${alertId}`);
        if (!response.ok) throw new Error(`HTTP error ${response.status}`);
        const details = await response.json();

        if(dashboardModal.title) dashboardModal.title.innerHTML = `<i class="fas fa-${details.severity === 'high' || details.severity === 'critique' ? 'exclamation-triangle text-red-400' : (details.severity === 'medium' || details.severity === 'moyen' ? 'exclamation-circle text-orange-400' : 'info-circle text-yellow-400')} mr-2"></i> Détail de l'Alerte`;
        if(dashboardModal.subtitle) dashboardModal.subtitle.textContent = `${details.id || 'DB-' + alertId}`;
        if(dashboardModal.timestamp) dashboardModal.timestamp.textContent = details.timestamp ? new Date(details.timestamp).toLocaleString('fr-FR') : 'N/A';
        if(dashboardModal.sourceIP) dashboardModal.sourceIP.textContent = details.sourceIP || 'N/A';
        if(dashboardModal.destIP) dashboardModal.destIP.textContent = details.destIP || 'N/A';
        if(dashboardModal.sourcePort) dashboardModal.sourcePort.textContent = details.sourcePort !== null ? details.sourcePort : 'N/A';
        if(dashboardModal.destPort) dashboardModal.destPort.textContent = details.destPort !== null ? details.destPort : 'N/A';
        if(dashboardModal.protocol) dashboardModal.protocol.textContent = details.protocol || 'N/A';
        if(dashboardModal.model) dashboardModal.model.textContent = details.model || 'N/A';
        if(dashboardModal.type) dashboardModal.type.textContent = details.type || details.scan_type || 'N/A'; 
        if(dashboardModal.score) dashboardModal.score.textContent = details.score !== null ? parseFloat(details.score).toFixed(2) : 'N/A';
        
        if(dashboardModal.severity) {
            const severityText = details.severity ? details.severity.charAt(0).toUpperCase() + details.severity.slice(1) : 'N/A';
            dashboardModal.severity.textContent = severityText;
            let severityColorClass = 'text-yellow-400'; 
            if (details.severity === 'high' || details.severity === 'critique') severityColorClass = 'text-red-400';
            else if (details.severity === 'medium' || details.severity === 'moyen') severityColorClass = 'text-orange-400';
            dashboardModal.severity.className = `font-mono capitalize font-semibold ${severityColorClass}`;
        }
        
        if(dashboardModal.rawDetails) dashboardModal.rawDetails.textContent = details.raw_details || 'Aucun détail brut disponible.';

        if (dashboardModal.recommendations) {
            dashboardModal.recommendations.innerHTML = ''; 
            if (details.recommendations && details.recommendations.length > 0) {
                details.recommendations.forEach(reco => {
                    const li = document.createElement('li');
                    li.textContent = reco;
                    dashboardModal.recommendations.appendChild(li);
                });
            } else {
                const li = document.createElement('li');
                li.textContent = 'Aucune recommandation spécifique.';
                dashboardModal.recommendations.appendChild(li);
            }
        }

        if (dashboardModal.contentEl) { 
            dashboardModal.contentEl.classList.remove('border-red-500', 'border-orange-500', 'border-yellow-500', 'border-gray-700/50');
            if (details.severity === 'high' || details.severity === 'critique') {
                dashboardModal.contentEl.classList.add('border-red-500');
            } else if (details.severity === 'medium' || details.severity === 'moyen') {
                dashboardModal.contentEl.classList.add('border-orange-500');
            } else { 
                dashboardModal.contentEl.classList.add('border-yellow-500');
            }
        }

    } catch (error) {
        console.error('Erreur lors de la récupération des détails de l’alerte pour le modal:', error);
        if(dashboardModal.title) dashboardModal.title.innerHTML = `<i class="fas fa-exclamation-circle text-red-400 mr-2"></i> Erreur`;
        if(dashboardModal.rawDetails) dashboardModal.rawDetails.textContent = "Impossible de charger les détails de l'alerte.";
        if(dashboardModal.contentEl) dashboardModal.contentEl.classList.add('border-red-500');
    }
}

function closeDashboardAlertModal() {
    if (!dashboardModal.el || !dashboardModal.contentEl) return;
    dashboardModal.el.classList.add('opacity-0');
    dashboardModal.contentEl.classList.add('opacity-0','scale-95'); 
    setTimeout(() => {
        dashboardModal.el.classList.add('hidden');
        if(dashboardModal.title) dashboardModal.title.innerHTML = `<i class="fas fa-shield-alt mr-2"></i>Détails de l'Alerte`;
        if(dashboardModal.subtitle) dashboardModal.subtitle.textContent = 'N/A';
        if(dashboardModal.timestamp) dashboardModal.timestamp.textContent = 'N/A';
        if(dashboardModal.sourceIP) dashboardModal.sourceIP.textContent = 'N/A';
        if(dashboardModal.destIP) dashboardModal.destIP.textContent = 'N/A';
        if(dashboardModal.sourcePort) dashboardModal.sourcePort.textContent = 'N/A';
        if(dashboardModal.destPort) dashboardModal.destPort.textContent = 'N/A';
        if(dashboardModal.protocol) dashboardModal.protocol.textContent = 'N/A';
        if(dashboardModal.model) dashboardModal.model.textContent = 'N/A';
        if(dashboardModal.type) dashboardModal.type.textContent = 'N/A';
        if(dashboardModal.score) dashboardModal.score.textContent = 'N/A';
        if(dashboardModal.severity) {
            dashboardModal.severity.textContent = 'N/A';
            dashboardModal.severity.className = 'font-mono capitalize'; 
        }
        if(dashboardModal.rawDetails) dashboardModal.rawDetails.textContent = 'N/A';
        if(dashboardModal.recommendations) dashboardModal.recommendations.innerHTML = '<li>N/A</li>';
        
        if (dashboardModal.contentEl) { 
            dashboardModal.contentEl.classList.remove('border-red-500', 'border-orange-500', 'border-yellow-500', 'opacity-100', 'scale-100');
            dashboardModal.contentEl.classList.add('border-gray-700/50', 'opacity-0', 'scale-95'); 
        }
    }, 300); 
}

document.addEventListener('DOMContentLoaded', () => {
    createParticles();
    initAttackChart(); 
    initKitsuneChart();
    initLucidChart();
    initVertexChart();
    initSystemStatus(); 

    fetchAndRenderCriticalAlerts();
    setInterval(fetchAndRenderCriticalAlerts, 30000); 

    const profileTrigger = document.getElementById("profile-trigger");
    const profileMenu = document.getElementById("profile-menu");
    const chevronIcon = document.getElementById("chevron-icon");

    if (profileTrigger && profileMenu && chevronIcon) {
        profileTrigger.addEventListener("click", function (e) {
            e.stopPropagation();
            profileMenu.classList.toggle("hidden");
            if (!profileMenu.classList.contains("hidden")) {
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
            if (profileMenu && !profileMenu.classList.contains("hidden") && !profileMenu.contains(e.target) && !profileTrigger.contains(e.target)) {
                profileMenu.classList.add('opacity-0', 'scale-95');
                profileMenu.classList.remove('opacity-100', 'scale-100');
                setTimeout(() => profileMenu.classList.add("hidden"), 300); 
                chevronIcon.classList.remove("rotate-180");
            }
        });
        if(profileMenu) profileMenu.addEventListener("click", e => e.stopPropagation());
    }

    if (dashboardModal.closeButton) { 
        dashboardModal.closeButton.onclick = closeDashboardAlertModal;
    }
    
    if (dashboardModal.el) { 
        dashboardModal.el.onclick = (event) => {
            if (event.target === dashboardModal.el) {
                closeDashboardAlertModal();
            }
        };
    }
    
    const primaryModalButton = document.getElementById('primaryActionDashboardAlertModal');
    if (primaryModalButton) {
        primaryModalButton.onclick = () => {
            if (currentDashboardAlertId) {
                window.location.href = `${API_BASE_URL}/alert?alert_db_id=${currentDashboardAlertId}`;
            }
            closeDashboardAlertModal(); 
        };
    }
    
    const secondaryModalButton = document.getElementById('secondaryActionDashboardAlertModal');
    if (secondaryModalButton) {
        secondaryModalButton.onclick = () => {
            console.log("Secondary action for alert ID:", currentDashboardAlertId);
            closeDashboardAlertModal();
        }
    }
    
    setInterval(() => {
        const lastScanEl = document.getElementById('lastScanTime');
        if(lastScanEl) lastScanEl.textContent = formatTimeAgo(new Date());
    }, 60000);
});
