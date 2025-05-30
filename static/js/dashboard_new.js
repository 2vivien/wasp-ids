// Connect to Socket.IO
const socket = io();

// Global variable for the attack chart instance
let attackChartInstance; 

// Create floating particles
function createParticles() {
    const container = document.getElementById('particles-container');
    if (!container) return;
    const particleCount = 40;
    
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

// Initialize attack chart (will be populated by Socket.IO events)
function initAttackChart() {
    const ctx = document.getElementById('attackChart').getContext('2d');
    if (!ctx) return;

    attackChartInstance = new Chart(ctx, { 
        type: 'line',
        data: {
            labels: [], // Initial empty labels
            datasets: [
                {
                    label: 'Alerts', 
                    data: [], 
                    borderColor: '#ef4444', // Red color for alerts
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    borderWidth: 2,
                    tension: 0.3, 
                    fill: true,
                    pointRadius: 2, 
                    pointBackgroundColor: '#ef4444'
                }
            ]
        },
        options: { 
            responsive: true,
            maintainAspectRatio: false,
            plugins: { 
                legend: { 
                    display: true, 
                    labels: { color: '#e2e8f0' } 
                }, 
                tooltip: { mode: 'index', intersect: false } 
            },
            scales: {
                x: { 
                    grid: { color: 'rgba(226, 232, 240, 0.1)', drawBorder: false }, 
                    ticks: { color: '#e2e8f0', autoSkip: true, maxTicksLimit: 20 },
                    title: { display: true, text: 'Time', color: '#e2e8f0'}
                },
                y: { 
                    grid: { color: 'rgba(226, 232, 240, 0.1)', drawBorder: false }, 
                    ticks: { color: '#e2e8f0', stepSize: 1 }, 
                    beginAtZero: true,
                    title: { display: true, text: 'Number of Alerts', color: '#e2e8f0'}
                }
            },
            animation: { 
                duration: 250 
            }
        }
    });
}

// Initialize Kitsune chart (keeps its random data for now)
function initKitsuneChart() {
    const ctx = document.getElementById('kitsuneChart').getContext('2d');
    if (!ctx) return;    
    const data = Array.from({length: 10}, () => Math.floor(Math.random() * 100) / 100);
    data[3] = 0.95;
    data[7] = 0.98;
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.map((_, i) => i+1),
            datasets: [{
                data: data,
                backgroundColor: ['#3b82f6', '#3b82f6', '#3b82f6', '#ef4444', '#3b82f6', '#3b82f6', '#3b82f6', '#ef4444', '#3b82f6', '#3b82f6'],
                borderColor: ['#3b82f6', '#3b82f6', '#3b82f6', '#ef4444', '#3b82f6', '#3b82f6', '#3b82f6', '#ef4444', '#3b82f6', '#3b82f6'],
                borderWidth: 1
            }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { grid: { display: false, drawBorder: false }, ticks: { color: '#e2e8f0' } }, y: { grid: { color: 'rgba(226, 232, 240, 0.1)', drawBorder: false }, ticks: { color: '#e2e8f0', callback: function(value) { return value.toFixed(1); } }, min: 0, max: 1 } } }
    });
}

// Initialize LUCID chart (keeps its random data for now)
function initLucidChart() {
    const ctx = document.getElementById('lucidChart').getContext('2d');
    if (!ctx) return;
    const labels = Array.from({length: 24}, (_, i) => `${i}h`);
    const data = Array.from({length: 24}, () => 0);
    data[3] = 1; data[12] = 1; data[20] = 1;
    new Chart(ctx, {
        type: 'line',
        data: { labels: labels, datasets: [{ data: data, borderColor: '#a855f7', backgroundColor: 'rgba(168, 85, 247, 0.1)', borderWidth: 2, pointRadius: 5, pointBackgroundColor: '#ef4444', pointHoverRadius: 7, tension: 0.1 }] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { grid: { color: 'rgba(226, 232, 240, 0.1)', drawBorder: false }, ticks: { color: '#e2e8f0', maxRotation: 0, autoSkip: true, maxTicksLimit: 12 } }, y: { display: false, min: 0, max: 1 } } }
    });
}

// Initialize Vertex AI chart (keeps its random data for now)
function initVertexChart() {
    const ctx = document.getElementById('vertexChart').getContext('2d');
    if (!ctx) return;
    new Chart(ctx, {
        type: 'doughnut',
        data: { labels: ['DDoS', 'Brute Force', 'Port Scan', 'Zero-Day', 'Autre'], datasets: [{ data: [35, 25, 20, 15, 5], backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#a855f7', '#64748b'], borderWidth: 0 }] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, cutout: '70%', animation: { animateScale: true, animateRotate: true } }
    });
}

// Initialize system status ring (will be updated by Socket.IO)
function initSystemStatus() {
    const circle = document.querySelector('.progress-ring-circle');
    if (!circle) return;
    const radius = circle.r.baseVal.value;
    const circumference = radius * 2 * Math.PI;
    circle.style.strokeDasharray = circumference;
    const initialPercentage = 0; // Start at 0%
    circle.style.strokeDashoffset = circumference - (initialPercentage * circumference);
    const textElement = document.querySelector('.progress-ring-circle + text');
    if (textElement) {
        textElement.textContent = `${Math.round(initialPercentage * 100)}%`;
    }
}

// Socket.IO event listeners
socket.on('system_status_update', function(data) {
    // console.log('System status update received:', data);
    const packetCountEl = document.getElementById('dashboardPacketCount');
    const alertCountEl = document.getElementById('dashboardAlertCount');
    const sidebarAlertCountEl = document.getElementById('sidebarAlertCount');

    if (packetCountEl) packetCountEl.textContent = data.packets || 0;
    if (alertCountEl) alertCountEl.textContent = data.alerts || 0;
    if (sidebarAlertCountEl) sidebarAlertCountEl.textContent = data.alerts || 0;

    const circle = document.querySelector('.progress-ring-circle');
    const textElement = document.querySelector('.progress-ring-circle + text');
    if (circle && textElement) {
        const radius = circle.r.baseVal.value;
        const circumference = radius * 2 * Math.PI;
        const percentage = (data.packets || 0) > 0 ? Math.min(1, (data.alerts || 0) / (data.packets || 1)) : 0;
        circle.style.strokeDashoffset = circumference - (percentage * circumference);
        textElement.textContent = `${Math.round(percentage * 100)}%`;
    }
});

const MAX_CRITICAL_ALERTS_DISPLAY = 10; 

socket.on('new_alert', function(alert) {
    // console.log('New alert received:', alert);
    const criticalAlertsTableBody = document.getElementById('criticalAlertsTableBody');
    if (criticalAlertsTableBody) {
        const newRow = document.createElement('tr');
        newRow.classList.add('border-b', 'border-gray-700/30', 'hover:bg-gray-800/50', 'transition');
        const formattedTimestamp = new Date(alert.timestamp).toLocaleString();
        const severity = alert.severity ? alert.severity.toLowerCase() : 'low';
        let severityColor = 'text-green-500'; // Default to low
        if (severity === 'high' || severity === 'critical') {
            severityColor = 'text-red-500';
        } else if (severity === 'medium') {
            severityColor = 'text-yellow-500';
        }

        newRow.innerHTML = `
            <td class="py-2 px-2 text-xs">${formattedTimestamp}</td>
            <td class="py-2 px-2 text-xs text-red-400">${alert.source_ip || 'N/A'}</td>
            <td class="py-2 px-2 text-xs">${alert.model_name || alert.scan_type || 'N/A'}</td>
            <td class="py-2 px-2 text-xs">${alert.scan_type || 'N/A'}</td>
            <td class="py-2 px-2 text-xs">
                <span class="${severityColor}">${alert.severity || 'N/A'}</span>
            </td>
            <td class="py-2 px-2 text-xs">
                <button class="text-green-400 hover:text-green-300 transition" title="View details">
                    <i class="fas fa-search"></i>
                </button>
            </td>
        `;
        criticalAlertsTableBody.prepend(newRow);
        while (criticalAlertsTableBody.rows.length > MAX_CRITICAL_ALERTS_DISPLAY) {
            criticalAlertsTableBody.deleteRow(criticalAlertsTableBody.rows.length - 1);
        }
    }

    if (attackChartInstance) {
        const chart = attackChartInstance;
        const now = new Date();
        const currentLabel = `${now.getHours()}:${String(now.getMinutes()).padStart(2, '0')}`;
        const lastLabel = chart.data.labels.length > 0 ? chart.data.labels[chart.data.labels.length - 1] : null;

        if (lastLabel === currentLabel) {
            chart.data.datasets[0].data[chart.data.datasets[0].data.length - 1]++;
        } else {
            if (chart.data.labels.length >= 20) { // Max 20 data points
                chart.data.labels.shift();
                chart.data.datasets[0].data.shift();
            }
            chart.data.labels.push(currentLabel);
            chart.data.datasets[0].data.push(1);
        }
        chart.update(); 
    }
});

// Initialize everything when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    createParticles();
    initAttackChart(); // Initialize the main attack chart (now data-driven)
    initKitsuneChart();
    initLucidChart();
    initVertexChart();
    initSystemStatus(); // Initialize system status display
    
    // Blinking alerts visual effect (can be kept)
    const alertGlowElements = document.querySelectorAll('.alert-glow');
    if (alertGlowElements.length > 0) {
        setInterval(() => {
            alertGlowElements.forEach(alertEl => {
                alertEl.style.animation = 'none';
                void alertEl.offsetHeight; // Trigger reflow
                alertEl.style.animation = ''; // Re-apply animation from CSS
            });
        }, 3000); // Re-trigger blink animation periodically
    }
    
    // Removed: Simulate system status updates (now handled by Socket.IO)
});

// Profile menu toggle (remains unchanged)
function toggleProfileMenu() {
    const menu = document.getElementById('profile-menu');
    const chevron = document.getElementById('chevron-icon');
    if (!menu || !chevron) return;

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
