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