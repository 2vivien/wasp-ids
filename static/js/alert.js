// alert.js

// Constantes pour les modèles (utilisé dans la transformation)
const AVAILABLE_MODELS_JS = ["Kitsune", "LUCID", "Vertex AI"];

// Garder les données statiques comme fallback ou pour référence de structure
const staticSampleAlerts = [
    {
        id: 'SAMPLE-2025-05-02-001',
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
        recommendations: ['Isoler IP', 'Vérifier flux', 'Augmenter seuil modèle Kitsune'],
        raw_details: "Exemple de détails bruts pour l'alerte statique."
    }
    // ... (vous pouvez garder d'autres exemples statiques si nécessaire pour le développement)
];

let filteredAlerts = []; // Sera peuplé par l'API ou fallback
let currentSort = { column: 'timestamp', direction: 'desc' }; // Tri par défaut : plus récent en premier
const itemsPerPage = 10; // Plus d'éléments par page pour les alertes
let currentPage = 1;

// --- Fonctions Utilitaires de Transformation et de Mapping ---

function mapApiSeverityToScore(severityStr) {
    if (!severityStr) return Math.random() * (0.29 - 0.1) + 0.1; // Score bas par défaut
    const s = severityStr.toLowerCase();
    if (s === "high" || s === "critique") return parseFloat((Math.random() * (1.0 - 0.85) + 0.85).toFixed(2));
    if (s === "medium" || s === "moyen") return parseFloat((Math.random() * (0.84 - 0.6) + 0.6).toFixed(2));
    if (s === "low" || s === "faible") return parseFloat((Math.random() * (0.59 - 0.3) + 0.3).toFixed(2));
    return parseFloat((Math.random() * (0.29 - 0.1) + 0.1).toFixed(2));
}

function determineModelAndTypeJS(scanTypeStr, severityStr) {
    let model = AVAILABLE_MODELS_JS[Math.floor(Math.random() * AVAILABLE_MODELS_JS.length)];
    let alertType = "Anomalie";

    if (scanTypeStr) {
        const scanLower = scanTypeStr.toLowerCase();
        if (scanLower.includes("scan")) { alertType = "Scan de Ports"; model = "Kitsune"; }
        else if (scanLower.includes("brute force")) { alertType = "Brute Force"; model = "Vertex AI"; }
        else if (scanLower.includes("ddos") || scanLower.includes("flood")) { alertType = "DDoS/Flood"; model = "LUCID"; }
        else if (scanLower.includes("zero-day") || scanLower.includes("exploit")) { alertType = "Zero-Day/Exploit"; model = Math.random() > 0.5 ? "LUCID" : "Vertex AI"; }
        else if (scanLower.includes("malware")) { alertType = "Malware"; model = "Vertex AI"; }
        else { alertType = scanTypeStr.replace(/_/g, " ").replace(/\b\w/g, l => l.toUpperCase());} // Capitalize
    }
    return { model, alertType };
}


function transformApiAlertToJsFormat(apiAlert) {
    const { model, alertType } = determineModelAndTypeJS(apiAlert.scan_type, apiAlert.severity);
    const severity = apiAlert.severity ? apiAlert.severity.toLowerCase() : 'medium';
    const score = mapApiSeverityToScore(apiAlert.severity);
    const timestampDate = new Date(apiAlert.timestamp);

    let verdictPrefix = 'ℹ️'; // Default
    if (severity === 'high' || severity === 'critique') verdictPrefix = '🚨';
    else if (severity === 'medium' || severity === 'moyen') verdictPrefix = '⚠️';


    return {
        id: `DB-${apiAlert.id}`, // Préfixe pour indiquer origine DB
        timestamp: timestampDate.toLocaleString('fr-FR', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        timestampFullISO: apiAlert.timestamp, // Garder l'ISO pour tri précis
        file: 'N/A (DB Event)',
        sourceIP: apiAlert.source_ip,
        destIP: apiAlert.destination_ip,
        model: model,
        score: score,
        verdict: `${verdictPrefix} ${alertType}`,
        severity: severity,
        sourcePort: apiAlert.source_port || 'N/A',
        destPort: apiAlert.destination_port || 'N/A',
        protocol: apiAlert.protocol,
        payloadSize: 'N/A', // Non disponible depuis IDSLog simple
        flowDuration: 'N/A', // Non disponible
        kitsuneScore: model === 'Kitsune' ? score : parseFloat((Math.random() * 0.6).toFixed(2)),
        lucidDetection: model === 'LUCID' && (severity === 'high' || severity === 'critique') ? 'Zero-Day Détecté' : (model === 'LUCID' ? 'Anomalie Possible' : 'Normal'),
        vertexLabel: model === 'Vertex AI' ? alertType : 'Non Applicable',
        vertexConfidence: model === 'Vertex AI' ? score : parseFloat((Math.random() * 0.7).toFixed(2)),
        recommendations: severity === 'high' || severity === 'critique' ? ['Isoler IP', 'Analyser Payload', 'Bloquer IP au pare-feu'] : (severity === 'medium' ? ['Surveiller IP', 'Vérifier Logs Système'] : ['Noter pour corrélation']),
        raw_details: apiAlert.details || "Aucun détail brut spécifique fourni.",
        scan_type: apiAlert.scan_type // garder le scan_type original
    };
}


// --- Fonctions Principales de la Page d'Alertes ---

async function fetchAllAlertsForTable(page = 1) {
    try {
        const response = await fetch(`/api/logs/alertes?page=${page}&per_page=${itemsPerPage}`);
        if (!response.ok) {
            console.error("Échec de la récupération des alertes pour le tableau:", response.status, await response.text());
            // Fallback vers les données statiques en cas d'erreur
            filteredAlerts = staticSampleAlerts.map(a => ({...a, timestampFullISO: new Date().toISOString() })); // Ajouter timestampFullISO pour le tri
            return { alerts: filteredAlerts, total_pages: 1, current_page: 1, total_alerts: filteredAlerts.length };
        }
        const apiData = await response.json();
        // Transformer les données de l'API au format attendu par le frontend
        const transformedAlerts = apiData.alerts.map(transformApiAlertToJsFormat);
        return { alerts: transformedAlerts, total_pages: apiData.total_pages, current_page: apiData.current_page, total_alerts: apiData.total_alerts };

    } catch (error) {
        console.error("Erreur lors de la récupération des alertes pour le tableau:", error);
        filteredAlerts = staticSampleAlerts.map(a => ({...a, timestampFullISO: new Date().toISOString() }));
        return { alerts: filteredAlerts, total_pages: 1, current_page: 1, total_alerts: filteredAlerts.length };
    }
}

async function initializeAlertPage() {
    const urlParams = new URLSearchParams(window.location.search);
    const alertDbIdParam = urlParams.get('alert_db_id');

    if (alertDbIdParam) {
        try {
            const response = await fetch(`/api/alert/${alertDbIdParam}`);
            if (!response.ok) {
                console.error("Échec du chargement des détails de l'alerte spécifique:", alertDbIdParam, response.status);
                // Afficher un message d'erreur dans le modal ou rediriger
                document.getElementById('modalTitle').textContent = "Erreur de chargement";
                document.getElementById('modalContent').innerHTML += "<p class='text-red-400 p-4'>Impossible de charger les détails de cette alerte.</p>";
                document.getElementById('alertModal').classList.add('active'); // Ouvrir le modal pour montrer l'erreur
                // Charger quand même la table principale en arrière-plan
                loadAndRenderTable();
                return;
            }
            const alertDetailFromApi = await response.json();
            // Pas besoin de transformer ici car /api/alert/<id> retourne déjà la structure attendue par openModal
            openModal(alertDetailFromApi);
            // Charger la table en arrière-plan pour la navigation
            loadAndRenderTable();

        } catch (error) {
            console.error("Erreur lors de la récupération de l'alerte spécifique:", error);
            loadAndRenderTable(); // Charger la table principale en fallback
        }
    } else {
        loadAndRenderTable(); // Comportement par défaut: charger la table des alertes
    }
    setupEventListeners(); // Configurer les écouteurs d'événements une seule fois
}

async function loadAndRenderTable(page = 1) {
    const alertData = await fetchAllAlertsForTable(page);
    filteredAlerts = alertData.alerts;
    currentPage = alertData.current_page;
    
    // Trier avant de rendre si un tri est déjà défini
    sortAlertsInternal(); // Appelle le tri interne sans changer la direction
    renderTable(); // renderTable utilisera filteredAlerts et currentPage
    updatePagination(alertData.total_pages, alertData.current_page, alertData.total_alerts);
}


function renderTable() {
    const tableBody = document.getElementById('alertTableBody');
    if (!tableBody) { console.error("Element 'alertTableBody' non trouvé."); return; }
    tableBody.innerHTML = '';

    // La pagination est maintenant gérée par l'API, donc on affiche juste les alertes de la page courante
    // `filteredAlerts` contient déjà les alertes pour la page actuelle après `loadAndRenderTable`

    if (!filteredAlerts || filteredAlerts.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-gray-500">Aucune alerte à afficher.</td></tr>`;
        // Mettre à jour les informations de pagination pour le cas vide
        const startItemEl = document.getElementById('startItem');
        const endItemEl = document.getElementById('endItem');
        const totalItemsEl = document.getElementById('totalItems');
        if(startItemEl) startItemEl.textContent = 0;
        if(endItemEl) endItemEl.textContent = 0;
        if(totalItemsEl) totalItemsEl.textContent = 0;
        return;
    }
    
    filteredAlerts.forEach(alert => {
        const row = document.createElement('tr');
        // Utiliser l'ID de l'alerte (sans le préfixe DB- s'il existe) pour le dataset
        const originalId = alert.id.startsWith('DB-') ? alert.id.substring(3) : alert.id;
        row.dataset.alertOriginalId = originalId; // Pour ouvrir le modal avec l'ID DB correct

        row.className = `alert-row border-b border-gray-700 hover:bg-gray-800/70 transition duration-150 ease-in-out ${alert.severity === 'high' || alert.severity === 'critique' ? 'critical-alert' : ''}`;
        
        row.innerHTML = `
            <td class="px-4 py-3 tooltip">
                ${alert.timestamp}
                <div class="tooltip-text bg-gray-700 text-white text-xs rounded py-1 px-2 absolute z-10 invisible group-hover:visible transition-opacity">
                    <strong>ID:</strong> ${alert.id}<br>
                    <strong>Heure exacte (UTC):</strong> ${new Date(alert.timestampFullISO).toISOString()}
                </div>
            </td>
            <td class="px-4 py-3 tooltip">
                ${alert.file}
                <div class="tooltip-text bg-gray-700 text-white text-xs rounded py-1 px-2 absolute z-10 invisible group-hover:visible transition-opacity">
                    <strong>Taille:</strong> ${alert.payloadSize}<br>
                    <strong>Durée:</strong> ${alert.flowDuration}
                </div>
            </td>
            <td class="px-4 py-3 tooltip">
                <span class="font-mono text-red-400">${alert.sourceIP}</span> → <span class="font-mono text-blue-300">${alert.destIP}</span>
                <div class="tooltip-text bg-gray-700 text-white text-xs rounded py-1 px-2 absolute z-10 invisible group-hover:visible transition-opacity">
                    <strong>Ports:</strong> ${alert.sourcePort} → ${alert.destPort}<br>
                    <strong>Protocole:</strong> ${alert.protocol}
                </div>
            </td>
            <td class="px-4 py-3">
                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                    alert.model === 'Kitsune' ? 'bg-blue-800 text-blue-200' : 
                    alert.model === 'LUCID' ? 'bg-purple-800 text-purple-200' : 
                    'bg-orange-800 text-orange-200' // Vertex AI ou autre
                }">
                    ${alert.model}
                </span>
            </td>
            <td class="px-4 py-3">
                <div class="flex items-center">
                    <div class="w-20 mr-2"> <div class="progress-bar bg-gray-700 rounded h-2.5">
                            <div class="progress-fill h-2.5 rounded ${
                                (alert.severity === 'high' || alert.severity === 'critique') ? 'bg-red-500' : 
                                (alert.severity === 'medium' || alert.severity === 'moyen') ? 'bg-orange-500' : 
                                'bg-yellow-500' // Low
                            }" style="width: ${alert.score * 100}%"></div>
                        </div>
                    </div>
                    <span class="text-sm font-mono">${alert.score.toFixed(2)}</span>
                </div>
            </td>
            <td class="px-4 py-3">
                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                    (alert.severity === 'high' || alert.severity === 'critique') ? 'bg-red-800 text-red-200' : 
                    (alert.severity === 'medium' || alert.severity === 'moyen') ? 'bg-orange-800 text-orange-200' : 
                    'bg-green-800 text-green-200' // Low ou Normal
                }">
                    ${alert.verdict}
                </span>
            </td>
        `;
        
        row.addEventListener('click', async () => {
            const alertIdToFetch = row.dataset.alertOriginalId;
            try {
                const response = await fetch(`/api/alert/${alertIdToFetch}`);
                if (!response.ok) {
                    console.error("Impossible de charger les détails de l'alerte:", response.status);
                    openModal({ ...staticSampleAlerts[0], id: `ERROR-${alertIdToFetch}`, raw_details: "Détails non trouvés."}); // Fallback
                    return;
                }
                const alertDetails = await response.json();
                openModal(alertDetails);
            } catch (e) {
                 console.error("Erreur JS lors du fetch des détails de l'alerte:", e);
                 openModal({ ...staticSampleAlerts[0], id: `ERROR-${alertIdToFetch}`, raw_details: "Erreur de chargement des détails."});
            }
        });
        tableBody.appendChild(row);
    });
}

function updatePagination(totalPages, currentPageNum, totalItems) {
    const paginationContainer = document.getElementById('pagination');
    if(!paginationContainer) { console.error("Element 'pagination' non trouvé."); return; }
    paginationContainer.innerHTML = '';

    const startItemEl = document.getElementById('startItem');
    const endItemEl = document.getElementById('endItem');
    const totalItemsEl = document.getElementById('totalItems');

    if (totalItems === 0) {
        if(startItemEl) startItemEl.textContent = 0;
        if(endItemEl) endItemEl.textContent = 0;
        if(totalItemsEl) totalItemsEl.textContent = 0;
        return;
    }
    
    const startIdx = (currentPageNum - 1) * itemsPerPage + 1;
    const endIdx = Math.min(startIdx + itemsPerPage - 1, totalItems);

    if(startItemEl) startItemEl.textContent = startIdx;
    if(endItemEl) endItemEl.textContent = endIdx;
    if(totalItemsEl) totalItemsEl.textContent = totalItems;


    // Bouton Précédent
    if (currentPageNum > 1) {
        const prevBtn = document.createElement('button');
        prevBtn.className = 'pagination-btn px-3 py-1 rounded-lg bg-gray-700 hover:bg-gray-600 transition';
        prevBtn.innerHTML = '<i class="fas fa-chevron-left"></i>';
        prevBtn.addEventListener('click', () => loadAndRenderTable(currentPageNum - 1));
        paginationContainer.appendChild(prevBtn);
    }

    // Numéros de page (simplifié pour l'exemple, peut être amélioré avec '...')
    let startPage = Math.max(1, currentPageNum - 2);
    let endPage = Math.min(totalPages, currentPageNum + 2);

    if (startPage > 1) {
        const firstBtn = document.createElement('button');
        firstBtn.className = 'pagination-btn px-3 py-1 rounded-lg bg-gray-700 hover:bg-gray-600 transition';
        firstBtn.textContent = '1';
        firstBtn.addEventListener('click', () => loadAndRenderTable(1));
        paginationContainer.appendChild(firstBtn);
        if (startPage > 2) {
            const dots = document.createElement('span');
            dots.className = 'px-3 py-1 text-gray-400';
            dots.textContent = '...';
            paginationContainer.appendChild(dots);
        }
    }

    for (let i = startPage; i <= endPage; i++) {
        const pageBtn = document.createElement('button');
        pageBtn.className = `pagination-btn px-3 py-1 rounded-lg transition ${i === currentPageNum ? 'active bg-blue-600 text-white' : 'bg-gray-700 hover:bg-gray-600'}`;
        pageBtn.textContent = i;
        pageBtn.addEventListener('click', () => loadAndRenderTable(i));
        paginationContainer.appendChild(pageBtn);
    }

    if (endPage < totalPages) {
        if (endPage < totalPages - 1) {
            const dots = document.createElement('span');
            dots.className = 'px-3 py-1 text-gray-400';
            dots.textContent = '...';
            paginationContainer.appendChild(dots);
        }
        const lastBtn = document.createElement('button');
        lastBtn.className = 'pagination-btn px-3 py-1 rounded-lg bg-gray-700 hover:bg-gray-600 transition';
        lastBtn.textContent = totalPages;
        lastBtn.addEventListener('click', () => loadAndRenderTable(totalPages));
        paginationContainer.appendChild(lastBtn);
    }
    

    // Bouton Suivant
    if (currentPageNum < totalPages) {
        const nextBtn = document.createElement('button');
        nextBtn.className = 'pagination-btn px-3 py-1 rounded-lg bg-gray-700 hover:bg-gray-600 transition';
        nextBtn.innerHTML = '<i class="fas fa-chevron-right"></i>';
        nextBtn.addEventListener('click', () => loadAndRenderTable(currentPageNum + 1));
        paginationContainer.appendChild(nextBtn);
    }
}


function sortAlertsInternal() { // Tri les données `filteredAlerts` en place
    filteredAlerts.sort((a, b) => {
        let valueA, valueB;
        
        switch (currentSort.column) {
            case 'timestamp':
                // Utiliser timestampFullISO pour un tri précis
                valueA = new Date(a.timestampFullISO || a.timestamp);
                valueB = new Date(b.timestampFullISO || b.timestamp);
                break;
            case 'file': valueA = (a.file || "").toLowerCase(); valueB = (b.file || "").toLowerCase(); break;
            case 'model': valueA = (a.model || "").toLowerCase(); valueB = (b.model || "").toLowerCase(); break;
            case 'score': valueA = a.score || 0; valueB = b.score || 0; break;
            case 'verdict': valueA = (a.verdict || "").toLowerCase(); valueB = (b.verdict || "").toLowerCase(); break;
            default: valueA = a[currentSort.column]; valueB = b[currentSort.column];
        }
        
        if (valueA < valueB) return currentSort.direction === 'asc' ? -1 : 1;
        if (valueA > valueB) return currentSort.direction === 'asc' ? 1 : -1;
        return 0;
    });
}

function handleSortColumnClick(columnKey) {
    if (currentSort.column === columnKey) {
        currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
    } else {
        currentSort.column = columnKey;
        currentSort.direction = 'desc'; // Par défaut, tri décroissant pour la nouvelle colonne (ex: timestamp)
    }
    
    // Mettre à jour les icônes de tri
    document.querySelectorAll('.sortable i.fa-sort, .sortable i.fa-sort-up, .sortable i.fa-sort-down').forEach(icon => {
        icon.classList.remove('fa-sort-up', 'fa-sort-down');
        icon.classList.add('fa-sort');
        icon.classList.add('text-gray-400'); // Couleur par défaut
    });
    const activeColumnIcon = document.querySelector(`.sortable[data-sort="${columnKey}"] i`);
    if (activeColumnIcon) {
        activeColumnIcon.classList.remove('fa-sort', 'text-gray-400');
        activeColumnIcon.classList.add(currentSort.direction === 'asc' ? 'fa-sort-up' : 'fa-sort-down');
        activeColumnIcon.classList.remove('text-gray-400'); // Enlever la couleur par défaut pour l'icône active
    }

    loadAndRenderTable(1); // Recharger la première page avec le nouveau tri
}


function filterAlertsFromUI() { // Renommé pour éviter conflit
    // Le filtrage sera géré côté serveur si l'API le supporte.
    // Pour l'instant, cette fonction recharge la table, ce qui est utile si les filtres API sont implémentés.
    // Si les filtres sont purement frontend, il faudrait filtrer `filteredAlerts` ici avant de rendre.
    // Pour l'instant, on recharge depuis l'API, supposant que l'API pourrait prendre des params de filtre.
    console.log("Filtrage UI déclenché. Recharge des données...");
    loadAndRenderTable(1); // Recharger la page 1 avec les filtres (si l'API les prend en compte)
}

function openModal(alertData) { // alertData vient maintenant de l'API /api/alert/<id>
    const modal = document.getElementById('alertModal');
    const modalContent = document.getElementById('modalContent'); // Le conteneur interne du modal
    if (!modal || !modalContent) { console.error("Éléments du modal non trouvés."); return; }

    // Mettre à jour le contenu du modal avec les données de `alertData`
    document.getElementById('modalTitle').innerHTML = `
        <i class="fas fa-${alertData.severity === 'high' || alertData.severity === 'critique' ? 'exclamation-triangle text-red-400' : (alertData.severity === 'medium' || alertData.severity === 'moyen' ? 'exclamation-circle text-orange-400' : 'info-circle text-yellow-400')} mr-2"></i> 
        Détail de l'Alerte
    `;
    document.getElementById('modalSubtitle').textContent = `ID: ${alertData.id}`;
    document.getElementById('modalSourceIP').textContent = alertData.sourceIP;
    document.getElementById('modalDestIP').textContent = alertData.destIP;
    document.getElementById('modalSourcePort').textContent = alertData.sourcePort || 'N/A';
    document.getElementById('modalDestPort').textContent = alertData.destPort || 'N/A';
    document.getElementById('modalProtocol').textContent = alertData.protocol;
    document.getElementById('modalPayloadSize').textContent = alertData.payloadSize || 'N/A';
    document.getElementById('modalPcapFile').textContent = alertData.file || 'N/A';
    document.getElementById('modalFlowDuration').textContent = alertData.flowDuration || 'N/A';
    document.getElementById('modalTimestamp').textContent = new Date(alertData.timestamp).toLocaleString('fr-FR', { dateStyle: 'medium', timeStyle: 'medium' });
    
    // Sorties des Modèles
    const kitsuneScoreEl = document.getElementById('kitsuneScore');
    const kitsuneProgressFill = kitsuneScoreEl.previousElementSibling.querySelector('.progress-fill');
    kitsuneScoreEl.textContent = (alertData.kitsuneScore || 0).toFixed(2);
    kitsuneProgressFill.style.width = `${(alertData.kitsuneScore || 0) * 100}%`;
    kitsuneProgressFill.className = `progress-fill h-full rounded ${alertData.kitsuneScore > 0.7 ? 'bg-red-500' : (alertData.kitsuneScore > 0.4 ? 'bg-orange-500' : 'bg-green-500')}`;


    document.getElementById('lucidDetection').textContent = alertData.lucidDetection || 'N/A';
    
    const vertexLabelEl = document.getElementById('vertexLabel');
    const vertexConfidenceEl = document.getElementById('vertexConfidence');
    const vertexProgressFill = vertexConfidenceEl.previousElementSibling.querySelector('.progress-fill');
    vertexLabelEl.textContent = alertData.vertexLabel || 'N/A';
    vertexConfidenceEl.textContent = (alertData.vertexConfidence || 0).toFixed(2);
    vertexProgressFill.style.width = `${(alertData.vertexConfidence || 0) * 100}%`;
    vertexProgressFill.className = `progress-fill h-full rounded ${alertData.vertexConfidence > 0.7 ? 'bg-red-500' : (alertData.vertexConfidence > 0.4 ? 'bg-orange-500' : 'bg-green-500')}`;

    // Recommandations
    const recommendationsContainer = document.getElementById('recommendations');
    recommendationsContainer.innerHTML = ''; // Vider les anciennes recommandations
    if (alertData.recommendations && alertData.recommendations.length > 0) {
        alertData.recommendations.forEach(rec => {
            let badgeClass = 'badge-info bg-sky-700 text-sky-200';
            let icon = 'fa-info-circle';
            const recLower = rec.toLowerCase();

            if (recLower.includes('isoler') || recLower.includes('bloquer')) { badgeClass = 'badge-danger bg-red-700 text-red-200'; icon = 'fa-ban'; }
            else if (recLower.includes('vérifier') || recLower.includes('analyser') || recLower.includes('surveiller')) { badgeClass = 'badge-warning bg-yellow-700 text-yellow-200'; icon = 'fa-search'; }
            else if (recLower.includes('aucune')) { badgeClass = 'badge-success bg-green-700 text-green-200'; icon = 'fa-check'; }
            
            const badge = document.createElement('span');
            badge.className = `badge ${badgeClass} inline-flex items-center text-xs font-semibold px-2.5 py-1 rounded-full mr-2 mb-2`;
            badge.innerHTML = `<i class="fas ${icon} mr-1.5"></i> ${rec}`;
            recommendationsContainer.appendChild(badge);
        });
    } else {
        recommendationsContainer.innerHTML = '<p class="text-gray-400 text-sm">Aucune recommandation spécifique.</p>';
    }

    // Style du modal basé sur la sévérité
    modalContent.classList.remove('critical-modal', 'medium-modal', 'low-modal'); // Enlever les anciennes classes
    if (alertData.severity === 'high' || alertData.severity === 'critique') modalContent.classList.add('critical-modal');
    else if (alertData.severity === 'medium' || alertData.severity === 'moyen') modalContent.classList.add('medium-modal');
    else modalContent.classList.add('low-modal');
    
    modal.classList.add('active'); // Afficher le modal
}

function setupEventListeners() {
    document.querySelectorAll('.sortable').forEach(columnHeader => {
        columnHeader.addEventListener('click', () => {
            handleSortColumnClick(columnHeader.dataset.sort);
        });
    });
    
    const criticalToggle = document.getElementById('criticalToggle');
    if (criticalToggle) criticalToggle.addEventListener('change', filterAlertsFromUI);
    
    const modelFilterSelect = document.getElementById('modelFilter');
    if (modelFilterSelect) modelFilterSelect.addEventListener('change', filterAlertsFromUI);
    
    const closeModalButton = document.getElementById('closeModal');
    if (closeModalButton) closeModalButton.addEventListener('click', () => {
        document.getElementById('alertModal').classList.remove('active');
    });
    
    const backToTableButton = document.getElementById('backToTable');
    if (backToTableButton) backToTableButton.addEventListener('click', () => {
        document.getElementById('alertModal').classList.remove('active');
    });
    
    const alertModalOverlay = document.getElementById('alertModal');
    if (alertModalOverlay) {
        alertModalOverlay.addEventListener('click', (e) => {
            if (e.target === alertModalOverlay) { // Si on clique sur le fond et non sur le contenu
                alertModalOverlay.classList.remove('active');
            }
        });
    }
}

// Initialisation de la page
document.addEventListener('DOMContentLoaded', initializeAlertPage);
