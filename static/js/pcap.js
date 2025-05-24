// Drag and drop functionality
const dropzone = document.getElementById('dropzone');
        
['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, preventDefaults, false);
});

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, highlight, false);
});

['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, unhighlight, false);
});

function highlight() {
    dropzone.classList.add('active');
}

function unhighlight() {
    dropzone.classList.remove('active');
}

dropzone.addEventListener('drop', handleDrop, false);

function handleDrop(e) {
    const dt = e.dataTransfer;
    const files = dt.files;
    handleFiles(files);
}

function handleFiles(files) {
    alert(`${files.length} fichier(s) reçu(s)! En production, ces fichiers seraient envoyés au serveur.`);
    // In a real app, you would upload files to server here
}

// Back button functionality
//document.querySelector('.back-button').addEventListener('click', function() {
    //alert("Retour au tableau de bord");
    // In a real app, this would navigate back or close modal
//});

// Generate random sparklines (demo only)
document.querySelectorAll('.sparkline').forEach(sparkline => {
    const width = sparkline.offsetWidth;
    const height = sparkline.offsetHeight;
    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    sparkline.appendChild(canvas);
    
    const ctx = canvas.getContext('2d');
    const points = [];
    
    // Generate random points
    for (let i = 0; i < 20; i++) {
        points.push(Math.random() * height);
    }
    
    // Draw sparkline
    ctx.strokeStyle = '#00f7ff';
    ctx.lineWidth = 2;
    ctx.beginPath();
    
    const step = width / (points.length - 1);
    points.forEach((point, i) => {
        const x = i * step;
        const y = height - point;
        
        if (i === 0) {
            ctx.moveTo(x, y);
        } else {
            ctx.lineTo(x, y);
        }
    });
    
    ctx.stroke();
});