document.addEventListener('DOMContentLoaded', function() {
  // Vérification des dépendances
  if (typeof THREE === 'undefined') {
    console.error('Three.js n\'est pas chargé');
    return;
  }

  // Effet de traînée du curseur
  const initCursorTrail = () => {
    const trail = [];
    const trailLength = 10;
    
    for (let i = 0; i < trailLength; i++) {
      const dot = document.createElement('div');
      dot.className = 'cursor-trail';
      dot.style.opacity = 1 - (i / trailLength);
      dot.style.transform = `scale(${1 - (i / (trailLength * 2))})`;
      document.body.appendChild(dot);
      trail.push({ element: dot, x: 0, y: 0 });
    }
    
    let posX = 0, posY = 0;
    let mouseX = 0, mouseY = 0;
    
    document.addEventListener('mousemove', (e) => {
      mouseX = e.clientX;
      mouseY = e.clientY;
    });
    
    const updateCursor = () => {
      posX += (mouseX - posX) / 10;
      posY += (mouseY - posY) / 10;
      
      trail.forEach((dot, i) => {
        const nextDot = i === 0 ? { x: posX, y: posY } : trail[i - 1];
        const x = nextDot.x - (nextDot.x - dot.x) * 0.3;
        const y = nextDot.y - (nextDot.y - dot.y) * 0.3;
        
        dot.element.style.left = `${x}px`;
        dot.element.style.top = `${y}px`;
        dot.x = x;
        dot.y = y;
      });
      
      requestAnimationFrame(updateCursor);
    };
    
    updateCursor();
  };

  // Effets d'inclinaison
  const initTiltEffects = () => {
    if (typeof VanillaTilt !== 'undefined') {
      VanillaTilt.init(document.querySelectorAll("[data-tilt]"), {
        max: 15,
        speed: 400,
        glare: true,
        "max-glare": 0.2,
      });
    }
  };

  // Défilement fluide
  const initSmoothScrolling = () => {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
      anchor.addEventListener('click', function(e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
          target.scrollIntoView({
            behavior: 'smooth'
          });
        }
      });
    });
  };

  // Scène de fond hexagonale
  const initBackgroundScene = () => {
    const container = document.getElementById('canvas-container');
    if (!container) return;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    const renderer = new THREE.WebGLRenderer({ 
      alpha: true, 
      antialias: true,
      powerPreference: "high-performance"
    });
    renderer.setSize(window.innerWidth, window.innerHeight);
    container.appendChild(renderer.domElement);

    // Grille hexagonale
    const hexGeometry = new THREE.CylinderGeometry(0.5, 0.5, 0.1, 6);
    const hexMaterial = new THREE.MeshBasicMaterial({ 
      color: 0xFFD700,
      transparent: true,
      opacity: 0.05,
      wireframe: true
    });

    const hexes = [];
    const gridSize = 15;
    
    for (let x = -gridSize; x <= gridSize; x++) {
      for (let y = -gridSize; y <= gridSize; y++) {
        const hex = new THREE.Mesh(hexGeometry, hexMaterial);
        hex.position.x = x * 1.1;
        hex.position.y = y * 1.3;
        hex.position.z = -10;
        if (Math.abs(x) % 2 === 1) hex.position.y += 0.65;
        scene.add(hex);
        hexes.push(hex);
      }
    }

    // Particules
    const particlesGeometry = new THREE.BufferGeometry();
    const particlesCount = 300;
    const posArray = new Float32Array(particlesCount * 3);
    
    for (let i = 0; i < particlesCount * 3; i++) {
      posArray[i] = (Math.random() - 0.5) * 30;
    }
    
    particlesGeometry.setAttribute('position', new THREE.BufferAttribute(posArray, 3));
    const particlesMaterial = new THREE.PointsMaterial({
      size: 0.03,
      color: 0x00FFFF,
      transparent: true,
      opacity: 0.6
    });
    
    const particlesMesh = new THREE.Points(particlesGeometry, particlesMaterial);
    scene.add(particlesMesh);
    
    camera.position.z = 5;
    
    const animate = () => {
      requestAnimationFrame(animate);
      hexes.forEach(hex => hex.rotation.z += 0.0005);
      particlesMesh.rotation.y += 0.0005;
      renderer.render(scene, camera);
    };
    
    animate();
    
    const onResize = () => {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
    };
    
    window.addEventListener('resize', onResize);
  };

  // Modèle 3D de guêpe - Version optimisée
  const initWaspModel = () => {
    const container = document.getElementById('wasp-viewer');
    if (!container || !THREE.OrbitControls) return;

    const scene = new THREE.Scene();
    scene.background = null;
    
    // Taille adaptative du conteneur
    const containerWidth = Math.min(500, window.innerWidth * 0.45);
    const containerHeight = Math.min(600, window.innerHeight * 0.7);
    
    const camera = new THREE.PerspectiveCamera(
      35, // Champ de vision plus réduit
      containerWidth / containerHeight,
      0.1,
      1000
    );
    camera.position.set(0, 0.2, 2.5); // Position ajustée
    
    const renderer = new THREE.WebGLRenderer({
      antialias: true,
      alpha: true,
      powerPreference: "high-performance"
    });
    renderer.setSize(containerWidth, containerHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    // Éclairage optimal
    const ambientLight = new THREE.AmbientLight(0xffffff, 1.8);
    scene.add(ambientLight);
    
    const directionalLight1 = new THREE.DirectionalLight(0xffffff, 1.2);
    directionalLight1.position.set(0.5, 1, 1);
    scene.add(directionalLight1);
    
    const directionalLight2 = new THREE.DirectionalLight(0xffffff, 0.8);
    directionalLight2.position.set(-0.5, -1, -0.5);
    scene.add(directionalLight2);

    // Contrôles
    const controls = new THREE.OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.05;
    controls.enableZoom = false;
    controls.autoRotate = true;
    controls.autoRotateSpeed = 1.0;
    controls.maxPolarAngle = Math.PI * 0.6; // Limite la rotation verticale
    controls.minPolarAngle = Math.PI * 0.4;

    // Chargement du modèle
    const loader = new THREE.GLTFLoader();
    const modelPath = window.MODEL_PATH || '/static/images/wasp3D.glb';
    
    loader.load(
      modelPath,
      (gltf) => {
        const model = gltf.scene;
        
        // Ajustement parfait de la taille et position
        model.scale.set(0.7, 0.7, 0.7); // Taille réduite
        model.position.set(0.1, -0.1, 0);

        model.rotation.y = Math.PI; // Rotation initiale
        
        // Ajustement des ombres si nécessaire
        model.traverse(child => {
          if (child.isMesh) {
            child.castShadow = true;
            child.receiveShadow = true;
          }
        });
        
        scene.add(model);
      },
      undefined,
      (error) => {
        console.error("Erreur de chargement:", error);
        container.innerHTML = `
          <div class="text-white text-center p-4">
            <p>Le modèle 3D n'a pas pu être chargé</p>
          </div>
        `;
      }
    );

    // Animation
    const animate = () => {
      requestAnimationFrame(animate);
      controls.update();
      renderer.render(scene, camera);
    };
    
    animate();

    // Redimensionnement responsive
    const onResize = () => {
      const newWidth = Math.min(500, window.innerWidth * 0.45);
      const newHeight = Math.min(600, window.innerHeight * 0.7);
      
      camera.aspect = newWidth / newHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(newWidth, newHeight);
    };
    
    window.addEventListener('resize', onResize);
  };

  // Initialisation
  try {
    initCursorTrail();
    initTiltEffects();
    initSmoothScrolling();
    initBackgroundScene();
    initWaspModel();
  } catch (error) {
    console.error('Erreur initialisation:', error);
  }
});
  // ... tout le code avant reste inchangé (cursor trail, VanillaTilt, etc.)
// Simple Three.js background for hero section
const container = document.getElementById('canvas-container');
const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
renderer.setSize(window.innerWidth, window.innerHeight);
container.appendChild(renderer.domElement);

// Create hexagon geometry and material
const hexGeometry = new THREE.CylinderGeometry(0.5, 0.5, 0.1, 6);
const hexMaterial = new THREE.MeshBasicMaterial({ 
    color: 0xFFD700,
    transparent: true,
    opacity: 0.05,
    wireframe: true
});

// Fullscreen hex grid
const hexes = [];
const hexRadius = 1;
const hexWidth = Math.sqrt(3) * hexRadius;
const hexHeight = 1.5 * hexRadius;

const screenWorldWidth = window.innerWidth / 50;
const screenWorldHeight = window.innerHeight / 50;

const cols = Math.ceil(screenWorldWidth / hexWidth) + 10;
const rows = Math.ceil(screenWorldHeight / hexHeight) + 10;

for (let col = -cols / 2; col <= cols / 2; col++) {
  for (let row = -rows / 2; row <= rows / 2; row++) {
    const hex = new THREE.Mesh(hexGeometry, hexMaterial);
    const x = col * hexWidth;
    const y = row * hexHeight + (col % 2 !== 0 ? hexHeight / 2 : 0);
    hex.position.set(x, y, -10);
    scene.add(hex);
    hexes.push(hex);
  }
}

// Add particles
const particlesGeometry = new THREE.BufferGeometry();
const particlesCount = 500;
const posArray = new Float32Array(particlesCount * 3);
for (let i = 0; i < particlesCount * 3; i++) {
  posArray[i] = (Math.random() - 0.5) * 50;
}
particlesGeometry.setAttribute('position', new THREE.BufferAttribute(posArray, 3));
const particlesMaterial = new THREE.PointsMaterial({
  size: 0.05,
  color: 0x00FFFF,
  transparent: true,
  opacity: 0.8
});
const particlesMesh = new THREE.Points(particlesGeometry, particlesMaterial);
scene.add(particlesMesh);

// Camera centered
camera.position.set(0, 0, 5);

// Animate
function animate() {
  requestAnimationFrame(animate);
  hexes.forEach(hex => {
    hex.rotation.z += 0.001;
  });
  particlesMesh.rotation.y += 0.001;
  renderer.render(scene, camera);
}
animate();

// Resize
window.addEventListener('resize', function() {
  camera.aspect = window.innerWidth / window.innerHeight;
  camera.updateProjectionMatrix();
  renderer.setSize(window.innerWidth, window.innerHeight);
});



