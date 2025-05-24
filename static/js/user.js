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
