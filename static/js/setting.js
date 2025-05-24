tailwind.config = {
    theme: {
        extend: {
            colors: {
                cyber: {
                    primary: '#00f7ff',
                    secondary: '#ff00f7',
                    dark: '#0a0a1a',
                    darker: '#050510',
                    panel: 'rgba(15, 15, 35, 0.8)'
                }
            },
            animation: {
                'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                'glow': 'glow 2s ease-in-out infinite alternate',
                'glow-blue': 'glow-blue 2s ease-in-out infinite alternate',
                'glow-pink': 'glow-pink 2s ease-in-out infinite alternate',
            },
            keyframes: {
                glow: {
                    'from': { 'box-shadow': '0 0 5px #00f7ff' },
                    'to': { 'box-shadow': '0 0 20px #00f7ff' }
                },
                'glow-blue': {
                    'from': { 'box-shadow': '0 0 5px #00f7ff' },
                    'to': { 'box-shadow': '0 0 20px #00f7ff' }
                },
                'glow-pink': {
                    'from': { 'box-shadow': '0 0 5px #ff00f7' },
                    'to': { 'box-shadow': '0 0 20px #ff00f7' }
                }
            }
        }
    }
}

 // Tab switching
 const systemTab = document.getElementById('systemTab');
 const profileTab = document.getElementById('profileTab');
 const systemPanel = document.getElementById('systemPanel');
 const profilePanel = document.getElementById('profilePanel');

 systemTab.addEventListener('click', () => {
     systemPanel.classList.remove('hidden');
     profilePanel.classList.add('hidden');
     systemTab.classList.add('text-cyber-primary', 'bg-cyber-dark');
     systemTab.classList.remove('text-cyber-secondary');
     profileTab.classList.add('text-cyber-secondary');
     profileTab.classList.remove('text-cyber-primary', 'bg-cyber-dark');
 });

 profileTab.addEventListener('click', () => {
     profilePanel.classList.remove('hidden');
     systemPanel.classList.add('hidden');
     profileTab.classList.add('text-cyber-primary', 'bg-cyber-dark');
     profileTab.classList.remove('text-cyber-secondary');
     systemTab.classList.add('text-cyber-secondary');
     systemTab.classList.remove('text-cyber-primary', 'bg-cyber-dark');
 });

 // Threshold slider
 const thresholdSlider = document.querySelector('input[type="range"]');
 const thresholdValue = document.getElementById('thresholdValue');

 thresholdSlider.addEventListener('input', () => {
     const value = (thresholdSlider.value / 100).toFixed(2);
     thresholdValue.textContent = value;
 });

 // API key visibility toggle
 const apiKeyInput = document.getElementById('apiKeyInput');
 const toggleApiKey = document.getElementById('toggleApiKey');

 toggleApiKey.addEventListener('click', () => {
     if (apiKeyInput.type === 'password') {
         apiKeyInput.type = 'text';
         toggleApiKey.innerHTML = '<i class="fas fa-eye-slash"></i>';
     } else {
         apiKeyInput.type = 'password';
         toggleApiKey.innerHTML = '<i class="fas fa-eye"></i>';
     }
 });

 // Retrain button animation
 const retrainBtn = document.getElementById('retrainBtn');
 const retrainProgress = document.getElementById('retrainProgress');

 retrainBtn.addEventListener('click', () => {
     retrainBtn.disabled = true;
     retrainBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Entraînement en cours...';
     retrainProgress.classList.remove('hidden');
     
     // Simulate progress
     let progress = 0;
     const progressBar = retrainProgress.querySelector('div > div');
     const progressText = retrainProgress.querySelector('p');
     
     const interval = setInterval(() => {
         progress += Math.random() * 10;
         if (progress > 100) progress = 100;
         progressBar.style.width = `${progress}%`;
         
         if (progress < 30) {
             progressText.textContent = "Initialisation des données...";
         } else if (progress < 60) {
             progressText.textContent = "Entraînement du modèle...";
         } else if (progress < 90) {
             progressText.textContent = "Validation des résultats...";
         } else {
             progressText.textContent = "Finalisation...";
         }
         
         if (progress === 100) {
             clearInterval(interval);
             setTimeout(() => {
                 retrainProgress.classList.add('hidden');
                 retrainBtn.disabled = false;
                 retrainBtn.innerHTML = '<i class="fas fa-check mr-2"></i>Entraînement terminé';
                 
                 // Reset after 3 seconds
                 setTimeout(() => {
                     retrainBtn.innerHTML = '<i class="fas fa-sync-alt mr-2"></i>Réentraînement Vertex AI';
                     progressBar.style.width = '0%';
                 }, 3000);
             }, 1000);
         }
     }, 300);
 });

 // Email validation
 const emailInput = document.getElementById('emailInput');
 const emailValidation = document.getElementById('emailValidation');

 emailInput.addEventListener('input', () => {
     const email = emailInput.value;
     if (!email) {
         emailValidation.classList.add('hidden');
         return;
     }
     
     const isValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
     if (isValid) {
         emailValidation.textContent = "Email valide";
         emailValidation.classList.remove('hidden', 'text-red-500');
         emailValidation.classList.add('text-cyber-primary');
     } else {
         emailValidation.textContent = "Format d'email invalide";
         emailValidation.classList.remove('hidden', 'text-cyber-primary');
         emailValidation.classList.add('text-red-500');
     }
     checkFormValidity();
 });

 // Password strength
 const passwordInput = document.getElementById('passwordInput');
 const confirmPassword = document.getElementById('confirmPassword');
 const passwordStrength = document.getElementById('passwordStrength');
 const strengthText = document.getElementById('strengthText');
 const passwordMatch = document.getElementById('passwordMatch');
 const saveProfileBtn = document.getElementById('saveProfileBtn');

 passwordInput.addEventListener('input', () => {
     const password = passwordInput.value;
     let strength = 0;
     
     // Length check
     if (password.length >= 8) strength++;
     if (password.length >= 12) strength++;
     
     // Character variety
     if (/[A-Z]/.test(password)) strength++;
     if (/[0-9]/.test(password)) strength++;
     if (/[^A-Za-z0-9]/.test(password)) strength++;
     
     // Update UI
     if (password.length === 0) {
         passwordStrength.className = 'password-strength';
         strengthText.textContent = '';
     } else if (strength <= 2) {
         passwordStrength.className = 'password-strength weak';
         strengthText.textContent = 'Faible';
         strengthText.className = 'text-xs font-mono text-red-500';
     } else if (strength <= 4) {
         passwordStrength.className = 'password-strength medium';
         strengthText.textContent = 'Moyen';
         strengthText.className = 'text-xs font-mono text-yellow-500';
     } else {
         passwordStrength.className = 'password-strength strong';
         strengthText.textContent = 'Fort';
         strengthText.className = 'text-xs font-mono text-cyber-primary';
     }
     
     checkPasswordMatch();
     checkFormValidity();
 });

 // Password match check
 confirmPassword.addEventListener('input', checkPasswordMatch);

 function checkPasswordMatch() {
     const password = passwordInput.value;
     const confirm = confirmPassword.value;
     
     if (!password || !confirm) {
         passwordMatch.classList.add('hidden');
         return;
     }
     
     if (password === confirm) {
         passwordMatch.textContent = "Les mots de passe correspondent";
         passwordMatch.classList.remove('hidden', 'text-red-500');
         passwordMatch.classList.add('text-cyber-primary');
     } else {
         passwordMatch.textContent = "Les mots de passe ne correspondent pas";
         passwordMatch.classList.remove('hidden', 'text-cyber-primary');
         passwordMatch.classList.add('text-red-500');
     }
     
     checkFormValidity();
 }

 // Form validity check
 function checkFormValidity() {
     const email = emailInput.value;
     const password = passwordInput.value;
     const confirm = confirmPassword.value;
     
     const emailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
     const passwordsValid = password && password === confirm;
     
     if (emailValid && passwordsValid) {
         saveProfileBtn.disabled = false;
         saveProfileBtn.classList.remove('opacity-50', 'cursor-not-allowed');
     } else {
         saveProfileBtn.disabled = true;
         saveProfileBtn.classList.add('opacity-50', 'cursor-not-allowed');
     }
 }

 // Save profile button
 saveProfileBtn.addEventListener('click', () => {
     saveProfileBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Sauvegarde...';
     
     // Simulate save operation
     setTimeout(() => {
         saveProfileBtn.innerHTML = '<i class="fas fa-check mr-2"></i>Modifications enregistrées!';
         saveProfileBtn.classList.remove('border-cyber-secondary', 'text-cyber-secondary');
         saveProfileBtn.classList.add('border-cyber-primary', 'text-cyber-primary');
         
         // Reset after 3 seconds
         setTimeout(() => {
             saveProfileBtn.innerHTML = '<i class="fas fa-save mr-2"></i>Enregistrer les modifications';
             saveProfileBtn.classList.remove('border-cyber-primary', 'text-cyber-primary');
             saveProfileBtn.classList.add('border-cyber-secondary', 'text-cyber-secondary');
         }, 3000);
     }, 1500);
 });

 // Toggle switch animation
 const toggleSwitches = document.querySelectorAll('.toggle-checkbox');
 toggleSwitches.forEach(switchEl => {
     switchEl.addEventListener('change', function() {
         const dot = this.nextElementSibling.querySelector('.dot');
         if (this.checked) {
             dot.classList.remove('translate-x-0');
             dot.classList.add('translate-x-5');
         } else {
             dot.classList.remove('translate-x-5');
             dot.classList.add('translate-x-0');
         }
     });
 });
