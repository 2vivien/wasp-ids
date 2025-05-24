document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("login-form");
  if (!form) return;

  const usernameInput = form.querySelector("input[name='identifier']");
  const passwordInput = form.querySelector("input[name='password']");

  const showError = (input, message) => {
    let error = input.nextElementSibling;
    if (!error || !error.classList.contains("error-message")) {
      error = document.createElement("div");
      error.className = "error-message";
      error.style.color = "red";
      error.style.fontSize = "0.8rem";
      error.style.marginTop = "5px";
      input.insertAdjacentElement("afterend", error);
    }
    error.textContent = message;
    input.classList.add("is-invalid");
  };

  const clearError = (input) => {
    const error = input.nextElementSibling;
    if (error && error.classList.contains("error-message")) {
      error.remove();
    }
    input.classList.remove("is-invalid");
  };

  const isValidUsername = (username) => /^[a-zA-Z0-9._@+-]{3,30}$/.test(username);
  const isValidPassword = (password) => password.length >= 6;

  form.addEventListener("submit", (e) => {
    e.preventDefault();

    const username = usernameInput.value.trim();
    const password = passwordInput.value.trim();
    let valid = true;

    if (!isValidUsername(username)) {
      showError(usernameInput, "Nom d'utilisateur ou e-mail invalide.");
      valid = false;
    } else {
      clearError(usernameInput);
    }

    if (!isValidPassword(password)) {
      showError(passwordInput, "Mot de passe invalide (min 6 caractères).");
      valid = false;
    } else {
      clearError(passwordInput);
    }

    if (valid) {
      fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ identifier: username, password: password })
      })
      .then(response => response.json())
      .then(data => {
        if (data.message === "Connexion réussie") {
          window.location.href = data.redirect || "/dashboard"; // Remplace par `url_for()` si besoin
        } else {
          showError(usernameInput, data.error || "Identifiants incorrects.");
          showError(passwordInput, "");
        }
      })
      .catch(error => {
        console.error("Erreur lors de la requête :", error);
        showError(usernameInput, "Erreur serveur.");
      });
    }
  });
});
document.addEventListener('DOMContentLoaded', function() {
  const togglePassword = document.getElementById('toggle-password');
  const passwordField = document.getElementById('password-field');
  const eyeIcon = document.getElementById('eye-icon');
  const handIcon = document.getElementById('hand-icon');
  
  togglePassword.addEventListener('click', function(e) {
      e.preventDefault();
      
      // Basculer entre texte et mot de passe
      const type = passwordField.getAttribute('type') === 'password' ? 'text' : 'password';
      passwordField.setAttribute('type', type);
      
      // Activer/désactiver l'animation
      togglePassword.classList.toggle('active');
      
      // Changer l'icône de l'œil
      if (type === 'text') {
          eyeIcon.classList.remove('fa-eye-slash');
          eyeIcon.classList.add('fa-eye');
      } else {
          eyeIcon.classList.remove('fa-eye');
          eyeIcon.classList.add('fa-eye-slash');
      }
      
      // Animation supplémentaire au clic
      togglePassword.style.transform = 'translateY(-50%) scale(1.2)';
      setTimeout(() => {
          togglePassword.style.transform = 'translateY(-50%) scale(1)';
      }, 200);
  });
});
