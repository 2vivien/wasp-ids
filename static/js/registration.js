document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("register-form");
  if (!form) return;

  const username = form.querySelector("input[name='username']");
  const email = form.querySelector("input[name='email']");
  const password = form.querySelector("input[name='password']");
  const confirmPassword = form.querySelector("input[name='confirm_password']");
  const role = form.querySelector("select[name='role']");
  const terms = form.querySelector("input[name='accepted_terms']");

  const showError = (input, message) => {
    input.classList.add("is-invalid");
    let error = input.nextElementSibling;
    if (!error || !error.classList.contains("invalid-feedback")) {
      error = document.createElement("div");
      error.className = "invalid-feedback";
      input.insertAdjacentElement("afterend", error);
    }
    error.textContent = message;
  };

  const clearError = (input) => {
    input.classList.remove("is-invalid");
    const error = input.nextElementSibling;
    if (error && error.classList.contains("invalid-feedback")) {
      error.remove();
    }
  };

  const shake = (element) => {
    element.classList.add("shake");
    setTimeout(() => element.classList.remove("shake"), 500);
  };

  form.addEventListener("submit", (e) => {
    e.preventDefault();

    let isValid = true;

    const usernameRegex = /^[a-zA-Z0-9]{3,16}$/;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;

    if (!usernameRegex.test(username.value)) {
      showError(username, "Nom d'utilisateur invalide (3-16 caractères alphanumériques).");
      isValid = false;
    } else {
      clearError(username);
    }

    if (!emailRegex.test(email.value)) {
      showError(email, "Adresse mail invalide.");
      isValid = false;
    } else {
      clearError(email);
    }

    if (!passwordRegex.test(password.value)) {
      showError(password, "Mot de passe trop faible (8+ caractères, maj, min, chiffre, spécial).");
      isValid = false;
    } else {
      clearError(password);
    }

    if (confirmPassword.value !== password.value) {
      showError(confirmPassword, "Les mots de passe ne correspondent pas.");
      isValid = false;
    } else {
      clearError(confirmPassword);
    }

    if (!role.value) {
      showError(role, "Veuillez sélectionner un rôle.");
      isValid = false;
    } else {
      clearError(role);
    }

    if (!terms.checked) {
      shake(terms.closest("label") || terms.parentNode);
      isValid = false;
    }

    if (isValid) {
      const formData = {
        username: username.value.trim(),
        email: email.value.trim(),
        password: password.value,
        confirm_password: confirmPassword.value,
        role: role.value,
        accepted_terms: terms.checked
      };

      fetch("/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData)
      })
      .then(response => response.json())
      .then(data => {
        if (data.message) {
          alert("✅ Inscription réussie !");
          window.location.href = "/login"; // Remplace par une URL dynamique si besoin
        } else {
          alert("❌ Erreur : " + (data.error || "Veuillez réessayer."));
        }
      })
      .catch(error => {
        console.error("Erreur :", error);
        alert("❌ Une erreur est survenue. Veuillez réessayer.");
      });
    }
  });
});
document.querySelectorAll('.toggle-password').forEach(button => {
  button.addEventListener('click', () => {
    const wrapper = button.closest('.password-wrapper');
    const input = wrapper.querySelector('.real-input');
    const visual = wrapper.querySelector('.password-visual');
    const value = input.dataset.original || input.value;

    if (input.getAttribute('type') === 'password') {
      // Passer en mode VISIBLE
      input.setAttribute('data-original', value);
      input.setAttribute('type', 'text');
      input.style.color = 'transparent';

      visual.innerHTML = '';

      [...value].forEach((char, idx) => {
        const span = document.createElement('span');
        span.textContent = char; // ✅ On met la vraie lettre ici !
        visual.appendChild(span);
      });

      revealPasswordWave(visual);

      button.innerHTML = '<i class="fas fa-eye-slash"></i>';

    } else {
      // Passer en mode CACHÉ avec wave inverse
      hidePasswordWave(visual, () => {
        input.setAttribute('type', 'password');
        input.style.color = '';
        visual.innerHTML = '';
        button.innerHTML = '<i class="fas fa-eye"></i>';
      });
    }
  });
});

function revealPasswordWave(visual) {
  const spans = visual.querySelectorAll('span');

  spans.forEach((span, idx) => {
    setTimeout(() => {
      span.classList.add('revealed');
    }, idx * 100);
  });
}

function hidePasswordWave(visual, onComplete) {
  const spans = visual.querySelectorAll('span');

  spans.forEach((span, idx) => {
    setTimeout(() => {
      span.classList.remove('revealed');
      span.classList.add('hiding');
      span.textContent = '•'; // On remet le point quand on cache

      if (idx === spans.length - 1 && typeof onComplete === 'function') {
        setTimeout(onComplete, 300); // On attend la fin de l'animation pour reset
      }
    }, idx * 100);
  });
}
