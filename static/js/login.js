document.addEventListener("DOMContentLoaded", () => {
    const loginForm = document.getElementById("loginForm");
    const loginMessage = document.getElementById("loginMessage");

    if (loginForm) {
        loginForm.addEventListener("submit", function(event) {
            event.preventDefault();

            const username = document.getElementById("username").value.trim();
            const password = document.getElementById("password").value.trim();

            if (!username || !password) {
                loginMessage.textContent = "Todos los campos son obligatorios.";
                return;
            }

            loginMessage.style.color = "green";
            loginMessage.textContent = "Formulario válido. Luego conectaremos esto con Flask y MySQL.";
        });
    }
});