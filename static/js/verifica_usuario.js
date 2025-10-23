document.addEventListener('DOMContentLoaded', function () {
    const form = document.querySelector('form');
    const usernameInput = document.querySelector('input[name="username"]');
    const emailInput = document.querySelector('input[name="email"]');

    form.addEventListener('submit', function (e) {
        e.preventDefault();

        const formData = new FormData();
        formData.append('username', usernameInput.value);
        formData.append('email', emailInput.value);

        fetch('/verificar_usuario_email', {
            method: 'POST',
            body: formData
        })
        .then(response => response.text())
        .then(data => {
            if (data === 'existe') {
                alert('Usuário ou email já cadastrados.');
            } else {
                form.submit();
            }
        })
        .catch(error => {
            console.error('Erro na verificação:', error);
            form.submit(); // em caso de erro, envia o formulário mesmo assim
        });
    });
});