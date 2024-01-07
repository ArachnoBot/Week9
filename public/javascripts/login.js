document.getElementById("LoginBtn").addEventListener("click", login)

async function login() {
    const emailInput = document.getElementById("EmailInput").value
    const passwordInput = document.getElementById("PasswordInput").value

    const res = await fetch("/api/user/login", {
        method: "POST",
        headers: {
            "Content-Type":"application/json"
        },
        body: JSON.stringify({
           email: emailInput,
           password: passwordInput 
        })
    })
    const data = res.json()

    if (data.success) {
        localStorage.setItem("auth_token", data.token)
    }
    console.log(localStorage.getItem("auth_token"))

    fetch("/", {
        method: "GET",
        headers: {
          "Authorization": "Bearer " + localStorage.getItem("auth_token"),
        },
    })
    .then(response => response.text())
    .then(html => {
        document.body.innerHTML = html;
    })
}