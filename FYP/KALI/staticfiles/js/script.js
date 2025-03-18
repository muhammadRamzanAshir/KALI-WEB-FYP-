$(document).ready(function () {
    $('.navbar-toggler').click(function () {
        $(this).toggleClass('open');
    });

$('.navbar-toggler').click(function () {
        $('#navbarNav').toggleClass('show');
    });
});
function togglePasswordVisibility(id, icon) {
    var input = document.getElementById(id);
    if (input.type === "password") {
        input.type = "text";
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    } else {
        input.type = "password";
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    }
}
// for url validation