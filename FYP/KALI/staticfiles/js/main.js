/*==================== SHOW NAVBAR ====================*/
const showMenu = (headerToggle, navbarId) =>{
    const toggleBtn = document.getElementById(headerToggle),
    nav = document.getElementById(navbarId)
    
    // Validate that variables exist
    if(headerToggle && navbarId){
        toggleBtn.addEventListener('click', ()=>{
            // We add the show-menu class to the div tag with the nav__menu class
            nav.classList.toggle('show-menu')
            // change icon
            toggleBtn.classList.toggle('bx-x')
        })
    }
}
showMenu('header-toggle','navbar')

/*==================== LINK ACTIVE ====================*/
const linkColor = document.querySelectorAll('.nav__link')

function colorLink(){
    linkColor.forEach(l => l.classList.remove('active'))
    this.classList.add('active')
}

linkColor.forEach(l => l.addEventListener('click', colorLink))
<script src="https://cdn.jsdelivr.net/npm/typed.js@2.0.12"></script>
<script>
    document.addEventListener('DOMContentLoaded', function(){
        var typed = new Typed('.auto-typing', {
            strings: ["Kali Web is an innovative platform designed to ignite students' interest in cybersecurity by providing hands-on experience and practical knowledge. In the dynamic field of cybersecurity, practical skills are essential. Many students struggle to get started due to the complexity of command-line tools and the steep learning curve associated with traditional methods."],
            typeSpeed: 50,
            backSpeed: 25,
            loop: false
        });
    });
</script>
