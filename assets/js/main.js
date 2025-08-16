// Custom Cursor (Desktop only)
const cursor = document.querySelector('.cursor');
const links = document.querySelectorAll('a, button, .service-card');

if (window.innerWidth > 768) {
    document.addEventListener('mousemove', (e) => {
        cursor.style.left = e.clientX + 'px';
        cursor.style.top = e.clientY + 'px';
    });

    links.forEach(link => {
        link.addEventListener('mouseenter', () => cursor.classList.add('active'));
        link.addEventListener('mouseleave', () => cursor.classList.remove('active'));
    });
}

// Mobile Menu Toggle
const mobileToggle = document.querySelector('.mobile-toggle');
const navLinks = document.querySelector('.nav-links');
const navLinksItems = document.querySelectorAll('.nav-links a');

mobileToggle.addEventListener('click', () => {
    navLinks.classList.toggle('active');
    const icon = mobileToggle.querySelector('i');

    if (navLinks.classList.contains('active')) {
        icon.classList.remove('fa-bars');
        icon.classList.add('fa-times');
        document.body.style.overflow = 'hidden';
    } else {
        icon.classList.remove('fa-times');
        icon.classList.add('fa-bars');
        document.body.style.overflow = 'auto';
    }
});

// Close mobile menu when clicking on a link
navLinksItems.forEach(link => {
    link.addEventListener('click', () => {
        navLinks.classList.remove('active');
        const icon = mobileToggle.querySelector('i');
        icon.classList.remove('fa-times');
        icon.classList.add('fa-bars');
        document.body.style.overflow = 'auto';
    });
});

// Close mobile menu when clicking outside
document.addEventListener('click', (e) => {
    if (!navLinks.contains(e.target) && !mobileToggle.contains(e.target)) {
        navLinks.classList.remove('active');
        const icon = mobileToggle.querySelector('i');
        icon.classList.remove('fa-times');
        icon.classList.add('fa-bars');
        document.body.style.overflow = 'auto';
    }
});

// Navbar Scroll Effect
window.addEventListener('scroll', () => {
    const navbar = document.querySelector('.navbar');
    const scrollProgress = document.querySelector('.scroll-progress');

    if (window.scrollY > 100) {
        navbar.classList.add('scrolled');
    } else {
        navbar.classList.remove('scrolled');
    }

    // Scroll Progress
    const scrollPercent = (window.scrollY / (document.documentElement.scrollHeight - window.innerHeight)) * 100;
    scrollProgress.style.width = scrollPercent + '%';
});

// Smooth Scrolling
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Intersection Observer for Animations
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.style.opacity = '1';
            entry.target.style.transform = 'translateY(0)';
        }
    });
}, observerOptions);

// Observe service cards
document.querySelectorAll('.service-card').forEach(card => {
    card.style.opacity = '0';
    card.style.transform = 'translateY(30px)';
    card.style.transition = 'all 0.6s ease';
    observer.observe(card);
});

// Counter Animation for Stats
const animateCounters = () => {
    const statNumbers = document.querySelectorAll('.stat-number');
    statNumbers.forEach(stat => {
        const text = stat.textContent;
        if (text.includes('+')) {
            const target = parseInt(text);
            let current = 0;
            const increment = target / 50;
            const timer = setInterval(() => {
                current += increment;
                if (current >= target) {
                    current = target;
                    clearInterval(timer);
                }
                stat.textContent = Math.floor(current) + '+';
            }, 30);
        } else if (text === '100%') {
            let current = 0;
            const timer = setInterval(() => {
                current += 2;
                if (current >= 100) {
                    current = 100;
                    clearInterval(timer);
                }
                stat.textContent = current + '%';
            }, 30);
        }
    });
};

// Trigger counter animation when stats section is visible
const statsObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            animateCounters();
            statsObserver.unobserve(entry.target);
        }
    });
});

const statsSection = document.querySelector('.stats');
if (statsSection) {
    statsObserver.observe(statsSection);
}

// Typing Effect for Hero
const typeWriter = (element, text, speed = 50) => {
    let i = 0;
    element.textContent = '';
    const timer = setInterval(() => {
        if (i < text.length) {
            element.textContent += text.charAt(i);
            i++;
        } else {
            clearInterval(timer);
        }
    }, speed);
};

// Initialize typing effect on load
window.addEventListener('load', () => {
    setTimeout(() => {
        const intro = document.querySelector('.hero-intro');
        if (intro) {
            typeWriter(intro, "Hi, we're TechEmir.", 80);
        }
    }, 1000);
});

// Parallax Effect for Tech Grid (Desktop only)
if (window.innerWidth > 1200) {
    window.addEventListener('scroll', () => {
        const techGrid = document.querySelector('.tech-grid');
        if (techGrid) {
            const scrolled = window.pageYOffset;
            const rate = scrolled * -0.5;
            techGrid.style.transform = `translateY(${rate}px)`;
        }
    });
}

// Form Enhancement
const form = document.querySelector('.contact-form');
const inputs = document.querySelectorAll('.form-input');

inputs.forEach(input => {
    input.addEventListener('focus', () => {
        input.style.borderColor = 'var(--accent)';
        input.style.boxShadow = '0 0 0 3px rgba(255, 51, 102, 0.1)';
    });

    input.addEventListener('blur', () => {
        if (!input.value) {
            input.style.borderColor = 'rgba(255, 255, 255, 0.2)';
            input.style.boxShadow = 'none';
        }
    });
});

form.addEventListener('submit', (e) => {
    const submitBtn = form.querySelector('.submit-button');
    submitBtn.textContent = 'Sending...';
    submitBtn.style.background = 'var(--gray)';
});

// reCAPTCHA Integration
let recaptchaLoaded = false;

function onRecaptchaSuccess(token) {
    document.getElementById('recaptchaResponse').value = token;
    document.getElementById('submitBtn').disabled = false;
    document.getElementById('submitBtn').style.background = 'var(--gradient-accent)';
    recaptchaLoaded = true;
}

// Form submission with reCAPTCHA verification
document.getElementById('contactForm').addEventListener('submit', function(e) {
    if (!recaptchaLoaded) {
        e.preventDefault();
        alert('Please complete the reCAPTCHA verification.');
        return false;
    }

    const submitBtn = document.getElementById('submitBtn');
    submitBtn.textContent = 'Sending...';
    submitBtn.disabled = true;
    submitBtn.style.background = 'var(--gray)';
});

// Reset reCAPTCHA if form validation fails
function resetRecaptcha() {
    if (typeof grecaptcha !== 'undefined') {
        grecaptcha.reset();
        document.getElementById('recaptchaResponse').value = '';
        document.getElementById('submitBtn').disabled = true;
        recaptchaLoaded = false;
    }
}

// Easter Egg - Konami Code
let konamiCode = [];
const konami = [38, 38, 40, 40, 37, 39, 37, 39, 66, 65];

document.addEventListener('keydown', (e) => {
    konamiCode.push(e.keyCode);
    if (konamiCode.length > konami.length) {
        konamiCode.shift();
    }
    if (konamiCode.toString() === konami.toString()) {
        document.body.style.background = 'var(--gradient-accent)';
        setTimeout(() => {
            document.body.style.background = 'var(--dark)';
        }, 2000);
        console.log('🚀 You found the easter egg! TechEmir appreciates curious minds.');
    }
});

// Responsive behavior adjustments
window.addEventListener('resize', () => {
    if (window.innerWidth > 968) {
        navLinks.classList.remove('active');
        const icon = mobileToggle.querySelector('i');
        icon.classList.remove('fa-times');
        icon.classList.add('fa-bars');
        document.body.style.overflow = 'auto';
    }
});

// Performance optimization - Reduce animations on low-end devices
if (navigator.hardwareConcurrency && navigator.hardwareConcurrency < 4) {
    document.documentElement.style.setProperty('--animation-duration', '0.2s');
}
