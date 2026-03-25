/**
 * Particle Animation System
 * Creates an immersive, floating particle background with connections
 */
(function () {
    const canvas = document.getElementById('particles-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    let particles = [];
    let animationId;
    let mouse = { x: null, y: null, radius: 120 };

    const CONFIG = {
        particleCount: 60,
        maxSpeed: 0.3,
        particleSize: { min: 1, max: 3 },
        connectionDistance: 150,
        colors: [
            'rgba(0, 240, 255, 0.6)',     // Cyan
            'rgba(139, 92, 246, 0.5)',     // Purple
            'rgba(59, 130, 246, 0.4)',     // Blue
            'rgba(236, 72, 153, 0.3)',     // Pink
        ],
    };

    function resize() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }

    function createParticle() {
        return {
            x: Math.random() * canvas.width,
            y: Math.random() * canvas.height,
            vx: (Math.random() - 0.5) * CONFIG.maxSpeed,
            vy: (Math.random() - 0.5) * CONFIG.maxSpeed,
            size: CONFIG.particleSize.min + Math.random() * (CONFIG.particleSize.max - CONFIG.particleSize.min),
            color: CONFIG.colors[Math.floor(Math.random() * CONFIG.colors.length)],
            opacity: 0.3 + Math.random() * 0.5,
            pulseSpeed: 0.005 + Math.random() * 0.01,
            pulsePhase: Math.random() * Math.PI * 2,
        };
    }

    function init() {
        resize();
        particles = [];
        for (let i = 0; i < CONFIG.particleCount; i++) {
            particles.push(createParticle());
        }
    }

    function drawParticle(p, time) {
        const pulseFactor = 0.5 + 0.5 * Math.sin(time * p.pulseSpeed + p.pulsePhase);
        const currentOpacity = p.opacity * (0.5 + pulseFactor * 0.5);
        const currentSize = p.size * (0.8 + pulseFactor * 0.4);

        ctx.beginPath();
        ctx.arc(p.x, p.y, currentSize, 0, Math.PI * 2);
        ctx.fillStyle = p.color.replace(/[\d.]+\)$/, `${currentOpacity})`);
        ctx.fill();

        // Glow effect
        ctx.beginPath();
        ctx.arc(p.x, p.y, currentSize * 3, 0, Math.PI * 2);
        const gradient = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, currentSize * 3);
        gradient.addColorStop(0, p.color.replace(/[\d.]+\)$/, `${currentOpacity * 0.3})`));
        gradient.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.fillStyle = gradient;
        ctx.fill();
    }

    function drawConnections() {
        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const dx = particles[i].x - particles[j].x;
                const dy = particles[i].y - particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < CONFIG.connectionDistance) {
                    const opacity = (1 - dist / CONFIG.connectionDistance) * 0.15;
                    ctx.beginPath();
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.strokeStyle = `rgba(0, 240, 255, ${opacity})`;
                    ctx.lineWidth = 0.5;
                    ctx.stroke();
                }
            }
        }
    }

    function updateParticle(p) {
        // Mouse interaction
        if (mouse.x !== null) {
            const dx = p.x - mouse.x;
            const dy = p.y - mouse.y;
            const dist = Math.sqrt(dx * dx + dy * dy);
            if (dist < mouse.radius) {
                const force = (1 - dist / mouse.radius) * 0.02;
                p.vx += dx / dist * force;
                p.vy += dy / dist * force;
            }
        }

        p.x += p.vx;
        p.y += p.vy;

        // Dampen velocity
        p.vx *= 0.999;
        p.vy *= 0.999;

        // Wrap around edges
        if (p.x < -10) p.x = canvas.width + 10;
        if (p.x > canvas.width + 10) p.x = -10;
        if (p.y < -10) p.y = canvas.height + 10;
        if (p.y > canvas.height + 10) p.y = -10;
    }

    function animate(time) {
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        drawConnections();

        for (const p of particles) {
            updateParticle(p);
            drawParticle(p, time);
        }

        animationId = requestAnimationFrame(animate);
    }

    // Event listeners
    window.addEventListener('resize', () => {
        resize();
    });

    window.addEventListener('mousemove', (e) => {
        mouse.x = e.clientX;
        mouse.y = e.clientY;
    });

    window.addEventListener('mouseout', () => {
        mouse.x = null;
        mouse.y = null;
    });

    // Initialize
    init();
    animate(0);

    // ── Scroll-triggered fade-in ──
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px',
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    }, observerOptions);

    document.querySelectorAll('.feature-card, .result-card').forEach(el => {
        observer.observe(el);
    });

    // ── Animated Counter ──
    window.animateCounter = function (element, target, duration = 2000) {
        let start = 0;
        const startTime = performance.now();

        function update(currentTime) {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            // Ease out cubic
            const eased = 1 - Math.pow(1 - progress, 3);
            const current = Math.round(start + (target - start) * eased);
            element.textContent = current;
            if (progress < 1) {
                requestAnimationFrame(update);
            }
        }

        requestAnimationFrame(update);
    };
})();
