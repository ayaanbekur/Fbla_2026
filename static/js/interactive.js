// Interactive Effects and Animations Script

/**
 * Initialize all interactive effects when page loads
 */
document.addEventListener('DOMContentLoaded', function() {
    initializeFormAnimations();
    initializeButtonEffects();
    initializeScrollAnimate();
    initializeTooltips();
    initializeCardHover();
    initializeInputFocus();
    initializeSectionAnimations();
});

/**
 * Add animations to form inputs
 */
function initializeFormAnimations() {
    const inputs = document.querySelectorAll('input, textarea, select');
    
    inputs.forEach(input => {
        // Add focus effect
        input.addEventListener('focus', function() {
            this.parentElement.classList.add('focused');
            this.style.transition = 'all 0.3s ease';
        });
        
        // Remove focus effect
        input.addEventListener('blur', function() {
            this.parentElement.classList.remove('focused');
        });
        
        // Add has-value class for styling
        input.addEventListener('input', function() {
            if (this.value) {
                this.classList.add('has-value');
            } else {
                this.classList.remove('has-value');
            }
        });
    });
}

/**
 * Add interactive button effects
 */
function initializeButtonEffects() {
    const buttons = document.querySelectorAll('button, .cta-button, a.button');
    
    buttons.forEach(button => {
        button.addEventListener('click', function(e) {
            // Add ripple effect
            const ripple = document.createElement('span');
            ripple.classList.add('ripple-effect');
            
            const rect = this.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height);
            const x = e.clientX - rect.left - size / 2;
            const y = e.clientY - rect.top - size / 2;
            
            ripple.style.width = ripple.style.height = size + 'px';
            ripple.style.left = x + 'px';
            ripple.style.top = y + 'px';
            
            this.appendChild(ripple);
            
            // Remove ripple after animation
            setTimeout(() => ripple.remove(), 600);
        });
        
        // Add hover effect
        button.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-3px)';
        });
        
        button.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
        });
    });
}

/**
 * Add scroll animation for elements coming into view
 */
function initializeScrollAnimate() {
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -100px 0px'
    };
    
    const observer = new IntersectionObserver(function(entries) {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('in-view');
                
                // Add staggered animations for child elements
                const children = entry.target.querySelectorAll('.form-section, .item-card, .claim-item');
                children.forEach((child, index) => {
                    child.style.animationDelay = (index * 0.1) + 's';
                    child.classList.add('slide-in-view');
                });
                
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);
    
    // Observe cards and sections
    document.querySelectorAll('.card-grid, .form-section, .item-card, .claim-container').forEach(el => {
        observer.observe(el);
    });
}

/**
 * Create and manage tooltips
 */
function initializeTooltips() {
    const tooltipElements = document.querySelectorAll('[data-tooltip]');
    
    tooltipElements.forEach(element => {
        element.addEventListener('mouseenter', function() {
            const tooltip = document.createElement('div');
            tooltip.className = 'tooltip show';
            tooltip.textContent = this.getAttribute('data-tooltip');
            tooltip.style.position = 'absolute';
            tooltip.style.backgroundColor = '#C8102E';
            tooltip.style.color = 'white';
            tooltip.style.padding = '8px 12px';
            tooltip.style.borderRadius = '4px';
            tooltip.style.fontSize = '12px';
            tooltip.style.zIndex = '1000';
            tooltip.style.whiteSpace = 'nowrap';
            
            document.body.appendChild(tooltip);
            
            const rect = this.getBoundingClientRect();
            tooltip.style.left = (rect.left + rect.width / 2 - tooltip.offsetWidth / 2) + 'px';
            tooltip.style.top = (rect.top - tooltip.offsetHeight - 8) + 'px';
            
            this.tooltipElement = tooltip;
        });
        
        element.addEventListener('mouseleave', function() {
            if (this.tooltipElement) {
                this.tooltipElement.remove();
                this.tooltipElement = null;
            }
        });
    });
}

/**
 * Add hover effects to cards
 */
function initializeCardHover() {
    const cards = document.querySelectorAll('.item-card, .card, .claim-item');
    
    cards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-8px) scale(1.02)';
            this.style.boxShadow = '0 20px 40px rgba(0, 0, 0, 0.15)';
            this.style.transition = 'all 0.3s ease';
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0) scale(1)';
            this.style.boxShadow = '';
        });
    });
}

/**
 * Add focus animations to input fields
 */
function initializeInputFocus() {
    const inputs = document.querySelectorAll('input, textarea');
    
    inputs.forEach(input => {
        input.addEventListener('focus', function() {
            const label = this.previousElementSibling;
            if (label && label.tagName === 'LABEL') {
                label.style.color = 'var(--accent)';
                label.style.transform = 'translateY(-5px) scale(0.95)';
                label.style.transition = 'all 0.3s ease';
            }
        });
        
        input.addEventListener('blur', function() {
            if (!this.value) {
                const label = this.previousElementSibling;
                if (label && label.tagName === 'LABEL') {
                    label.style.color = '';
                    label.style.transform = '';
                }
            }
        });
    });
}

/**
 * Stagger animations for form sections
 */
function initializeSectionAnimations() {
    const sections = document.querySelectorAll('.form-section, .existing-claims-section');
    
    sections.forEach((section, index) => {
        section.style.animationDelay = (index * 0.15) + 's';
    });
}

/**
 * Add ripple effect styles dynamically
 */
const style = document.createElement('style');
style.textContent = `
    .ripple-effect {
        position: absolute;
        border-radius: 50%;
        background: rgba(255, 255, 255, 0.5);
        transform: scale(0);
        animation: ripple-animation 0.6s ease-out;
        pointer-events: none;
    }
    
    @keyframes ripple-animation {
        to {
            transform: scale(4);
            opacity: 0;
        }
    }
    
    .item-card:hover {
        cursor: pointer;
    }
    
    .in-view {
        animation: slideInUp 0.6s ease forwards;
    }
    
    .slide-in-view {
        animation: slideInUp 0.5s ease forwards;
    }
    
    .form-group.focused {
        transform: translateY(-2px);
    }
    
    input.has-value:valid,
    textarea.has-value:valid {
        border-color: #27ae60;
    }
    
    /* Smooth page transitions */
    html {
        scroll-behavior: smooth;
    }
    
    /* Keep animations on page load */
    body.loaded .item-card {
        animation: slideInUp 0.5s ease forwards;
    }
`;
document.head.appendChild(style);

// Mark page as loaded
window.addEventListener('load', function() {
    document.body.classList.add('loaded');
});

/**
 * Create smooth scroll for navigation links
 */
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
        const href = this.getAttribute('href');
        if (href !== '#') {
            e.preventDefault();
            const target = document.querySelector(href);
            if (target) {
                target.scrollIntoView({ behavior: 'smooth' });
            }
        }
    });
});

/**
 * Add keyboard navigation effects
 */
document.addEventListener('keydown', function(e) {
    // Tab key for focus management
    if (e.key === 'Tab') {
        const focusedElement = document.activeElement;
        if (focusedElement && focusedElement.tagName === 'BUTTON') {
            focusedElement.style.outline = '3px solid #0A8754';
            focusedElement.style.outlineOffset = '2px';
        }
    }
});

document.addEventListener('keyup', function(e) {
    if (e.key === 'Tab') {
        const focusedElement = document.activeElement;
        if (focusedElement && focusedElement.tagName === 'BUTTON') {
            focusedElement.style.outline = '';
            focusedElement.style.outlineOffset = '';
        }
    }
});
