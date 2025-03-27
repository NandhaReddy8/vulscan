// Load Backend URL (Update manually if using a remote server)
const BACKEND_URL = "http://127.0.0.1:5000";  // Change this if backend runs on a different machine

// Initialize AOS (Animations)
AOS.init({
    duration: 800,
    once: true,
    offset: 100
});

// DOM Elements
const scanForm = document.getElementById('scanForm');
const scanButton = document.getElementById('scanButton');
const resultsSection = document.getElementById('results');
const scanTypes = document.querySelectorAll('.scan-type');
const requestFullReport = document.getElementById('requestFullReport');
const reportModal = document.getElementById('reportModal');
const closeModal = document.querySelector('.close');
const reportForm = document.getElementById('reportForm');

// Handle scan type selection
scanTypes.forEach(button => {
    button.addEventListener('click', () => {
        scanTypes.forEach(btn => btn.classList.remove('active'));
        button.classList.add('active');
    });
});

// Animate number counting
function animateCount(element, target) {
    const duration = 2000;
    const steps = 60;
    const stepDuration = duration / steps;
    let current = 0;
    
    const timer = setInterval(() => {
        current += target / steps;
        element.textContent = Math.round(current);
        
        if (current >= target) {
            element.textContent = target;
            clearInterval(timer);
        }
    }, stepDuration);
}

// Update results display
function updateResults(results) {
    // Update counters
    const counters = {
        high: document.querySelector('.stat-card.high .count'),
        medium: document.querySelector('.stat-card.medium .count'),
        low: document.querySelector('.stat-card.low .count')
    };

    animateCount(counters.high, results.high);
    animateCount(counters.medium, results.medium);
    animateCount(counters.low, results.low.length);

    // Update low vulnerability list
    const lowRiskList = document.getElementById('lowRiskList');
    lowRiskList.innerHTML = results.low.map(vuln => `
        <div class="vulnerability-item fade-in">
            <h4>${vuln.title}</h4>
            <p>${vuln.description}</p>
        </div>
    `).join('');
}

// Handle scan request
scanForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = document.getElementById('targetUrl').value.trim();

    if (!url) {
        alert("Please enter a valid URL.");
        return;
    }

    scanButton.classList.add('loading');
    scanButton.disabled = true;

    try {
        const response = await fetch(`${BACKEND_URL}/api/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });

        const data = await response.json();

        if (response.ok) {
            alert("Scan request submitted successfully!");
            resultsSection.classList.remove('hidden');
            resultsSection.classList.add('visible');
            updateResults(data);  // Update UI with scan results
        } else {
            alert("Error: " + (data.error || "Failed to submit scan request"));
        }
    } catch (error) {
        console.error('Error submitting scan request:', error);
        alert("Error: Unable to connect to the server.");
    } finally {
        scanButton.classList.remove('loading');
        scanButton.disabled = false;
    }
});

// Modal handling
requestFullReport.addEventListener('click', () => {
    reportModal.style.display = 'block';
});

closeModal.addEventListener('click', () => {
    reportModal.style.display = 'none';
});

window.addEventListener('click', (e) => {
    if (e.target === reportModal) {
        reportModal.style.display = 'none';
    }
});

// Handle report form submission
reportForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const formData = {
        name: document.getElementById('name').value.trim(),
        email: document.getElementById('email').value.trim(),
        organization: document.getElementById('organization').value.trim(),
        size: document.getElementById('size').value.trim(),
        purpose: document.getElementById('purpose').value.trim()
    };

    if (!formData.name || !formData.email || !formData.organization) {
        alert("Please fill in all required fields.");
        return;
    }

    try {
        const response = await fetch(`${BACKEND_URL}/api/report`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formData)
        });

        const data = await response.json();

        if (response.ok) {
            alert("Report request submitted successfully!");
            reportModal.style.display = 'none';
            reportForm.reset();
        } else {
            alert("Error: " + (data.error || "Failed to submit report request"));
        }
    } catch (error) {
        console.error('Error submitting report request:', error);
        alert("Error: Unable to connect to the server.");
    }
});
