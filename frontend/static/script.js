// Load Backend URL (Update manually if using a remote server)
const BACKEND_URL = "http://127.0.0.1:5000";  // Change this if backend runs on a different machine

// Toast notification function
function showToast(message, type = 'info') {
    const backgroundColor = {
        success: 'linear-gradient(to right, #00b09b, #96c93d)',
        error: 'linear-gradient(to right, #ff5f6d, #ffc371)',
        info: 'linear-gradient(to right, #2193b0, #6dd5ed)',
        warning: 'linear-gradient(to right, #f7b733, #fc4a1a)'
    };

    Toastify({
        text: message,
        duration: 3000,
        close: true,
        gravity: "top",
        position: "right",
        backgroundColor: backgroundColor[type],
        stopOnFocus: true
    }).showToast();
}

// Modified frontend code for better Socket.IO connection

document.addEventListener('DOMContentLoaded', () => {
    // Configure Socket.IO with explicit options
    const socket = io(BACKEND_URL, {
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000,
        timeout: 60000,
        transports: ['websocket', 'polling'] // Try WebSocket first, fall back to polling
    });

    // Connection event handlers
    socket.on('connect', () => {
        console.log('Connected to WebSocket server with ID:', socket.id);
    });

    socket.on('disconnect', (reason) => {
        console.log('Disconnected from WebSocket server. Reason:', reason);
    });

    socket.on('connect_error', (error) => {
        console.error('Connection error:', error);
    });

    // Server event handlers
    socket.on('scan_completed', (data) => {
        console.log('Scan completed:', data);
        // Update UI with scan results
        if (data.result) {
            updateResults(data.result);
        }
    });

    socket.on('scan_progress', (data) => {
        console.log('Scan progress:', data);
        showToast(data.message, "info");
        // Update UI with scan progress
    });

    socket.on('server_update', (data) => {
        console.log('Server update received:', data);
    });

    socket.io.on("error", (error) => {
        console.error('Transport error:', error);
    });

    // Make socket available globally (optional)
    window.socket = socket;
});

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
        current += Number(target) / steps;
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
        low: document.querySelector('.stat-card.low .count'),
        informational: document.querySelector('.stat-card.informational .count')
    };

    animateCount(counters.high, results.summary["High"] || 0);
    animateCount(counters.medium, results.summary["Medium"] || 0);
    animateCount(counters.low, results.summary["Low"] || 0);
    animateCount(counters.informational, results.summary["Informational"] || 0);

    // Update low vulnerability list
    const lowRiskList = document.getElementById('lowRiskList');
    lowRiskList.innerHTML = results.vulnerabilities_by_type
    .filter(vuln => vuln.risk.toLowerCase() === 'low')
    .map(vuln => `
      <div class="vulnerability-item fade-in">
        <p>${vuln.description}</p>
        <p>Count: ${vuln.count}</p>
      </div>
    `)
    .join('');
}

// Handle scan request
scanForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = document.getElementById('targetUrl').value.trim();

    if (!url) {
        showToast("Please enter a valid URL.", "warning");
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
            showToast("Scan request submitted successfully!", "success");
            resultsSection.classList.remove('hidden');
            resultsSection.classList.add('visible');
            // updateResults(data);  // Update UI with scan results
        } else {
            showToast("Error: " + (data.error || "Failed to submit scan request"), "error");
        }
    } catch (error) {
        console.error('Error submitting scan request:', error);
        showToast("Error: Unable to connect to the server.", "error");
    } finally {
        scanButton.classList.remove('loading');
        scanButton.disabled = false;
    }
});

// New scan request handling (merged correctly)
scanForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = document.getElementById('targetUrl').value.trim();

    if (!url) {
        showToast("Please enter a valid URL.", "warning");
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
            showToast("Scan request submitted successfully!", "success");
            resultsSection.classList.remove('hidden');
            resultsSection.classList.add('visible');
            updateResults(data);  // Update UI with scan results
        } else {
            showToast("Error: " + (data.error || "Failed to submit scan request"), "error");
        }
    } catch (error) {
        console.error('Error submitting scan request:', error);
        showToast("Error: Unable to connect to the server.", "error");
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
        showToast("Please fill in all required fields.", "warning");
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
            showToast("Report request submitted successfully!", "success");
            reportModal.style.display = 'none';
            reportForm.reset();
        } else {
            showToast("Error: " + (data.error || "Failed to submit report request"), "error");
        }
    } catch (error) {
        console.error('Error submitting report request:', error);
        showToast("Error: Unable to connect to the server.", "error");
    }
});