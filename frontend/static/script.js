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
    const progressIndicator = document.createElement('div');
    progressIndicator.className = 'progress-indicator';
    resultsSection.insertBefore(progressIndicator, resultsSection.firstChild);

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
        window.sessionId = socket.id; // Store session ID globally
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
        
        // Hide progress indicator
        progressIndicator.style.display = 'none';
        
        // Show completion toast
        showToast("Scan completed successfully!", "success");
        
        // Update results if available
        if (data.result) {
            updateResults(data.result);
        }
        
        // Handle error if present
        if (data.error) {
            showToast("Error: " + data.error, "error");
        }
    });

    // Update the scan_progress event handler
    socket.on('scan_progress', (data) => {
        console.log('Scan progress:', data);
        
        let displayProgress = data.progress;
        let message = data.message;
        
        // If it's passive scan, keep progress at 99%
        if (message.includes('Passive Scan')) {
            displayProgress = 99;
            message = `${message} (Overall Progress: 99%)`;
        } else if (data.progress === 100) {
            // Only show 100% when everything is complete
            displayProgress = 100;
        } else {
            // For spider scan, scale progress to 0-95%
            displayProgress = Math.min(95, Math.floor(data.progress * 0.95));
            message = `Spider Scan: ${message} (Overall Progress: ${displayProgress}%)`;
        }

        // Update progress indicator
        progressIndicator.innerHTML = `
            <div class="progress-bar">
                <div class="progress" style="width: ${displayProgress}%"></div>
            </div>
            <p class="progress-message">${message}</p>
            <p class="scan-phase">${data.phase || 'Scanning...'}</p>
        `;
        
        // Show toast only for major progress updates
        if (data.progress % 20 === 0 || message.includes('Completed') || message.includes('Starting')) {
            showToast(message, "info");
        }
        
        // Only show results section when truly complete
        if (displayProgress === 100) {
            resultsSection.classList.remove('hidden');
            resultsSection.classList.add('visible');
        }
    });

    socket.on('server_update', (data) => {
        console.log('Server update received:', data);
    });

    socket.io.on("error", (error) => {
        console.error('Transport error:', error);
    });

    // Make socket available globally (optional)
    window.socket = socket;

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
                body: JSON.stringify({ url, session_id: window.sessionId }) // Include session_id
            });

            const data = await response.json();

            if (response.ok) {
                showToast("Scan request submitted successfully!", "success");
                resultsSection.classList.remove('hidden');
                resultsSection.classList.add('visible');
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
    // Update vulnerability counters
    if (results.summary) {
        Object.entries(results.summary).forEach(([risk, count]) => {
            const counter = document.querySelector(`.stat-card.${risk.toLowerCase()} .count`);
            if (counter) animateCount(counter, count);
        });
    }

    // Filter and display only Low and Informational vulnerabilities
    if (results.vulnerabilities_by_type) {
        const vulnContainer = document.getElementById('vulnerabilityList');
        if (vulnContainer) {
            // Filter vulnerabilities
            const filteredVulns = results.vulnerabilities_by_type.filter(vuln => 
                ['Low', 'Informational'].includes(vuln.risk)
            );

            vulnContainer.innerHTML = filteredVulns
                .map(vuln => `
                    <div class="vulnerability-item ${vuln.risk.toLowerCase()}-risk">
                        <div class="vuln-header">
                            <span class="risk-badge ${vuln.risk.toLowerCase()}">${vuln.risk}</span>
                        </div>
                        <div class="vuln-details">
                            <div class="detail-row">
                                <div class="detail-label">Alert Tags</div>
                                <div class="detail-value">${vuln.alert_tags}</div>
                            </div>
                            <div class="detail-row">
                                <div class="detail-label">Parameter</div>
                                <div class="detail-value">${vuln.parameter || 'N/A'}</div>
                            </div>
                            <div class="detail-row">
                                <div class="detail-label">Evidence</div>
                                <div class="detail-value">${vuln.evidence || 'N/A'}</div>
                            </div>
                            <div class="detail-row">
                                <div class="detail-label">Alert Description</div>
                                <div class="detail-value">${vuln.description}</div>
                            </div>
                            <div class="detail-row">
                                <div class="detail-label">Solution</div>
                                <div class="detail-value">${vuln.solution}</div>
                            </div>
                        </div>
                    </div>
                `)
                .join('');
        }
    }
}

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

// Add CSS for progress indicator
const style = document.createElement('style');
style.textContent = `
    .progress-indicator {
        margin: 20px 0;
        padding: 15px;
        background: #f5f5f5;
        border-radius: 8px;
    }

    .progress-bar {
        height: 20px;
        background: #ddd;
        border-radius: 10px;
        overflow: hidden;
    }

    .progress {
        height: 100%;
        background: linear-gradient(to right, #2193b0, #6dd5ed);
        transition: width 0.3s ease;
    }

    .progress-message {
        margin-top: 10px;
        color: #666;
        font-size: 14px;
    }
`;

// Add some additional styling for the progress indicator
const additionalStyle = `
    .scan-phase {
        font-size: 12px;
        color: #888;
        margin-top: 5px;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    .progress {
        background: linear-gradient(to right, 
            #2193b0 0%, 
            #6dd5ed 50%, 
            #2193b0 100%);
        background-size: 200% auto;
        animation: gradient 2s linear infinite;
    }

    @keyframes gradient {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }
`;

// Add the new styles
style.textContent += additionalStyle;

document.head.appendChild(style);