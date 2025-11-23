// State
let transactions = [];
let riskChart;

// DOM Elements
const form = document.getElementById('transactionForm');
const resultsTableBody = document.querySelector('#resultsTable tbody');
const totalScannedEl = document.getElementById('totalScanned');
const totalAnomaliesEl = document.getElementById('totalAnomalies');
const fraudRateEl = document.getElementById('fraudRate');
const generateBtn = document.getElementById('generateBtn');

// Initialize Chart
function initChart() {
    const ctx = document.getElementById('riskChart').getContext('2d');
    riskChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Risk Score',
                data: [],
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                borderWidth: 2,
                tension: 0.4,
                fill: true,
                pointBackgroundColor: [] // Dynamic colors based on risk
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    grid: {
                        color: 'rgba(148, 163, 184, 0.1)'
                    },
                    ticks: { color: '#94a3b8' }
                },
                x: {
                    display: false, // Hide x labels for clean look
                    grid: { display: false }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                }
            }
        }
    });
}

// Mock AI Detection Logic
function detectAnomaly(transaction) {
    let score = 0;
    const amount = parseFloat(transaction.amount);
    
    // Rule 1: High Amount
    if (amount > 5000) score += 60;
    else if (amount > 1000) score += 30;
    else if (amount > 500) score += 10;

    // Rule 2: Location Risk
    if (transaction.location === 'International') score += 40;
    else if (transaction.location === 'Domestic') score += 15;

    // Rule 3: Category Risk
    if (transaction.category === 'Electronics') score += 15;
    if (transaction.category === 'Travel') score += 10;

    // Rule 4: Random AI "Black Box" Factor (Simulation)
    const aiFactor = Math.floor(Math.random() * 20) - 5; // -5 to +15
    score += aiFactor;

    // Cap Score
    score = Math.min(100, Math.max(0, score));

    // Determine Status
    let status = 'Normal';
    if (score >= 80) status = 'Fraud';
    else if (score >= 50) status = 'Suspicious';

    return { score, status };
}

// Add Transaction
function addTransaction(transaction) {
    const analysis = detectAnomaly(transaction);
    const timestamp = new Date().toLocaleTimeString();
    
    const processedTransaction = {
        ...transaction,
        ...analysis,
        timestamp
    };

    transactions.unshift(processedTransaction); // Add to top
    if (transactions.length > 50) transactions.pop(); // Keep last 50

    updateUI(processedTransaction);
}

// Update UI
function updateUI(newTx) {
    // 1. Update Table
    const row = document.createElement('tr');
    row.innerHTML = `
        <td>${newTx.timestamp}</td>
        <td>${newTx.merchant}</td>
        <td>$${parseFloat(newTx.amount).toFixed(2)}</td>
        <td>${newTx.location}</td>
        <td>
            <div style="display: flex; align-items: center; gap: 0.5rem;">
                <div style="width: 100%; background: rgba(255,255,255,0.1); height: 6px; border-radius: 3px; max-width: 60px;">
                    <div style="width: ${newTx.score}%; background: ${getColor(newTx.score)}; height: 100%; border-radius: 3px;"></div>
                </div>
                <span>${newTx.score}</span>
            </div>
        </td>
        <td><span class="status-badge status-${newTx.status.toLowerCase()}">${newTx.status}</span></td>
    `;
    
    // Animate new row
    row.style.opacity = '0';
    row.style.transform = 'translateX(-20px)';
    resultsTableBody.insertBefore(row, resultsTableBody.firstChild);
    
    // Trigger reflow
    row.offsetHeight;
    
    row.style.transition = 'all 0.5s ease';
    row.style.opacity = '1';
    row.style.transform = 'translateX(0)';

    // 2. Update Stats
    const total = transactions.length; // Or cumulative counter
    // Let's use a cumulative counter for "Total Scanned"
    const currentTotal = parseInt(totalScannedEl.innerText) + 1;
    totalScannedEl.innerText = currentTotal;

    const anomalies = transactions.filter(t => t.status === 'Fraud' || t.status === 'Suspicious').length;
    // We should probably track cumulative anomalies too
    const isAnomaly = newTx.status !== 'Normal';
    const currentAnomalies = parseInt(totalAnomaliesEl.innerText) + (isAnomaly ? 1 : 0);
    totalAnomaliesEl.innerText = currentAnomalies;

    const rate = ((currentAnomalies / currentTotal) * 100).toFixed(1);
    fraudRateEl.innerText = `${rate}%`;

    // 3. Update Chart
    addDataToChart(riskChart, newTx.timestamp, newTx.score);
}

function getColor(score) {
    if (score >= 80) return '#ef4444';
    if (score >= 50) return '#f59e0b';
    return '#10b981';
}

function addDataToChart(chart, label, data) {
    chart.data.labels.push(label);
    chart.data.datasets.forEach((dataset) => {
        dataset.data.push(data);
        // Update point color
        dataset.pointBackgroundColor.push(getColor(data));
    });

    if (chart.data.labels.length > 20) {
        chart.data.labels.shift();
        chart.data.datasets.forEach((dataset) => {
            dataset.data.shift();
            dataset.pointBackgroundColor.shift();
        });
    }
    chart.update();
}

// Event Listeners
form.addEventListener('submit', (e) => {
    e.preventDefault();
    const amount = document.getElementById('amount').value;
    const merchant = document.getElementById('merchant').value;
    const location = document.getElementById('location').value;
    const category = document.getElementById('category').value;

    addTransaction({ amount, merchant, location, category });
    form.reset();
});

// Random Data Generator
const merchants = ['Amazon', 'Walmart', 'Uber', 'Starbucks', 'Apple Store', 'Target', 'Best Buy', 'Shell Station', 'Netflix'];
const locations = ['Local', 'Local', 'Local', 'Domestic', 'International'];
const categories = ['Retail', 'Dining', 'Services', 'Electronics', 'Travel'];

generateBtn.addEventListener('click', () => {
    // Generate 1 random transaction
    generateRandomTransaction();
});

function generateRandomTransaction() {
    const merchant = merchants[Math.floor(Math.random() * merchants.length)];
    const location = locations[Math.floor(Math.random() * locations.length)];
    const category = categories[Math.floor(Math.random() * categories.length)];
    
    // Generate amount with some outliers
    let amount = Math.random() * 200; // Most are small
    if (Math.random() > 0.8) amount += 500; // Occasional medium
    if (Math.random() > 0.95) amount += 4000; // Rare large
    
    addTransaction({
        amount: amount.toFixed(2),
        merchant,
        location,
        category
    });
}

// Auto-generate a few on load
window.addEventListener('load', () => {
    initChart();
    // Add some initial data
    for(let i=0; i<3; i++) {
        setTimeout(generateRandomTransaction, i * 500);
    }
});
