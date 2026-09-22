const API_URL = "http://127.0.0.1:8000";


async function loadStats() {

    try {

        const response = await fetch(
            `${API_URL}/api/stats`
        );

        if (!response.ok) {
            throw new Error("Failed to load statistics");
        }

        const data = await response.json();


        // General statistics
        document.getElementById(
            "totalPredictions"
        ).textContent = data.total_predictions;


        document.getElementById(
            "normalPredictions"
        ).textContent = data.normal_predictions;


        document.getElementById(
            "attackPredictions"
        ).textContent = data.attack_predictions;


        document.getElementById(
            "averageRisk"
        ).textContent =
            (data.average_attack_probability * 100)
            .toFixed(2) + "%";


        // Adaptive firewall statistics
        document.getElementById(
            "allowedCount"
        ).textContent = data.allowed;


        document.getElementById(
            "monitoredCount"
        ).textContent = data.monitored;


        document.getElementById(
            "blockedCount"
        ).textContent = data.blocked;


        // System status
        document.getElementById(
            "systemStatus"
        ).textContent =
            data.system_status === "active"
                ? "System Active"
                : "System Offline";


    } catch (error) {

        console.error(error);

        document.getElementById(
            "systemStatus"
        ).textContent = "Backend Offline";

    }

}


async function loadPredictions() {

    try {

        const response = await fetch(
            `${API_URL}/api/predictions`
        );

        if (!response.ok) {
            throw new Error("Failed to load predictions");
        }

        const data = await response.json();


        const table = document.getElementById(
            "predictionTable"
        );


        table.innerHTML = "";


        if (
            !data.predictions ||
            data.predictions.length === 0
        ) {

            table.innerHTML = `
                <tr>
                    <td colspan="7">
                        No predictions available
                    </td>
                </tr>
            `;

            return;
        }


        data.predictions.forEach(prediction => {

            const row =
                document.createElement("tr");


            // Prediction style
            const predictionClass =
                prediction.prediction === "ATTACK"
                    ? "attack"
                    : "normal";


            // Convert probability to percentage
            const risk =
                (
                    parseFloat(
                        prediction.attack_probability
                    ) * 100
                ).toFixed(2);


            row.innerHTML = `

                <td>
                    ${prediction.timestamp}
                </td>

                <td>
                    ${prediction.source_ip}
                    :${prediction.source_port}
                </td>

                <td>
                    ${prediction.destination_ip}
                    :${prediction.destination_port}
                </td>

                <td>
                    ${prediction.protocol}
                </td>

                <td>
                    <span class="${predictionClass}">
                        ${prediction.prediction}
                    </span>
                </td>

                <td>
                    ${risk}%
                </td>

                <td>
                    ${prediction.firewall_action || "N/A"}
                </td>

            `;


            table.appendChild(row);

        });


    } catch (error) {

        console.error(error);

        document.getElementById(
            "predictionTable"
        ).innerHTML = `

            <tr>

                <td colspan="7">
                    Unable to connect to SentinelAI backend
                </td>

            </tr>

        `;

    }

}


async function loadDashboard() {

    await loadStats();

    await loadPredictions();

}


/* Load dashboard immediately */

loadDashboard();


/* Refresh every 5 seconds */

setInterval(
    loadDashboard,
    5000
);