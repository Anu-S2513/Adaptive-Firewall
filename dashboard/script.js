const API_URL = "http://127.0.0.1:8000";

let latestPredictions = [];
let latestFlows = [];


/* =========================================================
   HELPERS
========================================================= */

function safeNumber(value) {
    const number = parseFloat(value);
    return Number.isFinite(number) ? number : 0;
}


function formatTime(timestamp) {

    if (!timestamp) {
        return "--";
    }

    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) {
        return timestamp;
    }

    return date.toLocaleTimeString();
}


function escapeHTML(value) {

    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


function formatBytes(bytes) {

    bytes = safeNumber(bytes);

    if (bytes < 1024) {
        return `${bytes.toFixed(0)} B`;
    }

    if (bytes < 1024 * 1024) {
        return `${(bytes / 1024).toFixed(1)} KB`;
    }

    if (bytes < 1024 * 1024 * 1024) {
        return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    }

    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}


/* =========================================================
   UPDATE TRAFFIC DONUT
========================================================= */

function updateTrafficDonut(total, normal, attacks) {

    const donut = document.getElementById("trafficDonut");

    if (!donut) {
        return;
    }

    const totalSafe = Math.max(total, 1);

    const normalAngle =
        (normal / totalSafe) * 360;

    donut.style.background = `
        conic-gradient(
            #20e39a 0deg ${normalAngle}deg,
            #ff4d5f ${normalAngle}deg 360deg
        )
    `;

    const donutTotal =
        document.getElementById("donutTotal");

    if (donutTotal) {
        donutTotal.textContent = total;
    }

    const normalPercent =
        document.getElementById("normalPercent");

    if (normalPercent) {
        normalPercent.textContent =
            `${((normal / totalSafe) * 100).toFixed(1)}%`;
    }

    const attackPercent =
        document.getElementById("attackPercent");

    if (attackPercent) {
        attackPercent.textContent =
            `${((attacks / totalSafe) * 100).toFixed(1)}%`;
    }
}


/* =========================================================
   UPDATE FIREWALL DONUT
========================================================= */

function updateFirewallDonut(
    allowed,
    monitored,
    blocked
) {

    const donut =
        document.getElementById("firewallDonut");

    if (!donut) {
        return;
    }

    const total =
        allowed +
        monitored +
        blocked;

    const totalSafe =
        Math.max(total, 1);

    const allowedAngle =
        (allowed / totalSafe) * 360;

    const monitoredAngle =
        (monitored / totalSafe) * 360;

    const monitoredEnd =
        allowedAngle +
        monitoredAngle;

    donut.style.background = `
        conic-gradient(
            #20e39a 0deg ${allowedAngle}deg,
            #ffb52e ${allowedAngle}deg ${monitoredEnd}deg,
            #ff4d5f ${monitoredEnd}deg 360deg
        )
    `;

    const firewallTotal =
        document.getElementById("firewallTotal");

    if (firewallTotal) {
        firewallTotal.textContent = total;
    }

    const allowedPercent =
        document.getElementById("allowedPercent");

    if (allowedPercent) {
        allowedPercent.textContent =
            `${((allowed / totalSafe) * 100).toFixed(1)}%`;
    }

    const monitoredPercent =
        document.getElementById("monitoredPercent");

    if (monitoredPercent) {
        monitoredPercent.textContent =
            `${((monitored / totalSafe) * 100).toFixed(1)}%`;
    }

    const blockedPercent =
        document.getElementById("blockedPercent");

    if (blockedPercent) {
        blockedPercent.textContent =
            `${((blocked / totalSafe) * 100).toFixed(1)}%`;
    }
}


/* =========================================================
   RISK CHART
========================================================= */

function updateRiskChart(predictions) {

    const container =
        document.getElementById("riskChart");

    if (!container) {
        return;
    }

    if (!predictions || predictions.length === 0) {

        container.innerHTML = `
            <div class="chart-empty">
                Waiting for prediction data...
            </div>
        `;

        return;
    }

    const values = predictions
        .slice()
        .reverse()
        .slice(-30)
        .map(item =>
            Math.max(
                0,
                Math.min(
                    1,
                    safeNumber(
                        item.attack_probability
                    )
                )
            )
        );

    if (values.length === 1) {
        values.push(values[0]);
    }

    const width = 700;
    const height = 150;

    const points = values.map(
        (value, index) => {

            const x =
                (
                    index /
                    Math.max(
                        values.length - 1,
                        1
                    )
                ) * width;

            const y =
                height -
                (value * (height - 15)) -
                5;

            return `${x},${y}`;
        }
    ).join(" ");

    const areaPoints =
        `0,${height} ${points} ${width},${height}`;

    container.innerHTML = `
        <svg
            class="risk-svg"
            viewBox="0 0 ${width} ${height}"
            preserveAspectRatio="none"
        >

            <defs>

                <linearGradient
                    id="riskFill"
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="1"
                >

                    <stop
                        offset="0%"
                        stop-color="#a855f7"
                        stop-opacity="0.35"
                    />

                    <stop
                        offset="100%"
                        stop-color="#a855f7"
                        stop-opacity="0"
                    />

                </linearGradient>

            </defs>

            <polygon
                points="${areaPoints}"
                fill="url(#riskFill)"
            />

            <polyline
                points="${points}"
                fill="none"
                stroke="#a855f7"
                stroke-width="3"
                stroke-linecap="round"
                stroke-linejoin="round"
            />

        </svg>
    `;
}


/* =========================================================
   LOAD STATISTICS
========================================================= */

async function loadStats() {

    try {

        const response = await fetch(
            `${API_URL}/api/stats`,
            {
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(
                "Failed to load statistics"
            );
        }

        const data =
            await response.json();


        /* KPI */

        const totalPredictions =
            document.getElementById(
                "totalPredictions"
            );

        if (totalPredictions) {
            totalPredictions.textContent =
                data.total_predictions ?? 0;
        }


        const normalPredictions =
            document.getElementById(
                "normalPredictions"
            );

        if (normalPredictions) {
            normalPredictions.textContent =
                data.normal_predictions ?? 0;
        }


        const attackPredictions =
            document.getElementById(
                "attackPredictions"
            );

        if (attackPredictions) {
            attackPredictions.textContent =
                data.attack_predictions ?? 0;
        }


        const averageRisk =
            document.getElementById(
                "averageRisk"
            );

        if (averageRisk) {
            averageRisk.textContent =
                `${(
                    safeNumber(
                        data.average_attack_probability
                    ) * 100
                ).toFixed(2)}%`;
        }


        const allowedCount =
            document.getElementById(
                "allowedCount"
            );

        if (allowedCount) {
            allowedCount.textContent =
                data.allowed ?? 0;
        }


        const monitoredCount =
            document.getElementById(
                "monitoredCount"
            );

        if (monitoredCount) {
            monitoredCount.textContent =
                data.monitored ?? 0;
        }


        const blockedCount =
            document.getElementById(
                "blockedCount"
            );

        if (blockedCount) {
            blockedCount.textContent =
                data.blocked ?? 0;
        }


        /* STATUS */

        const active =
            data.system_status === "active";


        const systemStatus =
            document.getElementById(
                "systemStatus"
            );

        if (systemStatus) {
            systemStatus.textContent =
                active
                    ? "RUNNING"
                    : "OFFLINE";
        }


        const apiStatus =
            document.getElementById(
                "apiStatus"
            );

        if (apiStatus) {
            apiStatus.textContent =
                active
                    ? "Connected"
                    : "Offline";
        }


        const captureStatus =
            document.getElementById(
                "captureStatus"
            );

        if (captureStatus) {
            captureStatus.textContent =
                active
                    ? "Monitoring"
                    : "Stopped";
        }


        /* DONUTS */

        updateTrafficDonut(
            safeNumber(
                data.total_predictions
            ),
            safeNumber(
                data.normal_predictions
            ),
            safeNumber(
                data.attack_predictions
            )
        );


        updateFirewallDonut(
            safeNumber(data.allowed),
            safeNumber(data.monitored),
            safeNumber(data.blocked)
        );

    } catch (error) {

        console.error(
            "Statistics error:",
            error
        );

        const systemStatus =
            document.getElementById(
                "systemStatus"
            );

        if (systemStatus) {
            systemStatus.textContent =
                "OFFLINE";
        }

        const apiStatus =
            document.getElementById(
                "apiStatus"
            );

        if (apiStatus) {
            apiStatus.textContent =
                "Offline";
        }
    }
}


/* =========================================================
   LOAD PREDICTIONS
========================================================= */

async function loadPredictions() {

    try {

        const response = await fetch(
            `${API_URL}/api/predictions`,
            {
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(
                "Failed to load predictions"
            );
        }

        const data =
            await response.json();

        latestPredictions =
            data.predictions || [];


        updateRiskChart(
            latestPredictions
        );


        /* ALERT COUNT */

        const attacks =
            latestPredictions.filter(
                item =>
                    item.prediction === "ATTACK"
            );


        const navAlertCount =
            document.getElementById(
                "navAlertCount"
            );

        if (navAlertCount) {
            navAlertCount.textContent =
                attacks.length;
        }


        const alertBadge =
            document.getElementById(
                "alertBadge"
            );

        if (alertBadge) {
            alertBadge.textContent =
                attacks.length;
        }


        updateAlerts(attacks);

    } catch (error) {

        console.error(
            "Prediction error:",
            error
        );
    }
}


/* =========================================================
   LOAD BEHAVIORAL FLOWS
========================================================= */

async function loadFlows() {

    try {

        const response = await fetch(
            `${API_URL}/api/flows`,
            {
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(
                "Failed to load network flows"
            );
        }

        const data =
            await response.json();

        latestFlows =
            data.flows || [];


        updateFlowTable(
            latestFlows
        );


        const recordCount =
            document.getElementById(
                "recordCount"
            );

        if (recordCount) {
            recordCount.textContent =
                `${latestFlows.length} active flows`;
        }

    } catch (error) {

        console.error(
            "Flow error:",
            error
        );

        updateFlowTable([]);
    }
}


/* =========================================================
   UPDATE BEHAVIORAL FLOW TABLE
========================================================= */

function updateFlowTable(flows) {

    const table =
        document.getElementById(
            "predictionTable"
        );

    if (!table) {
        return;
    }


    if (!flows || flows.length === 0) {

        table.innerHTML = `
            <tr>
                <td
                    colspan="9"
                    class="empty"
                >
                    No active network flows
                </td>
            </tr>
        `;

        return;
    }


    table.innerHTML = "";


    /*
       Show the most recent 15 flows.
       Each row represents a FLOW,
       not an individual packet.
    */

    flows
        .slice()
        .reverse()
        .slice(0, 15)
        .forEach(flow => {

            const row =
                document.createElement("tr");


            /*
               Find the latest ML prediction
               belonging to this flow.
            */

            const matchingPrediction =
                latestPredictions.find(
                    prediction =>

                        prediction.source_ip ===
                            flow.source_ip &&

                        prediction.destination_ip ===
                            flow.destination_ip
                );


            let risk = 0;
            let prediction = "ANALYZING";
            let action = "WAITING";


            if (matchingPrediction) {

                risk =
                    safeNumber(
                        matchingPrediction.attack_probability
                    ) * 100;

                prediction =
                    String(
                        matchingPrediction.prediction ||
                        "ANALYZING"
                    ).toUpperCase();

                action =
                    String(
                        matchingPrediction.firewall_action ||
                        "WAITING"
                    ).toUpperCase();
            }


            const isAttack =
                prediction === "ATTACK";


            const actionClass =
                action === "BLOCK"
                    ? "action-block"
                    : action === "MONITOR"
                        ? "action-monitor"
                        : "action-allow";


            row.innerHTML = `

                <td>
                    ${escapeHTML(
                        flow.source_ip
                    )}
                </td>

                <td>
                    ${escapeHTML(
                        flow.destination_ip
                    )}
                </td>

                <td>
                    <span class="protocol">
                        ${escapeHTML(
                            flow.protocol
                        )}
                    </span>
                </td>

                <td>
                    ${safeNumber(
                        flow.total_packets
                    )}
                </td>

                <td>
                    ${formatBytes(
                        flow.total_bytes
                    )}
                </td>

                <td>
                    ${safeNumber(
                        flow.duration
                    )}s
                </td>

                <td>
                    ${risk.toFixed(2)}%
                </td>

                <td>
                    <span class="
                        badge
                        ${
                            isAttack
                                ? "badge-attack"
                                : "badge-normal"
                        }
                    ">
                        ${escapeHTML(
                            prediction
                        )}
                    </span>
                </td>

                <td>
                    <span class="
                        ${actionClass}
                    ">
                        ${escapeHTML(
                            action
                        )}
                    </span>
                </td>
            `;


            table.appendChild(row);

        });
}


/* =========================================================
   RECENT ALERTS
========================================================= */

function updateAlerts(attacks) {

    const container =
        document.getElementById(
            "recentAlerts"
        );


    if (!container) {
        return;
    }


    if (!attacks || attacks.length === 0) {

        container.innerHTML = `
            <div class="empty-alert">
                No attack alerts detected.
            </div>
        `;

        return;
    }


    container.innerHTML = "";


    attacks
        .slice(0, 5)
        .forEach(alert => {

            const risk =
                (
                    safeNumber(
                        alert.attack_probability
                    ) * 100
                ).toFixed(0);


            const item =
                document.createElement("div");

            item.className =
                "alert-item";


            item.innerHTML = `
                <strong>
                    🚨 Attack Detected
                </strong>

                <span>
                    ${
                        escapeHTML(
                            alert.source_ip
                        )
                    }
                    →
                    ${
                        escapeHTML(
                            alert.destination_ip
                        )
                    }

                    · Risk ${risk}%
                </span>
            `;


            container.appendChild(item);

        });
}


/* =========================================================
   DASHBOARD
========================================================= */

async function loadDashboard() {

    await Promise.all([
        loadStats(),
        loadPredictions(),
        loadFlows()
    ]);

}


/* =========================================================
   START DASHBOARD
========================================================= */

loadDashboard();


setInterval(
    loadDashboard,
    5000
);