async function loadEvents()  {
 const response = await fetch("/api/events");
 const events = await response.json();

 updateStats(events);
 renderEvents(events);
}

function updateStats(events) {
    document.getElementById("total-events").textContent = events.length;

    const alertCount = events.filter(e => e.severity == "HIGH").length;
    document.getElementById("total-alerts").textContent = alertCount;

    if (events.length > 0) {
        const lastTime = new Date(events[0].timestamp);
        document.getElementById("last-scan").textContent = lastTime.toLocaleTimeString();
    } else{
        document.getElementById("last-scan").textContent = "none yet";
    }
}

function renderEvents(events) {
    const container = document.getElementById("events-list");
    container.innerHTML = "";

    if (events.length === 0) {
        container.innerHTML = "<p class='loading'>no events logged yet</p>";
        return;
    }

    for (const event of events) {
        const item = document.createElement("div");
        item.className = "event-item" + (event.severity === "HIGH" ? " high" : "")

        const time = new Date(event.timestamp).toLocaleDateString();
        const severityClass = event.severity === "HIGH" ? "severity-high" : "severity-info";

        item.innerHTML = `
            <div class="event-time">${time}</div>
            <div class="event-description">${event.description}</div>
            <span class="event-severity ${severityClass}">${event.severity}</span>
        `;

        container.appendChild(item);

    }
}

loadEvents();
setInterval(loadEvents, 5000);