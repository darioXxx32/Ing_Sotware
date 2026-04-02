document.addEventListener("DOMContentLoaded", () => {
    const timeElement = document.getElementById("loginClockTime");
    const dateElement = document.getElementById("loginClockDate");
    const timeZone = "America/Guayaquil";

    if (!timeElement || !dateElement) {
        return;
    }

    const timeFormatter = new Intl.DateTimeFormat("es-EC", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
        timeZone
    });

    const dateFormatter = new Intl.DateTimeFormat("es-EC", {
        weekday: "long",
        day: "2-digit",
        month: "long",
        year: "numeric",
        timeZone
    });

    function updateClock() {
        const now = new Date();
        timeElement.textContent = timeFormatter.format(now);
        dateElement.textContent = dateFormatter.format(now);
    }

    updateClock();
    window.setInterval(updateClock, 1000);
});
