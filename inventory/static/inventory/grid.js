(() => {
    const grid = document.querySelector(".grid-scroll .grid");
    if (!grid) return;
    const heading = grid.tHead;
    let offset = 0;
    let scheduled = false;

    // Move the original two-row heading as a unit. Native viewport sticky is
    // trapped by the horizontal overflow ancestor; no duplicate table is needed.
    const update = () => {
        scheduled = false;
        const rect = heading.getBoundingClientRect();
        const originalTop = rect.top - offset;
        offset = Math.min(
            Math.max(0, -originalTop),
            Math.max(0, grid.getBoundingClientRect().bottom - originalTop - rect.height),
        );
        heading.style.setProperty("--grid-heading-offset", `${offset}px`);
    };
    const schedule = () => {
        if (!scheduled) {
            scheduled = true;
            requestAnimationFrame(update);
        }
    };
    window.addEventListener("scroll", schedule, {passive: true});
    window.addEventListener("resize", schedule);
    if ("ResizeObserver" in window) {
        const observer = new ResizeObserver(schedule);
        observer.observe(grid);
        observer.observe(heading);
    }
    schedule();
})();
