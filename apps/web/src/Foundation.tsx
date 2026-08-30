const universalAreas = ["Overview", "Work", "Docs"] as const;

export function Foundation() {
  return (
    <main className="foundation" data-component="stead-web">
      <p className="eyebrow">Stead</p>
      <h1>Open work, in one place.</h1>
      <p>
        The Phase 1 shell begins with the universal Project vocabulary. Software
        capabilities will appear only when a Project enables them.
      </p>
      <nav aria-label="Project areas">
        {universalAreas.map((area) => (
          <a href={`#${area.toLowerCase()}`} key={area}>
            {area}
          </a>
        ))}
      </nav>
    </main>
  );
}
