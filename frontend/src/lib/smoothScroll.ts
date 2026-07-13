// Decelerates smoothly into the stop, the "glide" feel used for anchor
// scrolling on sites like apple.com - much gentler than the native
// scrollIntoView({behavior:"smooth"}), which is fast and roughly linear.
function easeOutQuint(t: number): number {
  return 1 - Math.pow(1 - t, 5);
}

interface SmoothScrollOptions {
  duration?: number;
  offset?: number;
}

export function smoothScrollElementIntoView(
  container: HTMLElement,
  target: HTMLElement,
  options: SmoothScrollOptions = {}
): Promise<void> {
  const { duration = 1000, offset = 16 } = options;
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const containerRect = container.getBoundingClientRect();
  const targetRect = target.getBoundingClientRect();
  const startY = container.scrollTop;
  const maxScroll = container.scrollHeight - container.clientHeight;
  const destY = Math.max(0, Math.min(maxScroll, startY + (targetRect.top - containerRect.top) - offset));

  if (reducedMotion) {
    container.scrollTop = destY;
    return Promise.resolve();
  }

  const distance = destY - startY;
  if (Math.abs(distance) < 1) return Promise.resolve();

  const startTime = performance.now();

  return new Promise((resolve) => {
    function step(now: number) {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      container.scrollTop = startY + distance * easeOutQuint(progress);
      if (progress < 1) {
        requestAnimationFrame(step);
      } else {
        resolve();
      }
    }
    requestAnimationFrame(step);
  });
}
