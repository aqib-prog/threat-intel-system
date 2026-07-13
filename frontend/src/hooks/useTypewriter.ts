import { useEffect, useRef, useState } from "react";
import { useReducedMotion } from "./useReducedMotion";

export function useTypewriter(fullText: string, active: boolean, charsPerTick = 3) {
  const [displayed, setDisplayed] = useState(active ? "" : fullText);
  const reducedMotion = useReducedMotion();
  const indexRef = useRef(0);

  useEffect(() => {
    if (!active || reducedMotion) {
      setDisplayed(fullText);
      return;
    }

    indexRef.current = 0;
    setDisplayed("");
    const id = setInterval(() => {
      indexRef.current += charsPerTick;
      setDisplayed(fullText.slice(0, indexRef.current));
      if (indexRef.current >= fullText.length) {
        clearInterval(id);
      }
    }, 18);

    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fullText, active, reducedMotion]);

  const done = displayed.length >= fullText.length;
  return { displayed, done };
}
