import { sectionId } from "./answerSections";
import { smoothScrollElementIntoView } from "./smoothScroll";

function flashSection(el: HTMLElement) {
  el.classList.remove("answer-section-flash");
  void el.offsetWidth; // restart the animation if the section is clicked again quickly
  el.classList.add("answer-section-flash");
  window.setTimeout(() => el.classList.remove("answer-section-flash"), 900);
}

export function jumpToAnswerSection(messageId: string, label: string) {
  // Falls back to the message bubble itself when the response has no
  // bold-labeled <answer-section> for this category (e.g. a plain list
  // whose category was only inferred from context) - still lands somewhere
  // useful instead of a dead click.
  const el = document.getElementById(sectionId(messageId, label)) ?? document.getElementById(`message-${messageId}`);
  if (!el) return;

  const container = document.querySelector<HTMLElement>("main .overflow-y-auto");
  if (container) {
    smoothScrollElementIntoView(container, el, { duration: 1000, offset: 16 }).then(() => flashSection(el));
  } else {
    el.scrollIntoView({ behavior: "smooth", block: "start" });
    flashSection(el);
  }
}
