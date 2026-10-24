const TONE = /^\s*\[tone:\s*([^\]\n]*)\]/i;

/** A persona reply as the worker speaks it: the leading [tone: …] tag becomes the style, markup goes. */
export function spokenReply(text: string, instruct?: string): { chunk: string; style?: string } {
  const tone = TONE.exec(text)?.[1].trim();
  const chunk = text
    .replace(TONE, '')
    .replace(/<[^>]*>/g, '')
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/\[[^\]]*\]/g, '')
    .replace(/^\s*(?:[-•]|\d+\.)\s+/gm, '')
    .replace(/[*_`#~>|]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  // The style goes into the TTS instruction, so only a few plain words get through.
  const style = tone && /^[a-z, ]{1,40}$/i.test(tone) ? tone : instruct;
  return { chunk, style };
}
