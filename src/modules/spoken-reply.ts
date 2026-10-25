const TONE = /^\s*(?:\[tone:\s*([^\]\n]*)\]|<tone>\s*([^<\n]*)\s*<\/tone>)/i;

/** A persona reply as the worker speaks it: the leading tone tag becomes the style, markup goes. */
export function spokenReply(text: string, instruct?: string): { chunk: string; style?: string } {
  const match = TONE.exec(text);
  const tone = (match?.[1] ?? match?.[2])?.trim();
  let chunk = text
    .replace(TONE, '')
    .replace(/<[^>]*>/g, '')
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/\[[^\]]*\]/g, '')
    .replace(/^\s*(?:[-•]|\d+\.)\s+/gm, '')
    .replace(/[*_`#~>|]/g, '');
  chunk = (/^([\s\S]+?)\s*\n+\s*\1$/.exec(chunk.trim())?.[1] ?? chunk).replace(/\s+/g, ' ').trim();
  // The style goes into the TTS instruction, so only a few plain words get through.
  const style = tone && /^[a-z, ]{1,40}$/i.test(tone) ? tone : instruct;
  return { chunk, style };
}
