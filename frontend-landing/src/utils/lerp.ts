export const lerp = (a: number, b: number, t: number): number => a + (b - a) * t

export const clamp = (value: number, min: number, max: number): number =>
  Math.min(Math.max(value, min), max)

export const mapRange = (
  value: number,
  inMin: number,
  inMax: number,
  outMin: number,
  outMax: number
): number => {
  const t = clamp((value - inMin) / (inMax - inMin), 0, 1)
  return lerp(outMin, outMax, t)
}
