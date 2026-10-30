// One security rule condition value per line (the editor joins values with
// '\n'). A comma belongs to the value: regexes such as (\.\./|\.\.\\){2,} or
// \d{1,3} must survive an edit unchanged (live-waf D1).
export function conditionValues(text: string): string[] {
  return text.split('\n').map((value) => value.trim()).filter(Boolean)
}
