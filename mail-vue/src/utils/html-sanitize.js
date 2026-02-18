const URL_ATTRS = new Set(['src', 'href', 'xlink:href', 'action', 'formaction'])
const DROP_TAGS = new Set(['script', 'iframe', 'object', 'embed', 'meta', 'link', 'base'])

function isSafeUrl(value) {
  if (!value) return true
  const normalized = value.trim().toLowerCase()

  if (normalized.startsWith('javascript:')) return false
  if (normalized.startsWith('vbscript:')) return false
  if (normalized.startsWith('data:') && !normalized.startsWith('data:image/')) return false

  return true
}

function sanitizeInlineStyle(value) {
  if (!value) return ''

  const lowered = value.toLowerCase()
  if (lowered.includes('expression(') || lowered.includes('javascript:')) {
    return ''
  }

  return value
}

export function sanitizeHtml(input) {
  if (!input) return ''

  const parser = new DOMParser()
  const doc = parser.parseFromString(input, 'text/html')

  doc.querySelectorAll(Array.from(DROP_TAGS).join(',')).forEach(node => node.remove())

  doc.querySelectorAll('*').forEach((el) => {
    const attrs = Array.from(el.attributes)

    attrs.forEach((attr) => {
      const name = attr.name.toLowerCase()
      const value = attr.value

      if (name.startsWith('on')) {
        el.removeAttribute(attr.name)
        return
      }

      if (name === 'srcdoc') {
        el.removeAttribute(attr.name)
        return
      }

      if (name === 'style') {
        const sanitizedStyle = sanitizeInlineStyle(value)
        if (!sanitizedStyle) {
          el.removeAttribute(attr.name)
        } else {
          el.setAttribute(attr.name, sanitizedStyle)
        }
        return
      }

      if (URL_ATTRS.has(name) && !isSafeUrl(value)) {
        el.removeAttribute(attr.name)
      }
    })
  })

  return doc.body.innerHTML
}

export function sanitizeCssDeclaration(value) {
  return sanitizeInlineStyle(value)
}
