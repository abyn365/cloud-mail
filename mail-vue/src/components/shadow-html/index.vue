<template>
  <div class="content-box" ref="contentBox">
    <div ref="container" class="content-html"></div>
  </div>
</template>

<script setup>
import { ref, onMounted, watch } from 'vue'
<<<<<<< codex/review-code-for-security-vulnerabilities-mqoyk6
import { sanitizeCssDeclaration, sanitizeCssStylesheet, sanitizeHtml } from '@/utils/html-sanitize.js'
=======
import { sanitizeCssDeclaration, sanitizeHtml } from '@/utils/html-sanitize.js'
>>>>>>> main

const props = defineProps({
  html: {
    type: String,
    required: true
  }
})

const container = ref(null)
const contentBox = ref(null)
let shadowRoot = null

function updateContent() {
  if (!shadowRoot) return;

  // 1. 提取 <body> 的 style 属性（如果存在）
  const bodyStyleRegex = /<body[^>]*style="([^"]*)"[^>]*>/i;
  const bodyStyleMatch = props.html.match(bodyStyleRegex);
  const bodyStyle = bodyStyleMatch ? sanitizeCssDeclaration(bodyStyleMatch[1]) : '';
<<<<<<< codex/review-code-for-security-vulnerabilities-mqoyk6

  // 2. 提取 style 标签内容（兼容完整 HTML 邮件模板）
  const styleTagRegex = /<style[^>]*>([\s\S]*?)<\/style>/gi
  let styleMatch
  const safeStyleBlocks = []

  while ((styleMatch = styleTagRegex.exec(props.html)) !== null) {
    const styleContent = sanitizeCssStylesheet(styleMatch[1] || '')
    if (styleContent) {
      safeStyleBlocks.push(styleContent)
    }
  }

  // 3. 移除 body 标签（保留内容）
  const cleanedHtml = props.html.replace(/<\/?body[^>]*>/gi, '')
=======

  // 2. 移除 <body> 标签（保留内容）
  const cleanedHtml = props.html.replace(/<\/?body[^>]*>/gi, '');
>>>>>>> main
  const safeHtml = sanitizeHtml(cleanedHtml)

  // 4. 将 body 的 style 应用到 .shadow-content
  shadowRoot.innerHTML = `
    <style>
      :host {
        all: initial;
        width: 100%;
        height: 100%;
        font-family: -apple-system, Inter, BlinkMacSystemFont,
                    'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        font-size: 14px;
        line-height: 1.5;
        color: #13181D;
        word-break: break-word;
      }

      h1, h2, h3, h4 {
          font-size: 18px;
          font-weight: 700;
      }

      p {
        margin: 0;
      }

      a {
        text-decoration: none;
        color: #0E70DF;
      }

      .shadow-content {
        background: #FFFFFF;
        width: fit-content;
        height: fit-content;
        min-width: 100%;
        ${bodyStyle ? bodyStyle : ''} /* 注入 body 的 style */
      }

      img:not(table img) {
        max-width: 100%;
        height: auto !important;
      }

      ${safeStyleBlocks.join('\n')}

    </style>
    <div class="shadow-content">
      ${safeHtml}
    </div>
  `;
}

function autoScale() {
  if (!shadowRoot || !contentBox.value) return

  const parent = contentBox.value
  const shadowContent = shadowRoot.querySelector('.shadow-content')

  if (!shadowContent) return

  const parentWidth = parent.offsetWidth
  const childWidth = shadowContent.scrollWidth

  if (childWidth === 0) return

  const scale = parentWidth / childWidth

  const hostElement = shadowRoot.host
  hostElement.style.zoom = scale
}

onMounted(() => {
  shadowRoot = container.value.attachShadow({ mode: 'open' })
  updateContent()
  autoScale()
})

watch(() => props.html, () => {
  updateContent()
  autoScale()
})
</script>

<style scoped>
.content-box {
  width: 100%;
  height: 100%;
  overflow: hidden;
  font-family: -apple-system, Inter, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji";
}

.content-html {
  width: 100%;
  height: 100%;
}
</style>
