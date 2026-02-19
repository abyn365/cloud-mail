<template>
  <div :class="accountShow && hasPerm('account:query') ? 'main-box-show' : 'main-box-hide'">
    <div :class="accountShow && hasPerm('account:query') ? 'block-show' : 'block-hide'" @click="uiStore.accountShow = false"></div>
    <account  :class="accountShow && hasPerm('account:query') ? 'show' : 'hide'" />
    <router-view class="main-view" v-slot="{ Component,route }">
      <keep-alive :include="['email','all-email','send','sys-setting','star','user','role','analysis','reg-key','draft']">
        <component :is="Component" :key="route.name"/>
      </keep-alive>
    </router-view>
  </div>
</template>
<script setup>
import account from '@/layout/account/index.vue'
import {useUiStore} from "@/store/ui.js";
import {useSettingStore} from "@/store/setting.js";
import {useAccountStore} from "@/store/account.js";
import {emailLatest} from "@/request/email.js";
import {sleep} from "@/utils/time-utils.js";
import {computed, onBeforeUnmount, onMounted, watch} from "vue";
import { useRoute } from 'vue-router'
import { hasPerm } from "@/perm/perm.js"
import { sanitizeHtml } from '@/utils/html-sanitize.js'

const settingStore = useSettingStore()
const accountStore = useAccountStore()
const uiStore = useUiStore();
const route = useRoute()
let  innerWidth =  window.innerWidth

let elNotification = null

const accountShow = computed(() => {
  return uiStore.accountShow && settingStore.settings.manyEmail === 0
})

watch(() => uiStore.changeNotice, () => {

  const settings = settingStore.settings

  let data = {
    notice: settings.notice,
    noticeWidth: settings.noticeWidth,
    noticeTitle: settings.noticeTitle,
    noticeContent: settings.noticeContent,
    noticeType: settings.noticeType,
    noticeDuration: settings.noticeDuration,
    noticePosition: settings.noticePosition,
    noticeOffset: settings.noticeOffset
  }

  showNotice(data)
})

watch(() => uiStore.changePreview, () => {
  showNotice(uiStore.previewData)
})

function showNotice(data) {

  if (data.notice === 1) {
    return;
  }

  if (elNotification) {
    elNotification.close()
  }

  const safeNoticeWidth = Number(data.noticeWidth) || 360
  const safeNoticeContent = sanitizeHtml(data.noticeContent)

  const style = document.createElement('style');
  style.textContent = `
  .custom-notice.el-notification {
    --el-notification-width: min(${safeNoticeWidth}px,calc(100% - 30px)) !important;
  }
  `;

  document.head.appendChild(style);

  elNotification = ElNotification({
    title: data.noticeTitle,
    message: `<div style="width: 100%;height: 100%;">${safeNoticeContent}</div>`,
    type: data.noticeType === 'none' ? '' : data.noticeType,
    duration: data.noticeDuration,
    position: data.noticePosition,
    offset: data.noticeOffset,
    dangerouslyUseHTMLString: true,
    customClass: 'custom-notice'
  })
}


let latestNotifyEmailId = 0
let notifyLoopStarted = false

function canSendBrowserNotification() {
  return localStorage.getItem('browser-notify-opt-in') === '1' && ('Notification' in window) && Notification.permission === 'granted'
}

async function sendBrowserNotification(email) {
  if (!canSendBrowserNotification()) {
    return
  }

  const title = email.subject || 'New email received'
  const body = `${email.name || email.sendEmail || 'Unknown sender'}`
  const options = {
    body,
    icon: '/mail-pwa.png',
    badge: '/mail-pwa.png',
    tag: `mail-${email.emailId}`,
    data: { url: '/inbox' }
  }

  if ('serviceWorker' in navigator) {
    try {
      const registration = await navigator.serviceWorker.ready
      await registration.showNotification(title, options)
      return
    } catch (e) {
      console.error('Failed to show notification via service worker:', e)
    }
  }

  const notification = new Notification(title, options)
  notification.onclick = () => {
    window.focus()
  }
}

async function syncNotifyBaseline() {
  const accountId = accountStore.currentAccountId
  const allReceive = accountStore.currentAccount?.allReceive

  if (!accountId || allReceive === undefined || allReceive === null) {
    return
  }

  try {
    const list = await emailLatest(0, accountId, allReceive)
    if (list.length > 0) {
      latestNotifyEmailId = Math.max(...list.map(item => item.emailId || 0))
    }
  } catch (e) {
    console.error('Failed to sync notification baseline:', e)
  }
}

async function startGlobalNotifyLoop() {
  if (notifyLoopStarted) return
  notifyLoopStarted = true

  await syncNotifyBaseline()

  while (true) {
    await sleep(5000)

    if (!canSendBrowserNotification()) {
      continue
    }

    const accountId = accountStore.currentAccountId
    const allReceive = accountStore.currentAccount?.allReceive

    if (!accountId || allReceive === undefined || allReceive === null) {
      continue
    }

    try {
      const list = await emailLatest(latestNotifyEmailId, accountId, allReceive)
      if (list.length === 0) {
        continue
      }

      const sortedList = list.slice().sort((a, b) => a.emailId - b.emailId)

      for (const email of sortedList) {
        if (email.emailId > latestNotifyEmailId) {
          await sendBrowserNotification(email)
          latestNotifyEmailId = email.emailId
        }
      }
    } catch (e) {
      console.error('Failed to fetch latest email notifications:', e)
    }
  }
}

onMounted(() => {
  window.addEventListener('resize', handleResize)
  handleResize()
  startGlobalNotifyLoop()
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', handleResize)
})

const handleResize = () => {
  if (['content','email','send'].includes(route.meta.name)) {
    if (innerWidth !==  window.innerWidth) {
      innerWidth = window.innerWidth;
      uiStore.accountShow = window.innerWidth >= 767;
    }
  }
}

</script>
<style lang="scss" scoped>

.block-show {
  position: fixed;
  @media (max-width: 767px) {
    position: absolute;
    right: 0;
    border: 0;
    height: 100%;
    width: 100%;
    background: #000000;
    opacity: 0.6;
    z-index: 10;
    transition: all 300ms;
  }
}

.block-hide {
  position: fixed;
  pointer-events: none;
  transition: all 300ms;
}

.show {
  transition: all 100ms;
  @media (max-width: 767px) {
    position: fixed;
    z-index: 100;
    width: 260px;
  }
}

.hide {
  transition: all 100ms;
  position: fixed;
  transform: translateX(-100%);
  opacity: 0;
  @media (max-width: 1024px) {
    width: 260px;
    z-index: 100;
  }
}


.main-box-show {
  display: grid;
  grid-template-columns: 260px  1fr;
  height: calc(100% - 60px);
  @media (max-width: 767px) {
    grid-template-columns: 1fr;
  }
}

.main-box-hide {
  display: grid;
  grid-template-columns: 1fr;
  height: calc(100% - 60px);
}


.main-view {
  background: var(--el-bg-color);
}


.navigation {
  height: 30px;
  border-bottom: solid 1px var(--el-menu-border-color);
  display: inline-flex;
  justify-items: center;
  align-items: center;
  width: 100%;
  .tag {
    background: var(--el-bg-color);
    margin-left: 5px;
  }
}
</style>
