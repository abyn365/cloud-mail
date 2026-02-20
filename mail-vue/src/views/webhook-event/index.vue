<template>
  <div class="event-page">
    <div class="page-head">
      <div class="title">{{ $t('eventLogs') }}</div>
      <div class="subtitle">{{ $t('eventType') }} / {{ $t('level') }} / {{ $t('createdAt') }}</div>
    </div>

    <div class="toolbar" ref="toolbarRef">
      <el-input
        v-model="params.eventId"
        :placeholder="`${$t('eventId')} (#)`"
        clearable
        class="id-input"
        @keyup.enter="loadList"
      />
      <el-input
        v-model="params.keyword"
        :placeholder="$t('searchKeyword')"
        clearable
        class="keyword-input"
        @keyup.enter="loadList"
      />
      <div class="action-group">
        <el-button type="primary" @click="loadList">{{ $t('search') }}</el-button>
        <el-button @click="resetSearch">{{ $t('reset') }}</el-button>
      </div>
    </div>

    <div class="table-wrap">
      <el-table :data="rows" border stripe v-loading="loading" :height="tableHeight">
        <el-table-column prop="logId" :label="$t('eventId')" width="100" />
        <el-table-column prop="eventType" :label="$t('eventType')" min-width="220" />
        <el-table-column prop="level" :label="$t('level')" width="100" />
        <el-table-column :label="$t('message')" min-width="340">
          <template #default="{ row }">
            <div class="line-clamp">{{ row.message }}</div>
          </template>
        </el-table-column>
        <el-table-column prop="createTime" :label="$t('createdAt')" width="190" />
        <el-table-column :label="$t('action')" width="110" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="openDetail(row)">{{ $t('details') }}</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <div class="pager" ref="pagerRef">
      <el-pagination
        v-model:current-page="params.page"
        v-model:page-size="params.size"
        layout="prev, pager, next, total"
        :total="total"
        @current-change="loadList"
      />
    </div>

    <el-dialog
      v-model="detailVisible"
      :title="`${$t('eventDetail')} #${detail.logId || '-'}`"
      :width="dialogWidth"
      top="3vh"
    >
      <div class="detail">
        <div><b>{{ $t('eventType') }}:</b> {{ detail.eventType || '-' }}</div>
        <div><b>{{ $t('level') }}:</b> {{ detail.level || '-' }}</div>
        <div><b>{{ $t('createdAt') }}:</b> {{ detail.createTime || '-' }}</div>
        <div><b>{{ $t('message') }}:</b></div>
        <pre>{{ detail.message || '-' }}</pre>
        <div><b>Meta JSON:</b></div>
        <pre>{{ prettyMeta }}</pre>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, defineOptions, nextTick, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { webhookEventDetail, webhookEventList } from '@/request/webhook-event.js'

defineOptions({ name: 'webhook-event' })

const loading = ref(false)
const total = ref(0)
const rows = ref([])
const detailVisible = ref(false)
const detail = ref({})
const tableHeight = ref(420)
const toolbarRef = ref(null)
const pagerRef = ref(null)

const params = reactive({
  page: 1,
  size: 20,
  eventId: '',
  keyword: ''
})

const prettyMeta = computed(() => {
  if (!detail.value?.meta) return '-'
  try {
    return JSON.stringify(JSON.parse(detail.value.meta), null, 2)
  } catch (e) {
    return detail.value.meta
  }
})

const dialogWidth = computed(() => (window.innerWidth < 768 ? '95vw' : '760px'))

function sanitizeEventId(raw) {
  const n = Number(raw)
  return Number.isInteger(n) && n > 0 ? n : undefined
}

function updateTableHeight() {
  const viewport = window.innerHeight || 760
  const toolbarH = toolbarRef.value?.offsetHeight || 58
  const pagerH = pagerRef.value?.offsetHeight || 40
  const pageHead = 64
  const pagePadding = window.innerWidth < 768 ? 42 : 52
  const reserve = toolbarH + pagerH + pageHead + pagePadding
  tableHeight.value = Math.max(250, viewport - reserve)
}

function loadList() {
  loading.value = true
  return webhookEventList({
    page: params.page,
    size: params.size,
    eventId: sanitizeEventId(params.eventId),
    keyword: params.keyword?.trim() || undefined
  }).then(data => {
    rows.value = data.list || []
    total.value = data.total || 0
  }).finally(() => {
    loading.value = false
    nextTick(() => updateTableHeight())
  })
}

function resetSearch() {
  params.page = 1
  params.eventId = ''
  params.keyword = ''
  loadList()
}

function openDetail(row) {
  webhookEventDetail(row.logId).then(data => {
    detail.value = data || row
    detailVisible.value = true
  })
}

onMounted(() => {
  nextTick(() => updateTableHeight())
  window.addEventListener('resize', updateTableHeight)
  loadList()
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', updateTableHeight)
})
</script>

<style scoped>
.event-page {
  padding: 10px;
  min-height: calc(100dvh - 140px);
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.page-head {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.title {
  font-size: 18px;
  font-weight: 700;
}

.subtitle {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.toolbar {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  align-items: center;
}

.id-input {
  width: 170px;
}

.keyword-input {
  min-width: 220px;
  flex: 1;
}

.action-group {
  display: flex;
  gap: 8px;
}

.table-wrap {
  flex: 1;
  min-height: 250px;
}

.line-clamp {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.pager {
  display: flex;
  justify-content: flex-end;
  overflow-x: auto;
}

.detail {
  max-height: min(70dvh, 560px);
  overflow: auto;
}

.detail pre {
  background: var(--el-fill-color-light);
  padding: 10px;
  border-radius: 6px;
  max-height: 240px;
  overflow: auto;
}

@media (max-width: 767px) {
  .event-page {
    min-height: calc(100dvh - 110px);
    padding: 8px;
  }

  .id-input,
  .keyword-input,
  .action-group {
    width: 100%;
    min-width: 100%;
  }

  .action-group :deep(.el-button) {
    flex: 1;
  }

  .pager {
    justify-content: flex-start;
  }
}
</style>
