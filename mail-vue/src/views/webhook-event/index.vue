<template>
  <div class="event-page">
    <div class="toolbar">
      <el-input v-model="params.eventId" :placeholder="`${$t('eventId')} (#)`" clearable style="max-width: 180px" @keyup.enter="loadList" />
      <el-input v-model="params.keyword" :placeholder="$t('searchKeyword')" clearable @keyup.enter="loadList" />
      <el-button type="primary" @click="loadList">{{ $t('search') }}</el-button>
      <el-button @click="resetSearch">{{ $t('reset') }}</el-button>
    </div>

    <el-table :data="rows" border stripe v-loading="loading" height="calc(100vh - 220px)">
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

    <div class="pager">
      <el-pagination
        v-model:current-page="params.page"
        v-model:page-size="params.size"
        layout="prev, pager, next, total"
        :total="total"
        @current-change="loadList"
      />
    </div>

    <el-dialog v-model="detailVisible" :title="`${$t('eventDetail')} #${detail.logId || '-'}`" width="760px">
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
import { computed, defineOptions, onMounted, reactive, ref } from 'vue'
import { webhookEventDetail, webhookEventList } from '@/request/webhook-event.js'

defineOptions({ name: 'webhook-event' })

const loading = ref(false)
const total = ref(0)
const rows = ref([])
const detailVisible = ref(false)
const detail = ref({})

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

function sanitizeEventId(raw) {
  const n = Number(raw)
  return Number.isInteger(n) && n > 0 ? n : undefined
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
  loadList()
})
</script>

<style scoped>
.event-page { padding: 10px; }
.toolbar { display: flex; gap: 10px; margin-bottom: 12px; }
.line-clamp { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.pager { display: flex; justify-content: flex-end; margin-top: 12px; }
.detail pre { background: var(--el-fill-color-light); padding: 10px; border-radius: 6px; max-height: 250px; overflow: auto; }
</style>
