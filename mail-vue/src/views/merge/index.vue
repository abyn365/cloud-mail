<template>
  <div class="merge-container">
    <div class="header">
      <div class="header-left">
        <Icon icon="hugeicons:quill-write-01" width="28" height="28" class="title-icon"/>
        <h2 class="title">{{ $t('mailMerge') }}</h2>
      </div>
      <el-button @click="goBack" plain>
        <template #icon>
          <Icon icon="ep:arrow-left" />
        </template>
        {{ $t('back') }}
      </el-button>
    </div>

    <div class="merge-content">
      <el-form :model="form" label-position="top">
        <el-row :gutter="20">
          <el-col :span="12">
            <el-form-item :label="$t('sender')">
              <el-select v-model="form.accountId" style="width: 100%">
                <el-option
                  v-for="account in accountStore.accountList"
                  :key="account.accountId"
                  :label="account.email"
                  :value="account.accountId"
                />
              </el-select>
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item :label="$t('subject')">
              <el-input v-model="form.subject" :placeholder="$t('subjectPlaceholder')" />
            </el-form-item>
          </el-col>
        </el-row>
        
        <el-tabs v-model="activeTab" class="merge-tabs">
          <el-tab-pane :label="$t('template')" name="template">
            <div class="editor-wrapper">
              <tinyEditor ref="editorRef" :def-value="defValue" @change="onEditorChange" />
            </div>
          </el-tab-pane>
          <el-tab-pane :label="$t('recipients')" name="recipients">
            <div class="csv-upload">
              <el-input
                v-model="form.csvData"
                type="textarea"
                :rows="12"
                :placeholder="$t('csvPlaceholder')"
                @input="parseCSV"
              />
              <div class="upload-tip">
                <span>{{ $t('csvUploadTip') }}</span>
                <el-upload
                  action=""
                  :auto-upload="false"
                  :show-file-list="false"
                  :on-change="handleFileChange"
                  accept=".csv"
                >
                  <el-button type="primary" size="small" plain>
                    <template #icon>
                      <Icon icon="ep:upload" />
                    </template>
                    {{ $t('uploadCSV') }}
                  </el-button>
                </el-upload>
              </div>
            </div>
            
            <div v-if="parsedRecipients.length > 0" class="preview-table">
              <h3>{{ $t('recipientPreview') }} ({{ parsedRecipients.length }})</h3>
              <el-table :data="parsedRecipients.slice(0, 10)" stripe border style="width: 100%">
                <el-table-column v-for="header in csvHeaders" :key="header" :prop="header" :label="header" show-overflow-tooltip />
              </el-table>
              <p v-if="parsedRecipients.length > 10" class="more-tip">... and {{ parsedRecipients.length - 10 }} more recipients</p>
            </div>
          </el-tab-pane>
          <el-tab-pane :label="$t('preview')" name="preview">
             <div v-if="parsedRecipients.length > 0" class="personalized-preview">
                <div class="preview-header">
                  <div class="preview-controls">
                    <el-button @click="prevPreview" :disabled="previewIndex === 0" circle>
                      <Icon icon="ep:arrow-left" />
                    </el-button>
                    <span class="preview-index">{{ previewIndex + 1 }} / {{ parsedRecipients.length }}</span>
                    <el-button @click="nextPreview" :disabled="previewIndex === parsedRecipients.length - 1" circle>
                      <Icon icon="ep:arrow-right" />
                    </el-button>
                  </div>
                  <div class="preview-recipient-info">
                    <strong>{{ $t('to') }}:</strong> {{ currentRecipientEmail }}
                  </div>
                </div>
                <div class="preview-output">
                  <div class="preview-subject">
                    <strong>{{ $t('subject') }}:</strong> {{ personalizedSubject }}
                  </div>
                  <div v-html="personalizedContent" class="content-preview mce-content-body"></div>
                </div>
             </div>
             <div v-else class="no-recipients">
                <el-empty :description="$t('noRecipientsTip')" />
             </div>
          </el-tab-pane>
        </el-tabs>

        <div class="actions">
          <el-button type="primary" size="large" :loading="sending" @click="confirmSend" class="send-btn">
            <template #icon>
              <Icon icon="ep:promotion" />
            </template>
            {{ $t('sendMerge') }}
          </el-button>
        </div>
      </el-form>
    </div>

    <el-dialog v-model="showProgress" :title="$t('sending')" :close-on-click-modal="false" :close-on-press-escape="false" :show-close="results !== null" width="500px">
      <div class="progress-box">
        <el-progress 
          type="circle" 
          :percentage="progressPercentage" 
          :status="progressStatus"
          :stroke-width="10"
        />
        <p class="progress-text">{{ progressText }}</p>
        
        <div v-if="results" class="results">
          <el-divider />
          <div class="results-stats">
            <div class="stat-item">
              <span class="label">{{ $t('total') }}</span>
              <span class="value">{{ results.total }}</span>
            </div>
            <div class="stat-item success">
              <span class="label">{{ $t('sent') }}</span>
              <span class="value">{{ results.sent }}</span>
            </div>
            <div class="stat-item danger">
              <span class="label">{{ $t('failed') }}</span>
              <span class="value">{{ results.failed }}</span>
            </div>
          </div>
          
          <div v-if="results.failures.length > 0" class="failures">
             <el-collapse>
               <el-collapse-item :title="$t('failureDetails')" name="1">
                 <ul class="failure-list">
                   <li v-for="(f, i) in results.failures" :key="i">
                     <span class="fail-email">{{ f.email || 'N/A' }}</span>: {{ f.error }}
                   </li>
                 </ul>
               </el-collapse-item>
             </el-collapse>
          </div>
          <div class="dialog-footer">
            <el-button @click="showProgress = false" type="primary">{{ $t('close') }}</el-button>
          </div>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useAccountStore } from '@/store/account'
import tinyEditor from '@/components/tiny-editor/index.vue'
import mergeRequest from '@/request/merge'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Icon } from '@iconify/vue'

const { t } = useI18n()
const router = useRouter()
const accountStore = useAccountStore()

const activeTab = ref('template')
const form = reactive({
  accountId: null,
  subject: '',
  content: '',
  csvData: ''
})
const defValue = ref('')
const editorRef = ref(null)
const sending = ref(false)
const parsedRecipients = ref([])
const csvHeaders = ref([])
const previewIndex = ref(0)

const showProgress = ref(false)
const progressPercentage = ref(0)
const progressStatus = ref('')
const progressText = ref('')
const results = ref(null)

onMounted(() => {
  if (accountStore.accountList.length > 0) {
    form.accountId = accountStore.accountList[0].accountId
  }
})

function goBack() {
  router.back()
}

function onEditorChange(content) {
  form.content = content
}

function handleFileChange(file) {
  const reader = new FileReader()
  reader.onload = (e) => {
    form.csvData = e.target.result
    parseCSV()
  }
  reader.readAsText(file.raw)
}

function parseCSV() {
  if (!form.csvData) {
    parsedRecipients.value = []
    csvHeaders.value = []
    return
  }
  
  const rows = []
  let currentRow = []
  let currentField = ''
  let insideQuotes = false

  for (let i = 0; i < form.csvData.length; i++) {
    const char = form.csvData[i]
    const nextChar = form.csvData[i + 1]

    if (char === '"' && insideQuotes && nextChar === '"') {
      currentField += '"'
      i++
    } else if (char === '"') {
      insideQuotes = !insideQuotes
    } else if (char === ',' && !insideQuotes) {
      currentRow.push(currentField.trim())
      currentField = ''
    } else if ((char === '\r' || char === '\n') && !insideQuotes) {
      if (char === '\r' && nextChar === '\n') i++
      currentRow.push(currentField.trim())
      if (currentRow.length > 0 && currentRow.some(f => f !== '')) {
        rows.push(currentRow)
      }
      currentRow = []
      currentField = ''
    } else {
      currentField += char
    }
  }
  if (currentField || currentRow.length > 0) {
    currentRow.push(currentField.trim())
    rows.push(currentRow)
  }

  if (rows.length < 2) {
    parsedRecipients.value = []
    csvHeaders.value = []
    return
  }

  csvHeaders.value = rows[0]
  parsedRecipients.value = rows.slice(1).map(row => {
    const obj = {}
    csvHeaders.value.forEach((header, i) => {
      obj[header] = row[i] || ''
    })
    return obj
  })
}

function replacePlaceholders(template, variables) {
  if (!template) return ''
  return template.replace(/\{\{(.*?)\}\}/g, (match, key) => {
    const trimmedKey = key.trim()
    return variables[trimmedKey] !== undefined ? variables[trimmedKey] : match
  })
}

const currentRecipientEmail = computed(() => {
  if (parsedRecipients.value.length === 0) return ''
  const recipient = parsedRecipients.value[previewIndex.value]
  return recipient.email || recipient.Email || recipient.EMAIL || 'N/A'
})

const personalizedSubject = computed(() => {
  if (parsedRecipients.value.length === 0) return form.subject
  return replacePlaceholders(form.subject, parsedRecipients.value[previewIndex.value])
})

const personalizedContent = computed(() => {
  if (parsedRecipients.value.length === 0) return form.content
  return replacePlaceholders(form.content, parsedRecipients.value[previewIndex.value])
})

function prevPreview() {
  if (previewIndex.value > 0) previewIndex.value--
}

function nextPreview() {
  if (previewIndex.value < parsedRecipients.value.length - 1) previewIndex.value++
}

async function confirmSend() {
  if (!form.accountId || !form.subject || !form.content || !form.csvData) {
    ElMessage.error(t('missingParams'))
    return
  }

  if (parsedRecipients.value.length === 0) {
    ElMessage.error(t('noRecipientsFound'))
    return
  }

  try {
    await ElMessageBox.confirm(
      t('confirmSendMerge', { count: parsedRecipients.value.length }),
      t('warning'),
      {
        confirmButtonText: t('confirm'),
        cancelButtonText: t('cancel'),
        type: 'warning'
      }
    )
    
    sendMerge()
  } catch (e) {
    // cancelled
  }
}

async function sendMerge() {
  sending.value = true
  showProgress.value = true
  progressPercentage.value = 0
  progressStatus.value = ''
  progressText.value = t('sending')
  results.value = null
  
  // Fake progress since the backend handles it in one go (in this simple implementation)
  const progressInterval = setInterval(() => {
    if (progressPercentage.value < 90) {
      progressPercentage.value += Math.random() * 10
    }
  }, 1000)

  try {
    const res = await mergeRequest.send(form)
    clearInterval(progressInterval)
    results.value = res.data
    progressPercentage.value = 100
    if (res.data.failed === 0) {
      progressStatus.value = 'success'
      progressText.value = t('sendSuccessMsg')
    } else if (res.data.sent > 0) {
      progressStatus.value = 'warning'
      progressText.value = t('partiallyFailed')
    } else {
      progressStatus.value = 'exception'
      progressText.value = t('sendFailMsg')
    }
  } catch (e) {
    clearInterval(progressInterval)
    progressStatus.value = 'exception'
    progressText.value = e.message
  } finally {
    sending.value = false
  }
}
</script>

<style scoped>
.merge-container {
  padding: 24px;
  background: var(--el-bg-color);
  min-height: 100%;
  max-width: 1200px;
  margin: 0 auto;
}
.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}
.header-left {
  display: flex;
  align-items: center;
}
.title-icon {
  margin-right: 12px;
  color: var(--el-color-primary);
}
.title {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
}
.merge-content {
  background: var(--el-bg-color-overlay);
  padding: 24px;
  border-radius: 8px;
  box-shadow: var(--el-box-shadow-light);
}
.merge-tabs {
  margin-top: 20px;
}
.editor-wrapper {
  height: 500px;
  border: 1px solid var(--el-border-color-light);
  border-radius: 4px;
  overflow: hidden;
}
.csv-upload {
  margin-bottom: 20px;
}
.upload-tip {
  margin-top: 12px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  color: var(--el-text-color-secondary);
  font-size: 14px;
}
.preview-table {
  margin-top: 24px;
}
.preview-table h3 {
  font-size: 16px;
  margin-bottom: 12px;
}
.more-tip {
  margin-top: 12px;
  color: var(--el-text-color-secondary);
  font-size: 14px;
  text-align: center;
}
.preview-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding: 12px;
  background: var(--el-fill-color-light);
  border-radius: 4px;
}
.preview-controls {
  display: flex;
  align-items: center;
  gap: 12px;
}
.preview-index {
  font-weight: 600;
  min-width: 60px;
  text-align: center;
}
.preview-recipient-info {
  font-size: 14px;
}
.preview-output {
  border: 1px solid var(--el-border-color-light);
  border-radius: 4px;
  overflow: hidden;
}
.preview-subject {
  padding: 12px 16px;
  background: var(--el-fill-color-lighter);
  border-bottom: 1px solid var(--el-border-color-light);
}
.content-preview {
  padding: 20px;
  min-height: 300px;
  background: white;
  color: #333;
}
.no-recipients {
  padding: 40px 0;
}
.actions {
  margin-top: 32px;
  text-align: center;
}
.send-btn {
  padding-left: 40px;
  padding-right: 40px;
}
.progress-box {
  text-align: center;
  padding: 10px 0;
}
.progress-text {
  margin-top: 16px;
  font-weight: 600;
}
.results-stats {
  display: flex;
  justify-content: space-around;
  margin: 16px 0;
}
.stat-item {
  display: flex;
  flex-direction: column;
}
.stat-item .label {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
.stat-item .value {
  font-size: 20px;
  font-weight: 600;
}
.stat-item.success .value {
  color: var(--el-color-success);
}
.stat-item.danger .value {
  color: var(--el-color-danger);
}
.failures {
  margin-top: 16px;
  text-align: left;
}
.failure-list {
  padding-left: 20px;
  margin: 0;
  max-height: 200px;
  overflow-y: auto;
  font-size: 13px;
}
.fail-email {
  font-weight: 600;
}
.dialog-footer {
  margin-top: 24px;
  text-align: center;
}
</style>
