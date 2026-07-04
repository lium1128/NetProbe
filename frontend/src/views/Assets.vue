<template>
  <div class="assets">
    <div class="np-page-header">
      <div>
        <span class="np-page-title">{{ t('assets.title') }}</span>
        <span class="np-page-desc" v-if="items.length">{{ t('assets.assets', { n: items.length }) }}</span>
      </div>
    </div>

    <el-card>
      <div class="np-filter-bar">
        <el-input v-model="query" :placeholder="t('assets.searchPlaceholder')" clearable style="width: 260px" @keyup.enter="loadData">
          <template #prefix><el-icon><Search /></el-icon></template>
        </el-input>
        <el-select v-model="sortBy" style="width: 160px" @change="loadData">
          <el-option :label="t('assets.sortHostname')" value="hostname" />
          <el-option :label="t('assets.sortPortCount')" value="port_count" />
          <el-option :label="t('assets.sortScanCount')" value="scan_count" />
          <el-option :label="t('assets.sortRiskScore')" value="risk_score" />
        </el-select>
        <el-button type="primary" @click="loadData">{{ t('common.search') }}</el-button>
      </div>

      <div class="np-table-wrapper">
        <el-table
          :data="items"
          v-loading="loading"
          row-key="rowKey"
          :expand-row-keys="expandedKeys"
          @expand-change="handleExpandChange"
        >
          <!-- 展开行：资产详情 -->
          <el-table-column type="expand" width="38">
            <template #default="{ row }">
              <div class="expand-content" v-loading="row._loading">
                <!-- 加载失败 -->
                <div v-if="row._error" class="expand-error">
                  <el-icon :size="20" color="var(--np-danger)"><WarningFilled /></el-icon>
                  <span>{{ row._error }}</span>
                </div>

                <!-- 详情内容 -->
                <div v-else-if="row._detail" class="expand-body">
                  <!-- 概览数字条 -->
                  <div class="detail-overview">
                    <span class="ov-item"><b class="mono">{{ row._detail.port_count }}</b>{{ t('assets.ports') }}</span>
                    <span class="ov-item"><b class="mono">{{ row._detail.web_count }}</b>{{ t('assets.web') }}</span>
                    <span class="ov-item" v-if="row._detail.vuln_count">
                      <b class="mono">{{ row._detail.vuln_count }}</b>{{ t('assets.detail.vulns') }}
                    </span>
                    <span class="ov-item"><b class="mono">{{ row._detail.scan_count }}</b>{{ t('assets.scans') }}</span>
                  </div>

                  <div class="detail-grid">
                    <!-- 端口服务 -->
                    <section v-if="row._detail.ports?.length" class="detail-section">
                      <div class="np-section-title">
                        {{ t('assets.detail.portsServices') }}
                        <span class="np-badge">{{ row._detail.ports.length }}</span>
                      </div>
                      <el-table :data="row._detail.ports" size="small" class="mini-table" border>
                        <el-table-column prop="port" :label="t('table.port')" width="80">
                          <template #default="{ row: p }"><span class="mono">{{ p.port }}/{{ p.proto }}</span></template>
                        </el-table-column>
                        <el-table-column prop="state" :label="t('table.state')" width="80">
                          <template #default="{ row: p }">
                            <el-tag v-if="p.state === 'open'" type="success" size="small">{{ p.state }}</el-tag>
                            <span v-else class="mono">{{ p.state }}</span>
                          </template>
                        </el-table-column>
                        <el-table-column prop="service" :label="t('table.service')" width="110">
                          <template #default="{ row: p }">{{ p.service || '—' }}</template>
                        </el-table-column>
                        <el-table-column prop="product" :label="t('table.product')" min-width="120">
                          <template #default="{ row: p }">
                            <span class="mono">{{ [p.product, p.version].filter(Boolean).join(' ') || '—' }}</span>
                          </template>
                        </el-table-column>
                      </el-table>
                    </section>

                    <!-- Web 站点 -->
                    <section v-if="row._detail.web_info?.length" class="detail-section">
                      <div class="np-section-title">
                        {{ t('assets.detail.webSites') }}
                        <span class="np-badge">{{ row._detail.web_info.length }}</span>
                      </div>
                      <div class="web-list">
                        <div v-for="(site, i) in row._detail.web_info" :key="i" class="web-card">
                          <div class="web-head">
                            <a :href="site.url" target="_blank" rel="noopener" class="web-url mono">{{ site.url }}</a>
                            <el-tag v-if="site.status" :type="statusTagType(site.status)" size="small" effect="dark">{{ site.status }}</el-tag>
                          </div>
                          <div class="web-title" v-if="site.title">{{ site.title }}</div>
                          <div class="web-meta">
                            <span class="meta-item" v-if="site.port">
                              <el-icon :size="13"><Connection /></el-icon>{{ site.port }}
                            </span>
                            <span class="meta-item" v-if="site.cdn">
                              <el-icon :size="13"><Cloudy /></el-icon>CDN
                            </span>
                          </div>
                          <div class="web-tags" v-if="site.tech?.length">
                            <el-tag v-for="(tech, ti) in site.tech" :key="ti" size="small" type="info" class="tech-tag">
                              {{ typeof tech === 'string' ? tech : tech.name }}
                            </el-tag>
                          </div>
                        </div>
                      </div>
                    </section>

                    <!-- 漏洞 -->
                    <section v-if="row._detail.vulnerabilities?.length" class="detail-section">
                      <div class="np-section-title">
                        {{ t('assets.detail.vulns') }}
                        <span class="np-badge np-badge--danger">{{ row._detail.vulnerabilities.length }}</span>
                      </div>
                      <div class="vuln-list">
                        <div v-for="(v, i) in row._detail.vulnerabilities" :key="i" class="vuln-row">
                          <el-tag :type="vulnSeverityType(v.severity)" size="small" effect="dark">{{ v.severity }}</el-tag>
                          <span class="vuln-name">{{ v.name }}</span>
                          <a v-if="v.cve" :href="`https://nvd.nist.gov/vuln/detail/${v.cve}`" target="_blank" rel="noopener" class="mono vuln-cve">{{ v.cve }}</a>
                          <span class="mono cvss" v-if="v.cvss_score">CVSS {{ v.cvss_score }}</span>
                        </div>
                      </div>
                    </section>

                    <!-- 技术栈 -->
                    <section v-if="row._detail.tech_stack?.length" class="detail-section">
                      <div class="np-section-title">
                        {{ t('assets.detail.techStack') }}
                        <span class="np-badge">{{ row._detail.tech_stack.length }}</span>
                      </div>
                      <div class="np-tag-group">
                        <el-tag v-for="(tech, i) in row._detail.tech_stack" :key="i" size="small" type="info">{{ tech }}</el-tag>
                      </div>
                    </section>

                    <!-- 敏感路径 -->
                    <section v-if="row._detail.sensitive?.length" class="detail-section">
                      <div class="np-section-title">
                        {{ t('assets.detail.sensitive') }}
                        <span class="np-badge np-badge--warn">{{ row._detail.sensitive.length }}</span>
                      </div>
                      <el-table :data="row._detail.sensitive" size="small" class="mini-table" border>
                        <el-table-column prop="path" :label="t('table.path')" min-width="200">
                          <template #default="{ row: s }"><span class="mono">{{ s.path }}</span></template>
                        </el-table-column>
                        <el-table-column prop="severity" :label="t('table.severity')" width="90">
                          <template #default="{ row: s }">
                            <el-tag :type="severityType(s.severity)" size="small">{{ s.severity }}</el-tag>
                          </template>
                        </el-table-column>
                        <el-table-column prop="description" :label="t('table.description')" min-width="160">
                          <template #default="{ row: s }">{{ s.description || '—' }}</template>
                        </el-table-column>
                      </el-table>
                    </section>

                    <!-- Banner -->
                    <section v-if="row._detail.banners?.length" class="detail-section">
                      <div class="np-section-title">
                        {{ t('assets.detail.banners') }}
                        <span class="np-badge">{{ row._detail.banners.length }}</span>
                      </div>
                      <div class="banner-list">
                        <div v-for="(b, i) in row._detail.banners" :key="i" class="banner-row">
                          <span class="mono banner-port">{{ b.port }}</span>
                          <span class="banner-service">{{ b.service || '—' }}</span>
                          <pre class="mono banner-text">{{ b.banner }}</pre>
                        </div>
                      </div>
                    </section>

                    <!-- 空详情兜底（接口返回但全空） -->
                    <div
                      v-if="!row._detail.ports?.length && !row._detail.web_info?.length
                        && !row._detail.vulnerabilities?.length && !row._detail.tech_stack?.length
                        && !row._detail.sensitive?.length && !row._detail.banners?.length"
                      class="np-empty"
                    >
                      <el-icon :size="28" color="var(--np-text-disabled)"><Grid /></el-icon>
                      <p>{{ t('common.noData') }}</p>
                    </div>
                  </div>
                </div>
              </div>
            </template>
          </el-table-column>

          <!-- 主机名 -->
          <el-table-column prop="hostname" :label="t('assets.hostname')" min-width="200">
            <template #default="{ row }"><span style="font-weight:500">{{ row.hostname }}</span></template>
          </el-table-column>
          <!-- IP -->
          <el-table-column prop="ip" :label="t('assets.ip')" width="140">
            <template #default="{ row }"><span class="mono">{{ row.ip }}</span></template>
          </el-table-column>
          <!-- 扫描数 -->
          <el-table-column prop="scan_count" :label="t('assets.scans')" width="80">
            <template #default="{ row }"><span class="mono">{{ row.scan_count }}</span></template>
          </el-table-column>
          <!-- 端口数 -->
          <el-table-column prop="port_count" :label="t('assets.ports')" width="80">
            <template #default="{ row }"><span class="mono">{{ row.port_count }}</span></template>
          </el-table-column>
          <!-- 网站数 -->
          <el-table-column prop="web_count" :label="t('assets.web')" width="80">
            <template #default="{ row }"><span class="mono">{{ row.web_count }}</span></template>
          </el-table-column>
          <!-- 风险评分 -->
          <el-table-column prop="risk_score" :label="t('assets.risk')" width="100" align="center">
            <template #default="{ row }">
              <span class="risk-badge" :class="riskClass(row.risk_score || 0)">{{ row.risk_score || 0 }}</span>
            </template>
          </el-table-column>
        </el-table>
      </div>

      <div v-if="!loading && items.length === 0" class="np-empty">
        <el-icon :size="36" color="var(--np-text-disabled)"><Grid /></el-icon>
        <p>{{ t('assets.empty') }}</p>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { getAssets, getAssetDetail } from '../api/scan'
import type { AssetSummary } from '../types'

const { t } = useI18n()

/** 行数据：在 AssetSummary 上挂载展开态字段 */
interface AssetRow extends AssetSummary {
  rowKey: string
  _loading?: boolean
  _loaded?: boolean
  _error?: string
  _detail?: any
}

const items = ref<AssetRow[]>([])
const loading = ref(false)
const query = ref('')
const sortBy = ref('hostname')
/** 受控展开的行 key 列表 */
const expandedKeys = ref<string[]>([])

async function loadData() {
  loading.value = true
  try {
    const res = await getAssets(query.value, sortBy.value)
    items.value = (res.items || []).map(it => ({
      ...it,
      rowKey: `${it.hostname}::${it.ip}`,
      _loading: false,
      _loaded: false,
    }))
    expandedKeys.value = []
  } finally {
    loading.value = false
  }
}

/** el-table 展开行回调：仅当展开（expanded.length 增大）且未加载时拉取详情 */
async function handleExpandChange(row: AssetRow, expandedList: AssetRow[]) {
  const isExpanded = expandedList.some(r => r.rowKey === row.rowKey)
  // 同步受控 keys，保证折叠按钮工作正常
  expandedKeys.value = expandedList.map(r => r.rowKey)
  if (!isExpanded || row._loaded || row._loading) return
  row._loading = true
  row._error = undefined
  try {
    const detail = await getAssetDetail(row.hostname, row.ip)
    row._detail = detail || {}
    row._loaded = true
  } catch (e: any) {
    row._error = e?.message || t('assets.detail.loadError')
  } finally {
    row._loading = false
  }
}

function riskClass(score: number): string {
  if (score >= 70) return 'risk-high'
  if (score >= 40) return 'risk-medium'
  return 'risk-low'
}

/** HTTP 状态码 → el-tag 类型 */
function statusTagType(status: number) {
  if (status >= 200 && status < 300) return 'success'
  if (status >= 300 && status < 400) return 'warning'
  return 'danger'
}

/** 敏感路径等级 → el-tag 类型 */
function severityType(sev: string) {
  const s = (sev || '').toLowerCase()
  if (s === 'high' || s === 'critical') return 'danger'
  if (s === 'medium') return 'warning'
  return 'info'
}

/** 漏洞等级 → el-tag 类型 */
function vulnSeverityType(sev: string) {
  const s = (sev || '').toLowerCase()
  if (s === 'critical') return 'danger'
  if (s === 'high') return 'danger'
  if (s === 'medium') return 'warning'
  return 'info'
}

onMounted(loadData)
</script>

<style scoped>
.assets {
  max-width: 1400px;
  margin: 0 auto;
}

.risk-badge {
  display: inline-block;
  min-width: 32px;
  padding: 2px 8px;
  border-radius: 4px;
  font-weight: 600;
  font-size: 13px;
}
.risk-high {
  background: var(--np-danger-bg);
  color: var(--np-danger);
}
.risk-medium {
  background: var(--np-warning-bg);
  color: var(--np-warning);
}
.risk-low {
  background: var(--np-success-bg);
  color: var(--np-success);
}

/* ── 展开内容 ─────────────────────────────────────────────── */
.expand-content {
  min-height: 80px;
  padding: var(--np-space-4) var(--np-space-5);
}

.expand-error {
  display: flex;
  align-items: center;
  gap: var(--np-space-2);
  color: var(--np-danger);
  padding: var(--np-space-3) 0;
}

/* 顶部概览数字条 */
.detail-overview {
  display: flex;
  flex-wrap: wrap;
  gap: var(--np-space-5);
  padding-bottom: var(--np-space-3);
  margin-bottom: var(--np-space-4);
  border-bottom: 1px solid var(--np-border);
}
.detail-overview .ov-item {
  display: inline-flex;
  align-items: baseline;
  gap: var(--np-space-1);
  font-size: 13px;
  color: var(--np-text-muted);
}
.detail-overview .ov-item b {
  font-size: 18px;
  font-weight: 700;
  color: var(--np-text-primary);
}

/* 详情网格 */
.detail-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
  gap: var(--np-space-5);
}

.detail-section {
  min-width: 0;
}

/* 嵌套小表格 */
.mini-table {
  font-size: 12px;
}

/* Web 站点列表 */
.web-list {
  display: flex;
  flex-direction: column;
  gap: var(--np-space-3);
}
.web-card {
  border: 1px solid var(--np-border);
  border-radius: var(--np-radius-md);
  padding: var(--np-space-3);
  background: var(--np-bg-layout);
}
.web-head {
  display: flex;
  align-items: center;
  gap: var(--np-space-2);
  flex-wrap: wrap;
}
.web-url {
  font-size: 13px;
  font-weight: 500;
  color: var(--np-blue-500);
  word-break: break-all;
}
.web-url:hover {
  color: var(--np-blue-600);
}
.web-title {
  margin-top: var(--np-space-1);
  font-size: 13px;
  color: var(--np-text-secondary);
}
.web-meta {
  display: flex;
  gap: var(--np-space-3);
  margin-top: var(--np-space-2);
  color: var(--np-text-muted);
  font-size: 12px;
}
.web-meta .meta-item {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.web-tags {
  display: flex;
  flex-wrap: wrap;
  gap: var(--np-space-1);
  margin-top: var(--np-space-2);
}
.tech-tag {
  font-family: var(--np-font-mono);
  font-size: 12px;
}

/* 漏洞列表 */
.vuln-list {
  display: flex;
  flex-direction: column;
  gap: var(--np-space-2);
}
.vuln-row {
  display: flex;
  align-items: center;
  gap: var(--np-space-2);
  flex-wrap: wrap;
  padding: var(--np-space-2);
  border-radius: var(--np-radius-sm);
  background: var(--np-danger-bg);
}
.vuln-name {
  font-size: 13px;
  color: var(--np-text-primary);
  flex: 1;
  min-width: 120px;
}
.vuln-cve {
  font-size: 12px;
  color: var(--np-blue-500);
}
.vuln-cve:hover {
  color: var(--np-blue-600);
  text-decoration: underline;
}
.cvss {
  font-size: 12px;
  color: var(--np-text-muted);
}

/* Banner 列表 */
.banner-list {
  display: flex;
  flex-direction: column;
  gap: var(--np-space-2);
}
.banner-row {
  display: grid;
  grid-template-columns: 70px 90px 1fr;
  gap: var(--np-space-2);
  align-items: start;
  padding: var(--np-space-2);
  border: 1px solid var(--np-border);
  border-radius: var(--np-radius-sm);
  background: var(--np-bg-layout);
}
.banner-port {
  color: var(--np-text-secondary);
  font-weight: 600;
}
.banner-service {
  color: var(--np-text-secondary);
  font-size: 13px;
}
.banner-text {
  margin: 0;
  font-size: 12px;
  color: var(--np-text-muted);
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 120px;
  overflow-y: auto;
}

/* 响应式：窄屏单列 */
@media (max-width: 768px) {
  .detail-grid {
    grid-template-columns: 1fr;
  }
  .banner-row {
    grid-template-columns: 1fr;
  }
}
</style>
