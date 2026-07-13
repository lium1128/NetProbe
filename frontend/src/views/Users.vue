<template>
  <div class="users-page">
    <div class="np-page-header">
      <div>
        <span class="np-page-title">用户管理</span>
      </div>
      <div class="np-page-actions">
        <el-button type="primary" @click="showForm = true">
          <el-icon><Plus /></el-icon> 新建用户
        </el-button>
      </div>
    </div>

    <el-card>
      <el-table :data="users" v-loading="loading" size="small" stripe style="width: 100%">
        <el-table-column prop="id" label="ID" min-width="60" />
        <el-table-column prop="username" label="用户名" min-width="120" show-overflow-tooltip>
          <template #default="{ row }">
            <strong>{{ row.username }}</strong>
          </template>
        </el-table-column>
        <el-table-column label="角色" min-width="120" align="center">
          <template #default="{ row }">
            <el-tag :type="roleTagType(row.role)" size="small" effect="dark">
              {{ roleLabel(row.role) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="权限" min-width="300">
          <template #default="{ row }">
            <span class="perm-list">{{ (rolePerms[row.role] || []).join(', ') }}</span>
          </template>
        </el-table-column>
        <el-table-column label="创建时间" min-width="160">
          <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="最后登录" min-width="160">
          <template #default="{ row }">{{ formatTime(row.last_login) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="200" align="center" fixed="right">
          <template #default="{ row }">
            <el-button size="small" link type="primary" @click="openEditRole(row)" v-if="row.id !== currentUserId">改角色</el-button>
            <el-button size="small" link type="warning" @click="openEditPwd(row)">改密码</el-button>
            <el-button size="small" link type="danger" @click="handleDelete(row)" v-if="row.id !== currentUserId">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 新建用户对话框 -->
    <el-dialog v-model="showForm" title="新建用户" width="440px" destroy-on-close>
      <el-form label-width="80px">
        <el-form-item label="用户名">
          <el-input v-model="form.username" placeholder="登录用户名" />
        </el-form-item>
        <el-form-item label="密码">
          <el-input v-model="form.password" type="password" placeholder="至少 6 位" show-password />
        </el-form-item>
        <el-form-item label="角色">
          <el-select v-model="form.role" style="width: 100%">
            <el-option v-for="r in roleOptions" :key="r.value" :label="r.label" :value="r.value">
              <span>{{ r.label }}</span>
              <span class="perm-hint">{{ r.desc }}</span>
            </el-option>
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showForm = false">取消</el-button>
        <el-button type="primary" :loading="submitting" @click="handleCreate">创建</el-button>
      </template>
    </el-dialog>

    <!-- 改角色对话框 -->
    <el-dialog v-model="showRoleForm" title="修改角色" width="440px" destroy-on-close>
      <el-form label-width="80px">
        <el-form-item label="用户">
          <span class="mono">{{ editUser?.username }}</span>
        </el-form-item>
        <el-form-item label="角色">
          <el-select v-model="editRole" style="width: 100%">
            <el-option v-for="r in roleOptions" :key="r.value" :label="r.label" :value="r.value">
              <span>{{ r.label }}</span>
              <span class="perm-hint">{{ r.desc }}</span>
            </el-option>
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showRoleForm = false">取消</el-button>
        <el-button type="primary" :loading="submitting" @click="handleUpdateRole">确定</el-button>
      </template>
    </el-dialog>

    <!-- 改密码对话框 -->
    <el-dialog v-model="showPwdForm" title="修改密码" width="440px" destroy-on-close>
      <el-form label-width="80px">
        <el-form-item label="用户">
          <span class="mono">{{ editUser?.username }}</span>
        </el-form-item>
        <el-form-item label="新密码">
          <el-input v-model="newPwd" type="password" placeholder="至少 6 位" show-password />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showPwdForm = false">取消</el-button>
        <el-button type="primary" :loading="submitting" @click="handleUpdatePwd">确定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '../api/index'
import { useAuthStore } from '../stores/auth'

const authStore = useAuthStore()
const currentUserId = authStore.user?.id || 0

const users = ref<any[]>([])
const loading = ref(false)
const showForm = ref(false)
const showRoleForm = ref(false)
const showPwdForm = ref(false)
const submitting = ref(false)
const form = ref({ username: '', password: '', role: 'viewer' })
const editUser = ref<any>(null)
const editRole = ref('')
const newPwd = ref('')

const roleOptions = [
  { value: 'admin', label: '管理员', desc: '全部权限' },
  { value: 'scanner', label: '扫描员', desc: '扫描+查看+编辑+报告' },
  { value: 'auditor', label: '审计员', desc: '查看+报告+漏洞管理' },
  { value: 'viewer', label: '只读用户', desc: '仅查看' },
]

const rolePerms: Record<string, string[]> = {
  admin: ['全部权限'],
  scanner: ['扫描', '查看', '编辑', '报告', '漏洞管理'],
  auditor: ['查看', '报告', '漏洞管理'],
  viewer: ['查看'],
}

function roleLabel(role: string): string {
  return roleOptions.find(r => r.value === role)?.label || role
}

function roleTagType(role: string): string {
  if (role === 'admin') return 'danger'
  if (role === 'scanner') return 'warning'
  if (role === 'auditor') return 'primary'
  return 'info'
}

async function loadData() {
  loading.value = true
  try {
    const res: any = await api.get('/auth/users')
    users.value = res.items || []
  } catch (e: any) {
    ElMessage.error(e.message)
  } finally {
    loading.value = false
  }
}

async function handleCreate() {
  if (!form.value.username || !form.value.password) {
    ElMessage.warning('请填写用户名和密码')
    return
  }
  submitting.value = true
  try {
    await api.post('/auth/users', form.value)
    ElMessage.success('用户创建成功')
    showForm.value = false
    form.value = { username: '', password: '', role: 'viewer' }
    await loadData()
  } catch (e: any) {
    ElMessage.error(e.message)
  } finally {
    submitting.value = false
  }
}

function openEditRole(row: any) {
  editUser.value = row
  editRole.value = row.role || 'viewer'
  showRoleForm.value = true
}

async function handleUpdateRole() {
  submitting.value = true
  try {
    await api.put(`/auth/users/${editUser.value.id}`, { role: editRole.value })
    ElMessage.success('角色已更新')
    showRoleForm.value = false
    await loadData()
  } catch (e: any) {
    ElMessage.error(e.message)
  } finally {
    submitting.value = false
  }
}

function openEditPwd(row: any) {
  editUser.value = row
  newPwd.value = ''
  showPwdForm.value = true
}

async function handleUpdatePwd() {
  if (!newPwd.value || newPwd.value.length < 6) {
    ElMessage.warning('密码至少 6 位')
    return
  }
  submitting.value = true
  try {
    await api.put(`/auth/users/${editUser.value.id}`, { password: newPwd.value })
    ElMessage.success('密码修改成功')
    showPwdForm.value = false
  } catch (e: any) {
    ElMessage.error(e.message)
  } finally {
    submitting.value = false
  }
}

async function handleDelete(row: any) {
  try {
    await ElMessageBox.confirm(`确定删除用户「${row.username}」？此操作不可恢复。`, '确认删除', { type: 'error' })
    await api.delete(`/auth/users/${row.id}`)
    ElMessage.success('用户已删除')
    await loadData()
  } catch (e: any) {
    if (e.message && e.message !== 'cancel') ElMessage.error(e.message)
  }
}

function formatTime(iso: string) {
  if (!iso) return '—'
  const d = new Date(iso)
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}

onMounted(loadData)
</script>

<style scoped>
.perm-list {
  font-size: 12px;
  color: var(--np-text-muted);
}
.perm-hint {
  float: right;
  color: var(--np-text-muted);
  font-size: 12px;
}
</style>
