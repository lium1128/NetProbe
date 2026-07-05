import { ref, watch } from 'vue'

const STORAGE_KEY = 'netprobe_page_size'
const DEFAULT_SIZE = 20

/** 全局共享的每页条数（所有列表页统一），持久化到 localStorage。
 *
 * 用法：
 *   const perPage = usePageSize()  // 返回响应式 ref，自动同步 localStorage
 *   // 改 perPage.value 会自动保存，其他页面读取时拿到最新值
 */
export function usePageSize() {
  let initial = DEFAULT_SIZE
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved) initial = Number(saved) || DEFAULT_SIZE
  } catch {
    /* localStorage 不可用时用默认值 */
  }

  const pageSize = ref(initial)

  // 监听变化，自动持久化
  watch(pageSize, (val) => {
    try {
      localStorage.setItem(STORAGE_KEY, String(val))
    } catch {
      /* 忽略写入失败 */
    }
  })

  return pageSize
}
